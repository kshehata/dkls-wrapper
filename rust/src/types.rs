use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::group::GroupEncoding;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use signature::{Signer, Verifier};
use std::sync::Arc;

use crate::error::GeneralError;

/*****************************************************************************
 * Wrappers for basic types.
 *****************************************************************************/

#[repr(transparent)]
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, uniffi::Object,
)]
// We need to make our own InstanceID so we have access to the data under it.
pub struct InstanceId([u8; 32]);

impl InstanceId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<[u8; 32]> for InstanceId {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

#[uniffi::export]
impl InstanceId {
    #[uniffi::constructor]
    pub fn from_entropy() -> Self {
        let mut rnd = ChaCha20Rng::from_entropy();
        Self(rnd.gen())
    }

    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, GeneralError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| GeneralError::InvalidInput("Must be exactly 32 bytes".to_string()))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Into<sl_dkls23::InstanceId> for InstanceId {
    fn into(self) -> sl_dkls23::InstanceId {
        sl_dkls23::InstanceId::new(self.0)
    }
}

impl AsRef<[u8]> for InstanceId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/*****************************************************************************
 * Key shares
 *****************************************************************************/
#[derive(Clone, uniffi::Object)]
pub struct Keyshare(pub Arc<sl_dkls23::keygen::Keyshare>);

#[uniffi::export]
impl Keyshare {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GeneralError> {
        Self::try_from(bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_slice().to_vec()
    }

    pub fn print(&self) {
        println!(
            "PK={} SK={}",
            hex::encode(self.0.public_key().to_bytes()),
            hex::encode(self.0.s_i().to_bytes())
        );
    }

    pub fn threshold(&self) -> u8 {
        self.0.threshold
    }
}

#[uniffi::export]
impl Keyshare {
    pub fn vk(&self) -> NodeVerifyingKey {
        VerifyingKey::from_affine(self.0.public_key().to_affine())
            .unwrap()
            .into()
    }
}

impl TryFrom<&[u8]> for Keyshare {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let inner = sl_dkls23::keygen::Keyshare::from_bytes(value).ok_or(
            GeneralError::InvalidInput("Invalid Keyshare encoding".to_string()),
        )?;
        Ok(Self(Arc::new(inner)))
    }
}

impl Serialize for Keyshare {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for Keyshare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

/*****************************************************************************
 * Signatures.
 *****************************************************************************/

#[derive(Debug, Clone, PartialEq, uniffi::Object)]
pub struct Signature(pub k256::ecdsa::Signature);

impl TryFrom<&[u8]> for Signature {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let inner = k256::ecdsa::Signature::from_bytes(value.into())
            .map_err(|_| GeneralError::InvalidInput("Invalid Signature encoding".to_string()))?;
        Ok(Self(inner))
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Signature::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

#[uniffi::export]
impl Signature {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GeneralError> {
        Self::try_from(bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

/*****************************************************************************
 * Signing Keys.
 *****************************************************************************/

#[derive(Clone, uniffi::Object)]
pub struct NodeSecretKey {
    inner: SigningKey,
    bytes: Box<[u8]>,
}

#[uniffi::export]
impl NodeSecretKey {
    #[uniffi::constructor]
    pub fn from_entropy() -> Self {
        let mut rnd = ChaCha20Rng::from_entropy();
        let inner = SigningKey::random(&mut rnd);
        Self {
            bytes: inner.to_bytes().to_vec().into_boxed_slice(),
            inner,
        }
    }

    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, GeneralError> {
        Self::try_from(bytes.as_slice())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

impl TryFrom<&[u8]> for NodeSecretKey {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let inner = SigningKey::try_from(value)
            .map_err(|_| GeneralError::InvalidInput("Invalid sk encoding".to_string()))?;
        Ok(Self {
            inner,
            bytes: Box::from(value),
        })
    }
}

impl Into<SigningKey> for NodeSecretKey {
    fn into(self) -> SigningKey {
        self.inner
    }
}

impl AsRef<[u8]> for NodeSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Signer<k256::ecdsa::Signature> for NodeSecretKey {
    fn try_sign(&self, msg: &[u8]) -> Result<k256::ecdsa::Signature, signature::Error> {
        self.inner.try_sign(msg)
    }
}

impl Signer<k256::ecdsa::Signature> for &NodeSecretKey {
    fn try_sign(&self, msg: &[u8]) -> Result<k256::ecdsa::Signature, signature::Error> {
        self.inner.try_sign(msg)
    }
}

impl Serialize for NodeSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for NodeSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        NodeSecretKey::from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

/*****************************************************************************
 * Verifying Keys.
 *****************************************************************************/

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, uniffi::Object)]
pub struct NodeVerifyingKey {
    pub inner: VerifyingKey,
    bytes: Box<[u8]>,
}

impl std::hash::Hash for NodeVerifyingKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl From<VerifyingKey> for NodeVerifyingKey {
    fn from(inner: VerifyingKey) -> Self {
        Self {
            bytes: inner
                .to_encoded_point(true)
                .as_bytes()
                .to_vec()
                .into_boxed_slice(),
            inner,
        }
    }
}

#[uniffi::export]
impl NodeVerifyingKey {
    #[uniffi::constructor]
    pub fn from_sk(sk: &NodeSecretKey) -> Self {
        Self::from(VerifyingKey::from(&sk.inner))
    }

    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, GeneralError> {
        Self::try_from(bytes.as_slice())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), GeneralError> {
        self.inner
            .verify(msg, &sig.0)
            .map_err(|e| GeneralError::SignatureError(e.to_string()))
    }
}

impl TryFrom<&[u8]> for NodeVerifyingKey {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let inner = VerifyingKey::try_from(value)
            .map_err(|_| GeneralError::InvalidInput("Invalid vk encoding".to_string()))?;
        Ok(Self {
            inner,
            bytes: Box::from(value),
        })
    }
}

impl Into<VerifyingKey> for NodeVerifyingKey {
    fn into(self) -> VerifyingKey {
        self.inner
    }
}

impl Serialize for NodeVerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for NodeVerifyingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        NodeVerifyingKey::from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

impl AsRef<[u8]> for NodeVerifyingKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Verifier<k256::ecdsa::Signature> for NodeVerifyingKey {
    fn verify(
        &self,
        msg: &[u8],
        signature: &k256::ecdsa::Signature,
    ) -> Result<(), signature::Error> {
        self.inner.verify(msg, signature)
    }
}

impl Verifier<k256::ecdsa::Signature> for &NodeVerifyingKey {
    fn verify(
        &self,
        msg: &[u8],
        signature: &k256::ecdsa::Signature,
    ) -> Result<(), signature::Error> {
        self.inner.verify(msg, signature)
    }
}

pub struct ArcVerifier<T>(pub Arc<T>);

impl<T: Verifier<S>, S> Verifier<S> for ArcVerifier<T> {
    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), signature::Error> {
        self.0.verify(msg, signature)
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for ArcVerifier<T> {
    fn as_ref(&self) -> &[u8] {
        (*self.0).as_ref()
    }
}

/*****************************************************************************
 * Messages
 *****************************************************************************/

// A device is just a friendly name and a key.
#[derive(
    Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, uniffi::Object,
)]
pub struct DeviceInfo {
    pub friendly_name: String,
    pub vk: NodeVerifyingKey,
    // Whether we have scanned the QR code for this device.
    #[serde(default)]
    pub verified: bool,
}

impl DeviceInfo {
    pub fn new(friendly_name: String, vk: NodeVerifyingKey) -> Self {
        Self {
            friendly_name,
            vk,
            verified: false,
        }
    }

    pub fn for_sk(friendly_name: String, sk: &NodeSecretKey) -> Self {
        Self {
            friendly_name,
            vk: NodeVerifyingKey::from_sk(sk),
            verified: false,
        }
    }
}

#[uniffi::export]
impl DeviceInfo {
    // For UniFFI clients to be able to construct from an Arc.
    #[uniffi::constructor]
    pub fn init(friendly_name: String, vk: Arc<NodeVerifyingKey>) -> Self {
        Self {
            friendly_name,
            vk: Arc::unwrap_or_clone(vk),
            verified: false,
        }
    }

    #[uniffi::constructor]
    pub fn dummy(friendly_name: String, verified: bool) -> Self {
        let sk = NodeSecretKey::from_entropy();
        let mut info = Self::for_sk(friendly_name, &sk);
        info.verified = verified;
        info
    }

    pub fn name(&self) -> String {
        self.friendly_name.clone()
    }

    pub fn is_verified(&self) -> bool {
        self.verified
    }

    pub fn vk(&self) -> NodeVerifyingKey {
        self.vk.clone()
    }
}

// Have to keep this as a bare vector for UniFFI.
pub type DeviceList = Vec<Arc<DeviceInfo>>;

#[uniffi::export]
pub fn find_device_by_vk(devices: &DeviceList, vk: &NodeVerifyingKey) -> Option<Arc<DeviceInfo>> {
    devices.iter().find(|d| d.vk == *vk).cloned()
}

// Everything a TSS node needs on a single device.
#[derive(Clone, Serialize, Deserialize, uniffi::Object)]
pub struct DeviceLocalData {
    pub keyshare: Keyshare,
    pub my_index: u8,
    pub sk: NodeSecretKey,
    pub devices: DeviceList,
}

#[uniffi::export]
impl DeviceLocalData {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GeneralError> {
        Self::try_from(bytes)
    }

    #[uniffi::constructor]
    pub fn from_string(s: &str) -> Result<Self, GeneralError> {
        Self::try_from(s)
    }

    pub fn my_index(&self) -> u8 {
        self.my_index
    }

    // Shortcut to get the threshold value from keyshare.
    pub fn threshold(&self) -> u8 {
        self.keyshare.threshold()
    }

    pub fn my_device(&self) -> Arc<DeviceInfo> {
        self.devices[self.my_index as usize].clone()
    }

    // Just a vector of arcs, so can clone the whole thing cheaply.
    pub fn get_device_list(&self) -> DeviceList {
        self.devices.clone()
    }

    pub fn group_vk(&self) -> NodeVerifyingKey {
        self.keyshare.vk()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }
}

impl DeviceLocalData {
    pub fn my_vk(&self) -> &NodeVerifyingKey {
        &self.devices[self.my_index as usize].vk
    }
}

impl TryFrom<&[u8]> for DeviceLocalData {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        postcard::from_bytes(value).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }
}

impl TryFrom<&str> for DeviceLocalData {
    type Error = GeneralError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        serde_json::from_str(value).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }
}
