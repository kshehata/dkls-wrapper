use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::pkcs8::EncodePublicKey;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use signature::{Signer, Verifier};
use std::sync::Arc;

use crate::error::GeneralError;
use std::hash::{Hash, Hasher};

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

    pub fn equals(&self, other: &InstanceId) -> bool {
        self == other
    }

    pub fn ffi_hash(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
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

    pub fn num_parties(&self) -> u8 {
        self.0.total_parties
    }

    pub fn device_index(&self) -> u8 {
        self.0.party_id
    }

    pub fn key_id(&self) -> Vec<u8> {
        self.0.key_id.to_vec()
    }

    pub fn equals(&self, other: &Keyshare) -> bool {
        // We can't compare the Arcs directly as they might point to different allocations
        // but identical content. However, Keyshare doesn't implement PartialEq (it wraps a foreign type).
        // Let's assume for now we can compare the bytes.
        self.to_bytes() == other.to_bytes()
    }

    pub fn ffi_hash(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        // Since we don't have Hash on the inner type easily, hash the bytes.
        self.to_bytes().hash(&mut hasher);
        hasher.finish()
    }

    pub fn vk(&self) -> NodeVerifyingKey {
        VerifyingKey::from_affine(self.0.public_key().to_affine())
            .unwrap()
            .into()
    }

    // Needed for mocking in higher level code.
    #[uniffi::constructor]
    pub fn dummy(n: u8, t: u8, my_index: u8) -> Self {
        use sl_dkls23::keygen::Keyshare as InnerKeyshare;

        // 1. Create a base keyshare using the library method ensures correct sizes/offsets
        // for "OtherParty" which turned out to be quite large (65600 bytes).
        let base_share = InnerKeyshare::new(n, t, my_index, &[]);

        // 2. Clone the buffer to modify it
        let mut buffer = base_share.as_slice().to_vec();

        // 3. Init RNG
        let mut rng = ChaCha20Rng::from_entropy();

        // 4. Overwrite KeyshareInfo fields with random/valid data
        // KeyshareInfo layout offsets (verified):
        // 0..4: magic
        // 4..8: extra
        // 8: total_parties
        // 9: threshold
        // 10: party_id
        // 11..43: final_session_id
        // 43..75: root_chain_code
        // 75..108: public_key (33 bytes)
        // 108..140: key_id
        // 140..172: s_i

        // final_session_id (random 32 bytes)
        rng.fill(&mut buffer[11..43]);

        // root_chain_code (random 32 bytes)
        rng.fill(&mut buffer[43..75]);

        // public_key (valid compressed point, 33 bytes)
        let sk = SigningKey::random(&mut rng);
        let pk = VerifyingKey::from(&sk);
        let pk_bytes = pk.to_encoded_point(true);
        buffer[75..108].copy_from_slice(pk_bytes.as_bytes());

        // key_id (random 32 bytes)
        rng.fill(&mut buffer[108..140]);

        // s_i (valid scalar, 32 bytes)
        let scalar_bytes = sk.to_bytes();
        buffer[140..172].copy_from_slice(&scalar_bytes);

        // 5. Create valid wrapper
        Self::from_bytes(&buffer).expect("Failed to produce dummy keyshare")
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

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Object)]
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

    pub fn to_der(&self) -> Vec<u8> {
        self.0.to_der().as_bytes().to_vec()
    }

    pub fn equals(&self, other: &Signature) -> bool {
        self == other
    }

    pub fn ffi_hash(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        // Signature doesn't implement Hash in k256 either usually, but let's check.
        // If not, hash bytes.
        self.to_bytes().hash(&mut hasher);
        hasher.finish()
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

    pub fn equals(&self, other: &NodeVerifyingKey) -> bool {
        self == other
    }

    pub fn ffi_hash(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }

    pub fn to_pem(&self) -> String {
        self.inner
            .to_public_key_pem(Default::default())
            .expect("Failed to export vk to PEM")
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
    pub fn for_vk(friendly_name: String, vk: Arc<NodeVerifyingKey>) -> Self {
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

    #[uniffi::constructor]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GeneralError> {
        postcard::from_bytes(bytes).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }

    pub fn equals(&self, other: &DeviceInfo) -> bool {
        self == other
    }

    pub fn ffi_hash(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
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

    pub fn key_id(&self) -> Vec<u8> {
        self.keyshare.key_id()
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

    // TODO: these last two are a hack for Swift. Check if we really need this.
    pub fn equals(&self, other: &DeviceLocalData) -> bool {
        self.to_bytes() == other.to_bytes()
    }

    pub fn ffi_hash(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.to_bytes().hash(&mut hasher);
        hasher.finish()
    }

    #[uniffi::constructor]
    pub fn dummy(n: u8, t: u8, my_index: u8) -> Self {
        let keyshare = Keyshare::dummy(n, t, my_index);
        let sk = NodeSecretKey::from_entropy();

        let devices = (0..n)
            .into_iter()
            .map(|i| {
                if i == my_index {
                    Arc::new(DeviceInfo::for_sk("My Device".to_string(), &sk))
                } else {
                    Arc::new(DeviceInfo::dummy(format!("Device{}", i), i % 2 == 0))
                }
            })
            .collect::<DeviceList>();

        Self {
            keyshare,
            my_index,
            sk,
            devices,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy_device_local_data() {
        let device_data = DeviceLocalData::dummy(3, 2, 1);

        // Verify basic fields
        assert_eq!(device_data.my_index, 1);
        assert_eq!(device_data.threshold(), 2);
        assert_eq!(device_data.get_device_list().len(), 3);

        // Verify devices
        assert_eq!(device_data.devices[0].name(), "Device0");
        assert_eq!(device_data.devices[1].name(), "My Device");
        assert_eq!(device_data.devices[2].name(), "Device2");
        assert_eq!(device_data.devices[0].is_verified(), true);
        assert_eq!(device_data.devices[1].is_verified(), false);
        assert_eq!(device_data.devices[2].is_verified(), true);

        // Verify Keyshare access
        let keyshare = &device_data.keyshare;
        assert_eq!(keyshare.threshold(), 2);
        assert_eq!(keyshare.num_parties(), 3);
        assert_eq!(keyshare.device_index(), 1);

        // Verify VK validity
        let vk = keyshare.vk();
        assert!(!vk.to_bytes().is_empty());

        // Check group VK
        let group_vk = device_data.group_vk();
        assert_eq!(vk.to_bytes(), group_vk.to_bytes());
    }
}
