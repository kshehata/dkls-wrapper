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

/*****************************************************************************
 * Key shares
 *****************************************************************************/
#[derive(Clone, uniffi::Object)]
pub struct Keyshare(pub Arc<sl_dkls23::keygen::Keyshare>);

#[uniffi::export]
impl Keyshare {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GeneralError> {
        let inner = sl_dkls23::keygen::Keyshare::from_bytes(bytes).ok_or(
            GeneralError::InvalidInput("Invalid KeyShare encoding".to_string()),
        )?;
        Ok(Self(Arc::new(inner)))
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
}

#[uniffi::export]
impl Keyshare {
    pub fn vk(&self) -> NodeVerifyingKey {
        VerifyingKey::from_affine(self.0.public_key().to_affine())
            .unwrap()
            .into()
    }
}

#[derive(Clone, uniffi::Object)]
pub struct Signature(pub k256::ecdsa::Signature);

#[uniffi::export]
impl Signature {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GeneralError> {
        let inner = k256::ecdsa::Signature::from_bytes(bytes.into())
            .map_err(|_| GeneralError::InvalidInput("Invalid Signature encoding".to_string()))?;
        Ok(Self(inner))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

/*****************************************************************************
 * Keys for signing messages.
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
        let inner = SigningKey::try_from(bytes.as_slice())
            .map_err(|_| GeneralError::InvalidInput("Invalid sk encoding".to_string()))?;
        Ok(Self {
            inner,
            bytes: bytes.into_boxed_slice(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, uniffi::Object)]
pub struct NodeVerifyingKey {
    inner: VerifyingKey,
    bytes: Box<[u8]>,
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
        let inner = VerifyingKey::try_from(bytes.as_slice())
            .map_err(|_| GeneralError::InvalidInput("Invalid vk encoding".to_string()))?;
        Ok(Self {
            inner,
            bytes: bytes.into_boxed_slice(),
        })
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

/*
#[derive(Serialize, Deserialize)]
pub struct SignedMessage<'a> {
    pub msg: &'a [u8],
    pub sig: Signature,
}

pub fn sign_message<T: Serialize>(msg: &T, sk: &NodeSecretKey) -> Result<Vec<u8>, GeneralError> {
    let msg = msg.to_bytes();
    let sig = sk.try_sign(&msg).map_err(|e| GeneralError::SignatureError(e.to_string()))?;
    Ok(postcard::to_allocvec(SignedMessage { msg, sig }).unwrap().to_bytes())
}
*/

// impl SignedMessage {
//     pub fn from_bytes(bytes: &[u8]) -> Result<Self, GeneralError> {
//         postcard::from_bytes(bytes).map_err(|e| GeneralError::InvalidInput(e.to_string()))
//     }

//     pub fn to_bytes(&self) -> Vec<u8> {
//         postcard::to_allocvec(self).unwrap()
//     }
// }

// A device is just a friendly name and a key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, uniffi::Object)]
pub struct DeviceInfo {
    pub friendly_name: String,
    pub vk: NodeVerifyingKey,
    // Verified field is never serialized.
    #[serde(skip, default)]
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

// To set up any operation we need to know the verification keys of all parties
// and determine an ordering for them. Basic idea is that new parties scan the
// QR code of an existing member, then send a network message to update
// existing parties.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetupMessage {
    pub instance: InstanceId,
    pub threshold: u8,
    pub parties: Vec<DeviceInfo>,
    pub party_id: u8,
    pub num_parties: u8,
    pub start: bool,
}

impl SetupMessage {
    // Update setup from a received message.
    // Checks that instance, threshold, and all previous keys are the same,
    // and adds new keys to the store.
    pub fn update(&mut self, setup_msg: SetupMessage) -> Result<(), GeneralError> {
        // Make sure setup is consistent.
        if setup_msg.instance != self.instance
            || setup_msg.threshold != self.threshold
            || setup_msg.parties.len() < self.parties.len()
        {
            return Err(GeneralError::InvalidSetupMessage);
        }

        // If any of the keys are different, reject the setup.
        if self.parties.as_slice() != &setup_msg.parties[..self.parties.len()] {
            return Err(GeneralError::InvalidSetupMessage);
        }

        // Replace the local vector with the one received.
        self.parties = setup_msg.parties;
        Ok(())
    }

    pub fn from_string(s: &String) -> Result<Self, GeneralError> {
        serde_json::from_str(s).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Result<Self, GeneralError> {
        postcard::from_bytes(bytes).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }

    pub fn num_parties(&self) -> u8 {
        self.parties.len() as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl PartialEq for SetupMessage {
        fn eq(&self, other: &Self) -> bool {
            self.instance == other.instance
                && self.threshold == other.threshold
                && self.parties.as_slice() == other.parties.as_slice()
                && self.party_id == other.party_id
                && self.num_parties == other.num_parties
                && self.start == other.start
        }
    }

    #[test]
    fn test_dkg_setup_message() {
        let instance = InstanceId::from_entropy();
        let secret_keys = vec![
            NodeSecretKey::from_entropy(),
            NodeSecretKey::from_entropy(),
            NodeSecretKey::from_entropy(),
        ];
        let parties: Vec<DeviceInfo> = secret_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| DeviceInfo::for_sk(format!("node{}", i), sk))
            .collect();
        let setup_msg = SetupMessage {
            instance,
            threshold: 2,
            parties,
            party_id: 0,
            num_parties: 3,
            start: false,
        };
        let serialized = setup_msg.to_string();
        let deserialized: SetupMessage = SetupMessage::from_string(&serialized).unwrap();
        assert_eq!(setup_msg, deserialized);
    }

    #[test]
    fn test_dkg_setup_message_postcard() {
        let instance = InstanceId::from_entropy();
        let secret_keys = vec![
            NodeSecretKey::from_entropy(),
            NodeSecretKey::from_entropy(),
            NodeSecretKey::from_entropy(),
        ];
        let parties: Vec<DeviceInfo> = secret_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| DeviceInfo::for_sk(format!("node{}", i), sk))
            .collect();
        let setup_msg = SetupMessage {
            instance,
            threshold: 2,
            parties,
            party_id: 0,
            num_parties: 3,
            start: false,
        };
        let serialized = setup_msg.to_bytes();
        let deserialized: SetupMessage = SetupMessage::from_bytes(&serialized).unwrap();
        assert_eq!(setup_msg, deserialized);
    }
}
