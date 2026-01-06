use std::sync::{Arc, Mutex};
use futures::{Future, sink, Sink, SinkExt, Stream, StreamExt};
use core::pin::Pin;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use k256::elliptic_curve::group::GroupEncoding;
use k256::ecdsa::{SigningKey, VerifyingKey};
use signature::{Signer, Verifier};
use serde::{Serialize, Deserialize};

use crate::error::GeneralError;


/*****************************************************************************
 * Wrappers for basic types.
 *****************************************************************************/

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, uniffi::Object)]
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
        bytes.try_into()
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

#[derive(Clone, uniffi::Object)]
pub struct Keyshare(pub Arc<sl_dkls23::keygen::Keyshare>);

#[uniffi::export]
impl Keyshare {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GeneralError> {
        let inner = sl_dkls23::keygen::Keyshare::from_bytes(bytes)
            .ok_or(GeneralError::InvalidInput("Invalid KeyShare encoding".to_string()))?;
        Ok(Self(Arc::new(inner)))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_slice().to_vec()
    }

    pub fn print(&self) {
        println!("PK={} SK={}", hex::encode(self.0.public_key().to_bytes()),
            hex::encode(self.0.s_i().to_bytes()));
    }
}

#[uniffi::export]
impl Keyshare {
    pub fn vk(&self) -> NodeVerifyingKey {
        VerifyingKey::from_affine(self.0.public_key().to_affine()).unwrap().into()
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
        Ok(Self { inner, bytes: bytes.into_boxed_slice() })
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
            bytes: inner.to_encoded_point(true).as_bytes().to_vec().into_boxed_slice(),
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
        Ok(Self { inner, bytes: bytes.into_boxed_slice() })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), GeneralError> {
        self.inner.verify(msg, &sig.0).map_err(|e| GeneralError::SignatureError(e.to_string()))
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
    fn verify(&self, msg: &[u8], signature: &k256::ecdsa::Signature) -> Result<(), signature::Error> {
        self.inner.verify(msg, signature)
    }
}

/*****************************************************************************
 * Messages
 *****************************************************************************/

// To set up any operation we need to know the verification keys of all parties
// and determine an ordering for them. Basic idea is that new parties scan the
// QR code of an existing member, then send a network message to update
// existing parties.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetupMessage {
    pub instance: InstanceId,
    pub threshold: u8,
    pub party_vk: Mutex<Vec<NodeVerifyingKey>>,
}

impl SetupMessage {
    // Update setup from a received message.
    // Checks that instance, threshold, and all previous keys are the same,
    // and adds new keys to the store.
    pub fn update(&self, setup_msg: SetupMessage) -> Result<(), GeneralError> {
        // Lock the vk vector for the entire function.
        let mut old_party_vk = self.party_vk.lock().unwrap();
        let new_party_vk = setup_msg.party_vk.into_inner().unwrap();

        // Make sure setup is consistent.
        if setup_msg.instance != self.instance
            || setup_msg.threshold != self.threshold
            || new_party_vk.len() < old_party_vk.len()
        {
            return Err(GeneralError::InvalidSetupMessage);
        }

        // If any of the keys are different, reject the setup.
        if old_party_vk.as_slice() != &new_party_vk[..old_party_vk.len()] {
            return Err(GeneralError::InvalidSetupMessage);
        }

        // Replace the local vector with the one received.
        *old_party_vk = new_party_vk;
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
        self.party_vk.lock().unwrap().len() as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl PartialEq for SetupMessage {
        fn eq(&self, other: &Self) -> bool {
            // Note: .lock().unwrap() may panic if the mutex is poisoned
            let self_val = self.party_vk.lock().unwrap();
            let other_val = other.party_vk.lock().unwrap();
            self.instance == other.instance
                && self.threshold == other.threshold
                && self_val.as_slice() == other_val.as_slice()
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
        let party_vk: Vec<NodeVerifyingKey> = secret_keys.iter().map(|sk| NodeVerifyingKey::from_sk(sk)).collect();
        let setup_msg = SetupMessage {
            instance,
            threshold: 2,
            party_vk: Mutex::new(party_vk),
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
        let party_vk: Vec<NodeVerifyingKey> = secret_keys.iter().map(|sk| NodeVerifyingKey::from_sk(sk)).collect();
        let setup_msg = SetupMessage {
            instance,
            threshold: 2,
            party_vk: Mutex::new(party_vk),
        };
        let serialized = setup_msg.to_bytes();
        let deserialized: SetupMessage = SetupMessage::from_bytes(&serialized).unwrap();
        assert_eq!(setup_msg, deserialized);
    }
}

/*****************************************************************************
 * Network interface provides an interface for clients to implement network
 * functionality.
 *****************************************************************************/

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait NetworkInterface: Send + Sync {
    async fn send(&self, data: Vec<u8>) -> Result<(), GeneralError>;
    async fn receive(&self) -> Result<Vec<u8>, GeneralError>;
}

// Helper class to test the network interface.
// Basically just sends a message and checks if it comes back.
#[derive(uniffi::Object)]
pub struct NetworkInterfaceTester {
    interface: Arc<dyn NetworkInterface>,
}

#[uniffi::export]
impl NetworkInterfaceTester {
    #[uniffi::constructor]
    pub fn new(interface: Arc<dyn NetworkInterface>) -> Self {
        Self { interface }
    }

    pub async fn test(&self) -> Result<(), GeneralError> {
        let test_bytes = vec![0x01, 0x02, 0x03, 0x04];
        let rx = self.interface.receive();
        let tx = self.interface.send(test_bytes.clone());
        let (tx_res, rx_res) = futures::join!(tx, rx);
        tx_res?;
        let received = rx_res?;
        if test_bytes != received {
            return Err(GeneralError::MessageSendError);
        }
        Ok(())
    }

    pub async fn test_relay(&self, data: Vec<u8>) -> Result<(), GeneralError> {
        let mut r1 = create_network_relay(self.interface.clone());
        let mut r2 = create_network_relay(self.interface.clone());
        let tx = r1.send(data.clone());
        let rx = r2.next();
        let (tx_res, rx_res) = futures::join!(tx, rx);
        tx_res?;
        let received = rx_res.ok_or(GeneralError::MessageSendError)?;
        if data != received {
            return Err(GeneralError::MessageSendError);
        }
        Ok(())
    }
}


/*****************************************************************************
 * Bridge async network interface for UniFFI to the Source + Sink relay that
 * SL DKLS23 uses.
 *****************************************************************************/

type BoxedStream<T> = Pin<Box<dyn Stream<Item = T> + Send>>;
type BoxedSink<T, E> = Pin<Box<dyn Sink<T, Error = E> + Send>>;

pub struct Duplex<T, E> {
    rx: BoxedStream<T>,
    tx: BoxedSink<T, E>,
}

impl<T, E> Duplex<T, E> {
    pub fn new(rx: BoxedStream<T>, tx: BoxedSink<T, E>) -> Self {
        Self { rx, tx }
    }
}

impl<T, E> Stream for Duplex<T, E> {
    type Item = T;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.rx.as_mut().poll_next(cx)
    }
}

impl<T, E> Sink<T> for Duplex<T, E> {
    type Error = E;

    fn poll_ready(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.tx) }.poll_ready(cx)
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        unsafe { self.map_unchecked_mut(|s| &mut s.tx) }.start_send(item)
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.tx) }.poll_flush(cx)
    }

    fn poll_close(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.tx) }.poll_close(cx)
    }
}

// Have to explicitly mark as meeting the trait.
impl sl_dkls23::Relay for Duplex<Vec<u8>, sl_dkls23::MessageSendError> {    
}

// Helper to write things to the network interface needed for unfold.
fn network_write_fn(
    interface: Arc<dyn NetworkInterface>, 
    item: Vec<u8>
) -> impl Future<Output = Result<Arc<dyn NetworkInterface>, sl_dkls23::MessageSendError>> {
    
    // We clone the Arc to move it into the async block, 
    // ensuring the Arc's reference count is managed correctly.
    let interface_clone = interface.clone(); 
    
    async move {
        let res = interface_clone.send(item).await;
            match res {
            Ok(_) => Ok(interface_clone),
            Err(_) => Err(sl_dkls23::MessageSendError),
        }
    }
}

// Create an adapter that meets the SL DKLS23 Relay trait based on an ARC to the
// NetworkInterface from the client.
// NB: there's no way to detect errors from the receive state - it's assumed that
// clients will somehow pick this up!!
pub fn create_network_relay(interface: Arc<dyn NetworkInterface>) -> impl sl_dkls23::Relay {
    let interface_clone = interface.clone();
    let rx = async_stream::stream! {
        loop {
            let received = interface_clone.receive().await;
            match received {
                Ok(data) => yield data,
                Err(_) => yield Vec::new(), // Silently return an empty array on error
            }
        }
    };
    let tx = sink::unfold(
        interface,
        network_write_fn
    );
    Duplex::new(Box::pin(rx), Box::pin(tx))
}
