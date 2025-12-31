use std::sync::Arc;
use futures::{Future, sink, Sink, SinkExt, Stream, StreamExt};
use core::pin::Pin;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use k256::elliptic_curve::group::GroupEncoding;

use crate::error::{GeneralError, NetworkError};


/*****************************************************************************
 * Wrappers for basic types.
 *****************************************************************************/

#[repr(transparent)]
#[derive(Clone, Copy, Debug, uniffi::Object)]
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
    pub fn from_entropy() -> Arc<Self> {
        let mut rnd = ChaCha20Rng::from_entropy();
        Arc::new(Self(rnd.gen()))
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

#[derive(uniffi::Object)]
pub struct Keyshare(pub sl_dkls23::keygen::Keyshare);

#[uniffi::export]
impl Keyshare {
    pub fn print(&self) {
        println!("PK={} SK={}", hex::encode(self.0.public_key().to_bytes()),
            hex::encode(self.0.s_i().to_bytes()));
    }
}


/*****************************************************************************
 * Placeholders for keys.
 *****************************************************************************/

#[derive(uniffi::Object)]
pub struct NodeSecretKey { }

#[derive(Clone, uniffi::Object)]
pub struct NodeVerifyingKey(sl_dkls23::setup::NoVerifyingKey);

impl From<sl_dkls23::setup::NoVerifyingKey> for NodeVerifyingKey {
    fn from(value: sl_dkls23::setup::NoVerifyingKey) -> Self {
        Self(value)
    }
}

impl From<usize> for NodeVerifyingKey {
    fn from(value: usize) -> Self {
        Self(sl_dkls23::setup::NoVerifyingKey::new(value))
    }
}

impl NodeVerifyingKey {
    pub fn to_no_vk(&self) -> sl_dkls23::setup::NoVerifyingKey {
        self.0.clone()
    }
}

/*****************************************************************************
 * Network interface provides an interface for clients to implement network
 * functionality.
 *****************************************************************************/

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait NetworkInterface: Send + Sync {
    async fn send(&self, data: Vec<u8>) -> Result<(), NetworkError>;
    async fn receive(&self) -> Result<Vec<u8>, NetworkError>;
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

    pub async fn test(&self) -> Result<(), NetworkError> {
        let test_bytes = vec![0x01, 0x02, 0x03, 0x04];
        let rx = self.interface.receive();
        let tx = self.interface.send(test_bytes.clone());
        let (tx_res, rx_res) = futures::join!(tx, rx);
        tx_res?;
        let received = rx_res?;
        if test_bytes != received {
            return Err(NetworkError::MessageSendError);
        }
        Ok(())
    }

    pub async fn test_relay(&self, data: Vec<u8>) -> Result<(), NetworkError> {
        let mut r1 = create_network_relay(self.interface.clone());
        let mut r2 = create_network_relay(self.interface.clone());
        let tx = r1.send(data.clone());
        let rx = r2.next();
        let (tx_res, rx_res) = futures::join!(tx, rx);
        tx_res?;
        let received = rx_res.ok_or(NetworkError::MessageSendError)?;
        if data != received {
            return Err(NetworkError::MessageSendError);
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
