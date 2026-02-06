use core::pin::Pin;
use futures::{sink, Future, Sink, SinkExt, Stream, StreamExt};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

use crate::error::GeneralError;

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

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.tx) }.poll_ready(cx)
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        unsafe { self.map_unchecked_mut(|s| &mut s.tx) }.start_send(item)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.tx) }.poll_flush(cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.tx) }.poll_close(cx)
    }
}

// Have to explicitly mark as meeting the trait.
impl sl_dkls23::Relay for Duplex<Vec<u8>, sl_dkls23::MessageSendError> {}

// Helper to write things to the network interface needed for unfold.
fn network_write_fn(
    interface: Arc<dyn NetworkInterface>,
    item: Vec<u8>,
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
    let tx = sink::unfold(interface, network_write_fn);
    Duplex::new(Box::pin(rx), Box::pin(tx))
}

/*****************************************************************************
 * In memory bridge for testing
 *****************************************************************************/

pub struct InMemoryBridge {
    tx: broadcast::Sender<(usize, Vec<u8>)>,
    next_id: std::sync::atomic::AtomicUsize,
}

impl InMemoryBridge {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(100000);
        Self {
            tx,
            next_id: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn connect(&self) -> Arc<dyn NetworkInterface> {
        let rx = self.tx.subscribe();
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Arc::new(InMemoryNetworkInterface {
            id,
            tx: self.tx.clone(),
            rx: Mutex::new(rx),
        })
    }
}

struct InMemoryNetworkInterface {
    id: usize,
    tx: broadcast::Sender<(usize, Vec<u8>)>,
    rx: Mutex<broadcast::Receiver<(usize, Vec<u8>)>>,
}

#[async_trait::async_trait]
impl NetworkInterface for InMemoryNetworkInterface {
    async fn send(&self, data: Vec<u8>) -> Result<(), GeneralError> {
        self.tx
            .send((self.id, data))
            .map_err(|_| GeneralError::MessageSendError)?;
        Ok(())
    }

    async fn receive(&self) -> Result<Vec<u8>, GeneralError> {
        let mut rx = self.rx.lock().await;
        loop {
            match rx.recv().await {
                Ok((id, data)) => {
                    if id != self.id {
                        // simulate network delay, otherwise could overwhelm buffers.
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        return Ok(data);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    println!("Relay LAGGED: skipped {} messages", skipped);
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(GeneralError::MessageSendError)
                }
            }
        }
    }
}

#[cfg(test)]
mod bridge_tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_in_memory_bridge_simple() {
        let bridge = InMemoryBridge::new();
        let net1 = bridge.connect();
        let net2 = bridge.connect();

        let msg = vec![1, 2, 3];
        net1.send(msg.clone()).await.unwrap();

        // net2 should receive it
        let recv_msg = net2.receive().await.unwrap();
        assert_eq!(msg, recv_msg);

        // net1 should NOT receive it (loopback filtered)
        let res = timeout(Duration::from_millis(100), net1.receive()).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_in_memory_bridge_broadcast() {
        let bridge = InMemoryBridge::new();
        let net1 = bridge.connect();
        let net2 = bridge.connect();
        let net3 = bridge.connect();

        let msg = vec![10, 20];
        net1.send(msg.clone()).await.unwrap();

        assert_eq!(net2.receive().await.unwrap(), msg);
        assert_eq!(net3.receive().await.unwrap(), msg);
    }
}
