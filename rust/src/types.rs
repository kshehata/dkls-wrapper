use std::sync::Arc;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use k256::elliptic_curve::group::GroupEncoding;

use crate::error::NetworkError;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, uniffi::Object)]
pub struct InstanceId(sl_dkls23::InstanceId);

#[uniffi::export]
impl InstanceId {
    #[uniffi::constructor]
    pub fn from_entropy() -> Arc<Self> {
        let mut rnd = ChaCha20Rng::from_entropy();
        Arc::new(Self(sl_dkls23::InstanceId::new(rnd.gen())))
    }
}

impl From<sl_dkls23::InstanceId> for InstanceId {
    fn from(value: sl_dkls23::InstanceId) -> Self {
        Self(value)
    }
}

impl Into<sl_dkls23::InstanceId> for InstanceId {
    fn into(self) -> sl_dkls23::InstanceId {
        self.0
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

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait NetworkInterface: Send + Sync {
    async fn send(&self, data: Vec<u8>) -> Result<(), NetworkError>;
    async fn receive(&self) -> Result<Vec<u8>, NetworkError>;
}

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
}
