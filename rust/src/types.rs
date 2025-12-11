use std::sync::Arc;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use k256::elliptic_curve::group::GroupEncoding;

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