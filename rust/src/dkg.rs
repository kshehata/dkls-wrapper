
use std::sync::{Arc, Mutex};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use tokio::runtime::Runtime;

use std::sync::OnceLock;

use sl_dkls23::setup::keygen::SetupMessage as KeygenSetup;
use sl_dkls23::keygen::run as keygen_run;
use sl_dkls23::Relay;
use sl_dkls23::setup::ArcSigner;

use crate::error::GeneralError;
use crate::types::*;

#[derive(uniffi::Object)]
pub struct DKGNode {
    pub setup: Mutex<SetupMessage>,
    pub secret_key: NodeSecretKey,
}

impl DKGNode {
    pub fn from_setup(mut setup_msg: SetupMessage, name: &str) -> Self {
        setup_msg.party_id = setup_msg.parties.len() as u8;
        let secret_key = NodeSecretKey::from_entropy();
        setup_msg.parties.push(DeviceInfo::for_sk(name.to_string(), &secret_key));
        setup_msg.num_parties = setup_msg.parties.len() as u8;
        Self {
            setup: Mutex::new(setup_msg),
            secret_key,
        }
    }

    pub async fn do_keygen_relay<R: Relay>(&self, relay: R) -> Result<Keyshare, GeneralError> {
        let (instance, party_id, threshold, parties) = {
            let mut setup = self.setup.lock().unwrap();
            (
                setup.instance,
                setup.party_id,
                setup.threshold,
                std::mem::take(&mut setup.parties),
            )
        };

        let vkrefs: Vec<&NodeVerifyingKey> = parties.iter().map(|dev| &dev.vk).collect();
        let ranks = vec![0u8; parties.len()];
        let setup_msg = KeygenSetup::new(
            instance.into(),
            &self.secret_key,
            party_id.into(),
            vkrefs,
            &ranks,
            threshold.into()
        );

        let mut rng = ChaCha20Rng::from_entropy();

        let res = keygen_run(setup_msg, rng.gen(), relay).await;

        // Restore the parties to the setup member
        self.setup.lock().unwrap().parties = parties;

        res.map(|k| Keyshare(Arc::new(k)))
            .map_err(GeneralError::from)
    }
}


#[uniffi::export]
impl DKGNode {
    #[uniffi::constructor]
    pub fn starter(instance: &InstanceId, threshold: u8, name: &str) -> Self {
        let secret_key = NodeSecretKey::from_entropy();
        let parties = vec![DeviceInfo::for_sk(name.to_string(), &secret_key)];
        Self {
            setup: Mutex::new(SetupMessage {
                instance: *instance,
                threshold,
                parties,
                party_id: 0,
                num_parties: 1,
                start: false,
            }),
            secret_key, 
        }
    }

    #[uniffi::constructor]
    pub fn from_setup_string(setup_str: &String, name: &str) -> Result<Self, GeneralError> {
        Ok(DKGNode::from_setup(SetupMessage::from_string(setup_str)?, name))
    }

    #[uniffi::constructor]
    pub fn from_setup_bytes(setup: &Vec<u8>, name: &str) -> Result<Self, GeneralError> {
        Ok(DKGNode::from_setup(SetupMessage::from_bytes(setup)?, name))
    }

    pub fn setup_string(&self) -> String {
        self.setup.lock().unwrap().to_string()
    }

    pub fn setup_bytes(&self) -> Vec<u8> {
        self.setup.lock().unwrap().to_bytes()
    }

    pub fn update_from_string(&self, setup: &String) -> Result<(), GeneralError> {
        self.setup.lock().unwrap().update(SetupMessage::from_string(setup)?)
    }

    pub fn update_from_bytes(&self, setup: &Vec<u8>) -> Result<(), GeneralError> {
        self.setup.lock().unwrap().update(SetupMessage::from_bytes(setup)?)
    }

    pub fn instance_id(&self) -> InstanceId {
        self.setup.lock().unwrap().instance
    }

    pub fn threshold(&self) -> u8 {
        self.setup.lock().unwrap().threshold
    }

    pub fn party_id(&self) -> u8 {
        self.setup.lock().unwrap().party_id
    }
    
    pub async fn do_keygen(&self, interface: Arc<dyn NetworkInterface>) -> Result<Keyshare, GeneralError> {
        self.do_keygen_relay(create_network_relay(interface)).await
    }
}

#[derive(uniffi::Object)]
pub struct DKGRunner {
    coord: sl_mpc_mate::coord::SimpleMessageRelay,
    rt: OnceLock<Runtime>,
}

// All of this so that Swift can use a Tokio Runtime
// and the SimpleMessageRelay.
#[uniffi::export]
impl DKGRunner {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            coord: sl_mpc_mate::coord::SimpleMessageRelay::new(),
            rt: OnceLock::new(),
        })
    }

    pub fn initialize_tokio_runtime(&self) {
        // Create a multi-threaded runtime (or single-threaded if preferred)
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tokio runtime");
        
        // Store the runtime in the OnceLock for later access
        self.rt.set(rt).expect("Runtime already initialized");
    }

    pub async fn run(&self, node: &DKGNode) -> Result<Keyshare, GeneralError> {
        let Some(rt) = self.rt.get() else {
            return Err(GeneralError::InvalidContext);
        };

        // Use block_on to execute the async operation *on* the DKGRunner's runtime
        let result = rt.block_on(async {
            // The async block *itself* now runs under the context of 'rt'
            node.do_keygen_relay(self.coord.connect()).await
        });
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::group::GroupEncoding;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_node() {
        println!("Starting test");
        let instance = InstanceId::from_entropy();
        let mut nodes = vec![DKGNode::starter(&instance, 2, "node0")];
        for i in 1..3 {
            println!("Adding node {}", i);
            nodes.push(DKGNode::from_setup_bytes(&nodes[i-1].setup_bytes(), &format!("node{}", i)).unwrap());
            let new_setup = nodes[i].setup_bytes();
            for j in 0..i {
                nodes[j].update_from_bytes(&new_setup).unwrap();
            }
        }

        // Simulate running each independently
        let mut parties = tokio::task::JoinSet::new();
        let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();

        for node in nodes {
            let relay = coord.connect();
            parties.spawn(async move {
                node.do_keygen_relay(relay).await
            });
        }

        // collect all of the shares
        let mut shares = vec![];
        while let Some(fini) = parties.join_next().await {
            if let Err(ref err) = fini {
                println!("error {err:?}");
            } else {
                match fini.unwrap() {
                    Err(err) => panic!("err {:?}", err),
                    Ok(share) => {
                        // println!("share {}", hex::encode(share.0.s_i().to_bytes()));
                        shares.push(Arc::new(share)) },
                }
            }
        }

        for keyshare in shares.iter() {
            println!("PK={} SK={}", hex::encode(keyshare.0.public_key().to_bytes()),
                hex::encode(keyshare.0.s_i().to_bytes()));
        }
    }
}
