
use std::sync::{Arc, Mutex};
use k256::elliptic_curve::group::GroupEncoding;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use tokio::runtime::Runtime;
use tokio::task::spawn_blocking;
use std::sync::OnceLock;

use sl_dkls23::setup::{
    keygen::SetupMessage, NoSigningKey, NoVerifyingKey,
};
use sl_dkls23::keygen::run as keygen_run;
use sl_dkls23::Relay;

use crate::error::KeygenError;
use crate::types::*;

#[derive(uniffi::Object)]
pub struct DKGNode {
    pub instance: InstanceId,
    pub threshold: u8,
    pub secret_key: NodeSecretKey,
    pub party_id: u8,
    pub party_vk: Mutex<Vec<Arc<NodeVerifyingKey>>>,
}

#[uniffi::export]
impl DKGNode {
    #[uniffi::constructor]
    pub fn starter(instance: Arc<InstanceId>, threshold: u8) -> Arc<Self> {
        let party_vk = vec![Arc::new(NodeVerifyingKey::from(0))];
        Arc::new(Self {
            instance: *instance,
            threshold,
            secret_key: NodeSecretKey{},
            party_id: 0,
            party_vk: Mutex::new(party_vk),
        })
    }

    #[uniffi::constructor]
    pub fn new(instance: Arc<InstanceId>, threshold: u8, party_vk: &Vec<Arc<NodeVerifyingKey>>) -> Arc<Self> {
        let my_id = party_vk.len();
        let mut all_party_vk = party_vk.clone();
        all_party_vk.push(Arc::new(NodeVerifyingKey::from(my_id)));
        Arc::new(Self {
            instance: *instance,
            threshold,
            secret_key: NodeSecretKey{},
            party_id: my_id as u8,
            party_vk: Mutex::new(all_party_vk),
        })
    }

    pub fn add_party(&self, party_vk: Arc<NodeVerifyingKey>) {
        self.party_vk.lock().unwrap().push(party_vk);
    }

    pub fn my_vk(&self) -> Arc<NodeVerifyingKey> {
        self.party_vk.lock().unwrap()[self.party_id as usize].clone()
    }

    pub fn party_vk(&self) -> Vec<Arc<NodeVerifyingKey>> {
        self.party_vk.lock().unwrap().clone()
    }
}

impl DKGNode {
    pub async fn do_keygen<R: Relay>(&self, relay: R) -> Result<Keyshare, KeygenError> {
        let ranks = vec![0u8; self.party_vk.lock().unwrap().len()];
        let no_vk_vec: Vec<NoVerifyingKey> = self.party_vk.lock().unwrap()
            .iter()
            .map(|node_vk_arc| node_vk_arc.clone().to_no_vk())
            .collect();

        let setup_msg = SetupMessage::new(
            self.instance.into(),
            NoSigningKey,
            self.party_id.into(),
            no_vk_vec,
            &ranks,
            self.threshold.into()
        );
        let mut rng = ChaCha20Rng::from_entropy();
        keygen_run(setup_msg, rng.gen(), relay)
            .await
            .map(|k| Keyshare(k))
            .map_err(KeygenError::from)
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

    pub async fn run(&self, node: &DKGNode) -> Result<Keyshare, KeygenError> {
        let Some(rt) = self.rt.get() else {
            return Err(KeygenError::InvalidContext);
        };

        // Use block_on to execute the async operation *on* the DKGRunner's runtime
        let result = rt.block_on(async {
            // The async block *itself* now runs under the context of 'rt'
            node.do_keygen(self.coord.connect()).await
        });
        
        result
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_node() {
        println!("Starting test");
        let instance = InstanceId::from_entropy();
        let mut nodes = vec![DKGNode::starter(instance.clone(), 2)];
        for i in 1..3 {
            println!("Adding node {}", i);
            let party_vk = nodes[i-1].party_vk.lock().unwrap().clone();
            nodes.push(DKGNode::new(instance.clone(), 2, &party_vk));
            let new_vk = nodes[i].my_vk();
            for j in 0..i {
                nodes[j].add_party(new_vk.clone());
            }
        }

        // Simulate running each independently
        let mut parties = tokio::task::JoinSet::new();
        let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();

        for node in nodes {
            let relay = coord.connect();
            parties.spawn(async move {
                node.do_keygen(relay).await
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
