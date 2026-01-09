
use std::sync::{Arc, Mutex};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use k256::sha2::{Sha256, Digest};
use std::time::Duration;
use serde::{Serialize, Deserialize};

use sl_dkls23::setup::sign::SetupMessage as SignSetupMessage;
use sl_dkls23::sign::run as sign_run;
use sl_dkls23::Relay;

use crate::error::GeneralError;
use crate::types::*;

pub fn hash_message(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize().into()
} 

pub fn hash_string(message: &str) -> [u8; 32] {
    hash_message(message.as_bytes())
}


// Message sent on the network to request or join a signature party.
// TODO: to avoid race conditions, this needs to indicate sender or be signed.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub message: Vec<u8>,
    pub hash: [u8; 32],
    pub setup: SetupMessage,
}

impl SignRequest {
    pub fn init(message: Vec<u8>, setup: SetupMessage) -> Self {
        let hash = hash_message(&message);
        Self { message, hash, setup }
    }

    pub fn for_message(message: &str, setup: SetupMessage) -> Self {
        Self::init(message.as_bytes().to_vec(), setup)
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

    pub fn update(&self, req_msg: SignRequest) -> Result<(), GeneralError> {
        if req_msg.message.len() > 0 && req_msg.message != self.message {
            return Err(GeneralError::InvalidInput("Message mismatch".to_string()));
        }
        if req_msg.hash != self.hash {
            return Err(GeneralError::InvalidInput("Hash mismatch".to_string()));
        }
        self.setup.update(req_msg.setup)
    }
}


#[derive(uniffi::Object)]
pub struct SignNode {
    pub req: SignRequest,
    pub party_id: u8,
    pub secret_key: NodeSecretKey,
    pub keyshare: Keyshare,
}

// TODO: we really should be reusing keys from the clients.
impl SignNode {
    pub fn for_request(req_msg: SignRequest, keyshare: Keyshare) -> Self {
        let mut party_vk = req_msg.setup.party_vk.lock().unwrap();
        let my_id = party_vk.len() as u8;
        let secret_key = NodeSecretKey::from_entropy();
        party_vk.push(NodeVerifyingKey::from_sk(&secret_key));
        // drop the lock
        drop(party_vk);
        Self {
            req: req_msg,
            party_id: my_id,
            secret_key,
            keyshare,
        }
    }

    pub async fn do_sign_relay<R: Relay>(&self, relay: R) -> Result<Signature, GeneralError> {
        let setup_msg = SignSetupMessage::new(
            self.req.setup.instance.into(),
            &self.secret_key,
            self.party_id.into(),
            self.req.setup.party_vk.lock().unwrap().clone(),
            self.keyshare.0.clone(),
        )
        .with_hash(self.req.hash)
        .with_ttl(Duration::from_secs(1));
        let mut rng = ChaCha20Rng::from_entropy();
        Ok(Signature(sign_run(setup_msg, rng.gen(), relay).await?.0))
    } 
}

#[uniffi::export]
impl SignNode {
    #[uniffi::constructor]
    pub fn starter(message: &str, instance: &InstanceId, threshold: u8, keyshare: &Keyshare) -> Self {
        let secret_key = NodeSecretKey::from_entropy();
        let party_vk = vec![NodeVerifyingKey::from_sk(&secret_key)];
        Self {
            req: SignRequest::for_message(message,
                SetupMessage {
                    instance: *instance,
                    threshold,
                    party_vk: Mutex::new(party_vk),
                }),
            party_id: 0,
            secret_key, 
            keyshare: keyshare.clone(),
        }
    }

    #[uniffi::constructor]
    pub fn from_request_string(req_str: &String, keyshare: &Keyshare) -> Result<Self, GeneralError> {
        Ok(SignNode::for_request(SignRequest::from_string(req_str)?, keyshare.clone()))
    }

    #[uniffi::constructor]
    pub fn from_request_bytes(req: &Vec<u8>, keyshare: &Keyshare) -> Result<Self, GeneralError> {
        Ok(SignNode::for_request(SignRequest::from_bytes(req)?, keyshare.clone()))
    }

    pub fn request_string(&self) -> String {
        self.req.to_string()
    }

    // TODO: We should drop the message when joining.
    pub fn request_bytes(&self) -> Vec<u8> {
        self.req.to_bytes()
    }

    pub fn update_from_string(&self, req: &String) -> Result<(), GeneralError> {
        self.req.update(SignRequest::from_string(req)?)
    }

    pub fn update_from_bytes(&self, req: &Vec<u8>) -> Result<(), GeneralError> {
        self.req.update(SignRequest::from_bytes(req)?)
    }

    pub fn instance_id(&self) -> InstanceId {
        self.req.setup.instance
    }

    pub fn threshold(&self) -> u8 {
        self.req.setup.threshold
    }

    pub fn party_id(&self) -> u8 {
        self.party_id
    }

    pub fn num_parties(&self) -> u8 {
        self.req.setup.num_parties()
    }

    pub fn message(&self) -> Vec<u8> {
        self.req.message.clone()
    }

    pub fn hash(&self) -> Vec<u8> {
        self.req.hash.to_vec()
    }

    pub async fn do_sign(&self, interface: Arc<dyn NetworkInterface>) -> Result<Signature, GeneralError> {
        self.do_sign_relay(create_network_relay(interface)).await
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::*;

    async fn gen_key_shares() -> (Vec<NodeVerifyingKey>, Vec<NodeSecretKey>, Vec<Arc<Keyshare>>) {
        println!("Starting DKG");
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

        // backup the keys
        let vks = nodes[0].setup.lock().unwrap().parties.iter().map(|p| p.vk.clone()).collect::<Vec<_>>();
        let sks = nodes.iter().map(|n| n.secret_key.clone()).collect::<Vec<_>>();

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
        (vks, sks, shares)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_signing() {
        let (_vks, _sks, shares) = gen_key_shares().await;
        let instance = InstanceId::from_entropy();

        // Value to be signed
        let message = "Hello World".to_string();
        let vk = shares[0].vk();

        /*
        // let vks: Vec<NodeVerifyingKey> = vks.into_iter().take(2).collect();
        // OK, I think I finally get it. The KeyShares encode the x points.
        // The VK and SKs are encoded as a list. So you can change the ordering,
        // but the vectors have to match.
        let vks = vec![vks[2].clone(), vks[0].clone()];
        let sks = vec![sks[2].clone(), sks[0].clone()];
        let shares = vec![shares[1].clone(), shares[2].clone()];
        */
        let mut nodes = vec![SignNode::starter(&message, &instance, 2, &shares[2])];
        nodes.push(SignNode::from_request_bytes(&nodes[0].request_bytes(), &shares[1]).unwrap());
        nodes[0].update_from_bytes(&nodes[1].request_bytes()).unwrap();

        // Simulate running each independently
        let mut parties = tokio::task::JoinSet::new();
        let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();

        println!("Starting signing nodes");
        for node in nodes {
            println!("Signing node {}", node.party_id);
            let relay = coord.connect();
            parties.spawn(async move {
                node.do_sign_relay(relay).await
            });
        }

        println!("Waiting for signing nodes");
        // collect all of the shares
        let mut results = vec![];
        while let Some(fini) = parties.join_next().await {
            if let Err(ref err) = fini {
                println!("error {err:?}");
            } else {
                match fini.unwrap() {
                    Err(err) => panic!("err {:?}", err),
                    Ok(share) => {
                        results.push(share)
                    },
                }
            }
        }
        
        while let Some(res) = parties.join_next().await {
            let sig = res.unwrap().unwrap();
            assert!(vk.verify(&message.as_bytes(), &sig).is_ok());
        }
    }
}
