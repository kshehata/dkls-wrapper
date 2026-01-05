
use std::sync::Mutex;
use k256::ecdsa::{Signature, RecoveryId};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use std::time::Duration;

use sl_dkls23::setup::sign::SetupMessage as SignSetupMessage;
use sl_dkls23::sign::{run as sign_run, SignError};
use sl_dkls23::Relay;

use crate::error::GeneralError;
use crate::types::*;

#[derive(uniffi::Object)]
pub struct SignNode {
    pub setup: SetupMessage,
    pub party_id: u8,
    pub secret_key: NodeSecretKey,
    pub keyshare: Keyshare,
}

// TODO: we really should be reusing keys from the clients.
impl SignNode {
    pub fn from_setup(setup_msg: SetupMessage, keyshare: Keyshare) -> Self {
        let mut party_vk = setup_msg.party_vk.lock().unwrap();
        let my_id = party_vk.len() as u8;
        let secret_key = NodeSecretKey::from_entropy();
        party_vk.push(NodeVerifyingKey::from_sk(&secret_key));
        // drop the lock
        drop(party_vk);
        Self {
            setup: setup_msg,
            party_id: my_id,
            secret_key,
            keyshare,
        }
    }

    pub async fn do_sign_relay<R: Relay>(&self, hash: [u8; 32], relay: R) -> Result<(Signature, RecoveryId), SignError> {
        let setup_msg = SignSetupMessage::new(
            self.setup.instance.into(),
            &self.secret_key,
            self.party_id.into(),
            self.setup.party_vk.lock().unwrap().clone(),
            self.keyshare.0.clone(),
        )
        .with_hash(hash)
        .with_ttl(Duration::from_secs(1));
        let mut rng = ChaCha20Rng::from_entropy();
        sign_run(setup_msg, rng.gen(), relay).await
    }
}

#[uniffi::export]
impl SignNode {
    #[uniffi::constructor]
    pub fn starter(instance: &InstanceId, threshold: u8, keyshare: &Keyshare) -> Self {
        let secret_key = NodeSecretKey::from_entropy();
        let party_vk = vec![NodeVerifyingKey::from_sk(&secret_key)];
        Self {
            setup: SetupMessage {
                instance: *instance,
                threshold,
                party_vk: Mutex::new(party_vk),
            },
            party_id: 0,
            secret_key, 
            keyshare: keyshare.clone(),
        }
    }

    #[uniffi::constructor]
    pub fn from_setup_string(setup_str: &String, keyshare: &Keyshare) -> Result<Self, GeneralError> {
        Ok(SignNode::from_setup(SetupMessage::from_string(setup_str)?, keyshare.clone()))
    }

    #[uniffi::constructor]
    pub fn from_setup_bytes(setup: &Vec<u8>, keyshare: &Keyshare) -> Result<Self, GeneralError> {
        Ok(SignNode::from_setup(SetupMessage::from_bytes(setup)?, keyshare.clone()))
    }

    pub fn setup_string(&self) -> String {
        self.setup.to_string()
    }

    pub fn setup_bytes(&self) -> Vec<u8> {
        self.setup.to_bytes()
    }

    pub fn update_from_string(&self, setup: &String) -> Result<(), GeneralError> {
        self.setup.update(SetupMessage::from_string(setup)?)
    }

    pub fn update_from_bytes(&self, setup: &Vec<u8>) -> Result<(), GeneralError> {
        self.setup.update(SetupMessage::from_bytes(setup)?)
    }

    pub fn instance_id(&self) -> InstanceId {
        self.setup.instance
    }

    pub fn threshold(&self) -> u8 {
        self.setup.threshold
    }

    pub fn party_id(&self) -> u8 {
        self.party_id
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use signature::Verifier;
    use crate::dkg::*;

    async fn gen_key_shares() -> (Vec<NodeVerifyingKey>, Vec<NodeSecretKey>, Vec<Arc<Keyshare>>) {
        println!("Starting DKG");
        let instance = InstanceId::from_entropy();
        let mut nodes = vec![DKGNode::starter(&instance, 2)];
        for i in 1..3 {
            println!("Adding node {}", i);
            nodes.push(DKGNode::from_setup_bytes(&nodes[i-1].setup_bytes()).unwrap());
            let new_setup = nodes[i].setup_bytes();
            for j in 0..i {
                nodes[j].update_from_bytes(&new_setup).unwrap();
            }
        }

        // backup the keys
        let vks = nodes[0].setup.party_vk.lock().unwrap().clone();
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

        /*
        // let vks: Vec<NodeVerifyingKey> = vks.into_iter().take(2).collect();
        // OK, I think I finally get it. The KeyShares encode the x points.
        // The VK and SKs are encoded as a list. So you can change the ordering,
        // but the vectors have to match.
        let vks = vec![vks[2].clone(), vks[0].clone()];
        let sks = vec![sks[2].clone(), sks[0].clone()];
        let shares = vec![shares[1].clone(), shares[2].clone()];
        */
        let mut nodes = vec![SignNode::starter(&instance, 2, &shares[2])];
        nodes.push(SignNode::from_setup_bytes(&nodes[0].setup_bytes(), &shares[1]).unwrap());
        nodes[0].update_from_bytes(&nodes[1].setup_bytes()).unwrap();

        // Value to be signed
        let hash = [42u8; 32];
        let vk = shares[0].vk();

        // Simulate running each independently
        let mut parties = tokio::task::JoinSet::new();
        let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();

        println!("Starting signing nodes");
        for node in nodes {
            println!("Signing node {}", node.party_id);
            let relay = coord.connect();
            parties.spawn(async move {
                node.do_sign_relay(hash, relay).await
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
            let (sig, _recid) = res.unwrap().unwrap();
            assert!(vk.verify(&hash, &sig).is_ok());
        }
    }
}
