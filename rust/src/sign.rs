use k256::sha2::{Digest, Sha256};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use sl_dkls23::setup::sign::SetupMessage as SignSetupMessage;
use sl_dkls23::sign::run as sign_run;
use sl_dkls23::Relay;

use crate::error::GeneralError;
use crate::net::{create_network_relay, NetworkInterface};
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
    pub instance: InstanceId,
    pub message: Vec<u8>,
    pub hash: [u8; 32],
    pub party_vk: Arc<Vec<NodeVerifyingKey>>,
}

// TODO: there has to be a better way than repeating this boilerplate for every message.
impl TryFrom<&[u8]> for SignRequest {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        postcard::from_bytes(value).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }
}

impl TryFrom<&str> for SignRequest {
    type Error = GeneralError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        serde_json::from_str(value).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }
}

impl SignRequest {
    pub fn init(instance: &InstanceId, message: Vec<u8>, party_vk: Vec<NodeVerifyingKey>) -> Self {
        let hash = hash_message(&message);
        Self {
            instance: *instance,
            message,
            hash,
            party_vk: Arc::new(party_vk),
        }
    }

    pub fn for_message(
        instance: &InstanceId,
        message: &str,
        party_vk: Vec<NodeVerifyingKey>,
    ) -> Self {
        Self::init(instance, message.as_bytes().to_vec(), party_vk)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn update(&mut self, req_msg: SignRequest) -> Result<(), GeneralError> {
        if req_msg.instance != self.instance {
            return Err(GeneralError::InvalidInput("Instance mismatch".to_string()));
        }
        if req_msg.message.len() > 0 && req_msg.message != self.message {
            return Err(GeneralError::InvalidInput("Message mismatch".to_string()));
        }
        if req_msg.hash != self.hash {
            return Err(GeneralError::InvalidInput("Hash mismatch".to_string()));
        }

        // If any of the keys are different, reject the update.
        if self.party_vk.as_slice() != &req_msg.party_vk[..self.party_vk.len()] {
            return Err(GeneralError::InvalidSetupMessage);
        }
        self.party_vk = req_msg.party_vk;
        Ok(())
    }
}

#[derive(uniffi::Object)]
pub struct SignNode {
    pub req: RwLock<SignRequest>,
    pub party_id: u8,
    pub secret_key: Arc<NodeSecretKey>,
    pub keyshare: Keyshare,
}

// TODO: we really should be reusing keys from the clients.
impl SignNode {
    pub fn for_request(
        mut req_msg: SignRequest,
        secret_key: Arc<NodeSecretKey>,
        keyshare: Keyshare,
    ) -> Self {
        let my_id = req_msg.party_vk.len() as u8;
        Arc::make_mut(&mut req_msg.party_vk).push(NodeVerifyingKey::from_sk(&secret_key));
        Self {
            req: RwLock::new(req_msg),
            party_id: my_id,
            secret_key,
            keyshare,
        }
    }

    pub async fn do_sign_relay<R: Relay>(&self, relay: R) -> Result<Signature, GeneralError> {
        let (instance, vks, hash) = {
            let req = self.req.read().unwrap();
            (req.instance, req.party_vk.clone(), req.hash)
        };

        let vkrefs: Vec<&NodeVerifyingKey> = vks.iter().collect();
        let setup_msg = SignSetupMessage::new(
            instance.into(),
            self.secret_key.as_ref(),
            self.party_id as usize,
            vkrefs,
            self.keyshare.0.clone(),
        )
        .with_hash(hash)
        .with_ttl(Duration::from_secs(1));
        let mut rng = ChaCha20Rng::from_entropy();
        Ok(Signature(sign_run(setup_msg, rng.gen(), relay).await?.0))
    }
}

#[uniffi::export]
impl SignNode {
    #[uniffi::constructor]
    pub fn for_message_string(
        message: &str,
        instance: &InstanceId,
        secret_key: Arc<NodeSecretKey>,
        keyshare: &Keyshare,
    ) -> Self {
        let party_vk = vec![NodeVerifyingKey::from_sk(&secret_key)];
        Self {
            req: RwLock::new(SignRequest::for_message(instance, message, party_vk)),
            party_id: 0,
            secret_key,
            keyshare: keyshare.clone(),
        }
    }

    #[uniffi::constructor]
    pub fn from_request_string(
        req_str: &str,
        secret_key: Arc<NodeSecretKey>,
        keyshare: &Keyshare,
    ) -> Result<Self, GeneralError> {
        Ok(SignNode::for_request(
            SignRequest::try_from(req_str)?,
            secret_key,
            keyshare.clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn from_request_bytes(
        req: &Vec<u8>,
        secret_key: Arc<NodeSecretKey>,
        keyshare: &Keyshare,
    ) -> Result<Self, GeneralError> {
        Ok(SignNode::for_request(
            SignRequest::try_from(req.as_slice())?,
            secret_key,
            keyshare.clone(),
        ))
    }

    pub fn request_string(&self) -> String {
        self.req.read().unwrap().to_string()
    }

    // TODO: We should drop the message when joining.
    pub fn request_bytes(&self) -> Vec<u8> {
        self.req.read().unwrap().to_bytes()
    }

    pub fn update_from_string(&self, new_req: &str) -> Result<(), GeneralError> {
        let mut req = self.req.write().unwrap();
        req.update(SignRequest::try_from(new_req)?)
    }

    pub fn update_from_bytes(&self, new_req: &Vec<u8>) -> Result<(), GeneralError> {
        self.req
            .write()
            .unwrap()
            .update(SignRequest::try_from(new_req.as_slice())?)
    }

    pub fn instance_id(&self) -> InstanceId {
        self.req.read().unwrap().instance
    }

    pub fn threshold(&self) -> u8 {
        self.keyshare.threshold()
    }

    pub fn party_id(&self) -> u8 {
        self.party_id
    }

    pub fn num_parties(&self) -> u8 {
        self.req.read().unwrap().party_vk.len() as u8
    }

    pub fn message(&self) -> Vec<u8> {
        self.req.read().unwrap().message.clone()
    }

    pub fn hash(&self) -> Vec<u8> {
        self.req.read().unwrap().hash.to_vec()
    }

    pub async fn do_sign(
        &self,
        interface: Arc<dyn NetworkInterface>,
    ) -> Result<Signature, GeneralError> {
        self.do_sign_relay(create_network_relay(interface)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sl_dkls23::keygen::run as keygen_run;
    use sl_dkls23::setup::keygen::SetupMessage as KeygenSetup;

    //helper function to generate the keyshares for the sign protocol
    pub async fn gen_keyshares(
        t: u8,
        n: u8,
    ) -> (Vec<NodeSecretKey>, Vec<NodeVerifyingKey>, Vec<Keyshare>) {
        let instance = InstanceId::from_entropy();
        let party_sk = (0..n)
            .map(|_| NodeSecretKey::from_entropy())
            .collect::<Vec<_>>();
        let party_vk = party_sk
            .iter()
            .map(|sk| NodeVerifyingKey::from_sk(sk))
            .collect::<Vec<_>>();
        let ranks = vec![0u8; n as usize];

        let setup_msgs = party_sk
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                KeygenSetup::new(
                    instance.into(),
                    sk.clone(),
                    i as usize,
                    party_vk.clone(),
                    &ranks,
                    t as usize,
                )
            })
            .collect::<Vec<_>>();

        let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();
        let mut parties = tokio::task::JoinSet::new();

        for setup in setup_msgs {
            parties.spawn({
                let relay = coord.connect();
                let mut rng = ChaCha20Rng::from_entropy();
                keygen_run(setup, rng.gen(), relay)
            });
        }

        // Gather the key shares.
        let shares = parties
            .join_all()
            .await
            .into_iter()
            .map(|r| Keyshare(Arc::new(r.unwrap())))
            .collect::<Vec<_>>();

        (party_sk, party_vk, shares)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_signing() {
        let (party_sk, _party_vk, shares) = gen_keyshares(2, 3).await;
        let instance = InstanceId::from_entropy();

        // Value to be signed
        let message = "Hello World";
        let vk = shares[0].vk();
        let party_sk = party_sk
            .into_iter()
            .map(|sk| Arc::new(sk))
            .collect::<Vec<_>>();

        /*
        // let vks: Vec<NodeVerifyingKey> = vks.into_iter().take(2).collect();
        // OK, I think I finally get it. The KeyShares encode the x points.
        // The VK and SKs are encoded as a list. So you can change the ordering,
        // but the vectors have to match.
        let vks = vec![vks[2].clone(), vks[0].clone()];
        let sks = vec![sks[2].clone(), sks[0].clone()];
        let shares = vec![shares[1].clone(), shares[2].clone()];
        */
        let mut nodes = vec![SignNode::for_message_string(
            &message,
            &instance,
            party_sk[2].clone(),
            &shares[2],
        )];
        nodes.push(
            SignNode::from_request_bytes(
                &nodes[0].request_bytes(),
                party_sk[1].clone(),
                &shares[1],
            )
            .unwrap(),
        );
        nodes[0]
            .update_from_bytes(&nodes[1].request_bytes())
            .unwrap();

        // Simulate running each independently
        let mut parties = tokio::task::JoinSet::new();
        let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();

        println!("Starting signing nodes");
        for node in nodes {
            println!("Signing node {}", node.party_id);
            let relay = coord.connect();
            parties.spawn(async move { node.do_sign_relay(relay).await });
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
                    Ok(share) => results.push(share),
                }
            }
        }

        while let Some(res) = parties.join_next().await {
            let sig = res.unwrap().unwrap();
            assert!(vk.verify(&message.as_bytes(), &sig).is_ok());
        }
    }
}
