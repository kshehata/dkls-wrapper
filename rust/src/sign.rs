use k256::sha2::{Digest, Sha256};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use signature::Signer;
use std::sync::Arc;
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

pub fn hash_sig_req(instance: &InstanceId, msg_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(instance);
    hasher.update(msg_hash);
    hasher.finalize().into()
}

/*****************************************************************************
 * Signature Request
 * Represents a signature request from another node, whether within the app
 * or on the wire.
 *****************************************************************************/

#[derive(uniffi::Object, Clone, Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub instance: InstanceId,
    pub message: Arc<Vec<u8>>,
    pub hash: Option<[u8; 32]>,
    pub party_vk: Vec<NodeVerifyingKey>,
    pub sigs: Vec<Signature>,
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

#[uniffi::export]
impl SignRequest {
    #[uniffi::constructor]
    pub fn for_message_bytes(
        instance: &InstanceId,
        message: Vec<u8>,
        vk: &NodeVerifyingKey,
        sk: &NodeSecretKey,
    ) -> Self {
        let msg_hash = hash_message(&message);
        let req_hash = hash_sig_req(instance, &msg_hash);
        let req_sig = Signature(sk.sign(&req_hash));
        Self {
            instance: *instance,
            message: Arc::new(message),
            hash: None,
            party_vk: vec![vk.clone()],
            sigs: vec![req_sig],
        }
    }

    #[uniffi::constructor]
    pub fn for_message_string(
        instance: &InstanceId,
        message: &str,
        vk: &NodeVerifyingKey,
        sk: &NodeSecretKey,
    ) -> Self {
        Self::for_message_bytes(instance, message.as_bytes().to_vec(), vk, sk)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn instance(&self) -> InstanceId {
        self.instance
    }

    // This is extremely inefficient, but it's the only way in UniFFI.
    pub fn message(&self) -> Vec<u8> {
        self.message.as_ref().clone()
    }

    pub fn message_str(&self) -> String {
        String::from_utf8_lossy(&self.message).to_string()
    }

    pub fn msg_hash(&self) -> Vec<u8> {
        self.get_msg_hash().to_vec()
    }

    // Again inefficient but we don't have a choice when using UniFFI.
    pub fn party_vk(&self) -> Vec<Arc<NodeVerifyingKey>> {
        self.party_vk
            .iter()
            .map(|vk| Arc::new(vk.clone()))
            .collect()
    }

    pub fn sigs(&self) -> Vec<Arc<Signature>> {
        self.sigs.iter().map(|sig| Arc::new(sig.clone())).collect()
    }

    pub fn req_hash(&self) -> Vec<u8> {
        self.get_req_hash().to_vec()
    }

    pub fn check_sigs(&self) -> Result<(), GeneralError> {
        match self.hash {
            Some(hash) => {
                if !self.message.is_empty() && hash != hash_message(&self.message) {
                    return Err(GeneralError::InvalidInput(
                        "Message and hash mismatch".to_string(),
                    ));
                }
            }
            None => {
                if self.message.is_empty() {
                    return Err(GeneralError::InvalidInput("No message or hash".to_string()));
                }
            }
        }
        if self.sigs.is_empty() || self.party_vk.is_empty() {
            return Err(GeneralError::InvalidInput(
                "No signatures or party VKs".to_string(),
            ));
        }
        let req_hash = self.get_req_hash();
        for (sig, vk) in self.sigs.iter().zip(self.party_vk.iter()) {
            match vk.verify(&req_hash, &sig) {
                Ok(_) => continue,
                Err(e) => {
                    // println!("Signature verification failed: {}", e);
                    return Err(GeneralError::SigningError(e.to_string()));
                }
            }
        }
        Ok(())
    }
}

impl SignRequest {
    pub fn get_msg_hash(&self) -> [u8; 32] {
        match self.hash {
            Some(hash) => hash,
            None => hash_message(&self.message),
        }
    }

    pub fn get_req_hash(&self) -> [u8; 32] {
        hash_sig_req(&self.instance, &self.get_msg_hash())
    }

    // Basically strip out the message, add the hash, and sign it ourselves.
    pub fn get_join_reply(&self, vk: &NodeVerifyingKey, sk: &NodeSecretKey) -> SignRequest {
        let req_hash = self.get_req_hash();
        let req_sig = Signature(sk.sign(&req_hash));
        SignRequest {
            instance: self.instance,
            message: Arc::new(vec![]),
            hash: Some(self.get_msg_hash()),
            party_vk: vec![vk.clone()],
            sigs: vec![req_sig],
        }
    }

    // Shortcut to just set the message to be empty and serialize the rest.
    pub fn get_start_bytes(&mut self) -> Vec<u8> {
        self.hash = Some(self.get_msg_hash());
        let empty_msg: Arc<Vec<u8>> = Arc::new(vec![]);
        let org_msg = std::mem::replace(&mut self.message, empty_msg);
        let bytes = self.to_bytes();
        self.message = org_msg;
        self.hash = None;
        bytes
    }

    pub fn check_msg(&self, other: &SignRequest) -> Result<(), GeneralError> {
        if other.instance != self.instance {
            return Err(GeneralError::InvalidInput("Instance mismatch".to_string()));
        }
        // Message should be empty.
        if other.message.len() > 0 && other.message != self.message {
            return Err(GeneralError::InvalidInput("Message mismatch".to_string()));
        }
        match other.hash {
            Some(hash) => {
                if hash != self.get_msg_hash() {
                    return Err(GeneralError::InvalidInput("Hash mismatch".to_string()));
                }
            }
            None => {
                if other.message.is_empty() {
                    return Err(GeneralError::InvalidInput("No message or hash".to_string()));
                }
            }
        }
        if other.party_vk.len() != other.sigs.len() {
            return Err(GeneralError::InvalidInput(
                "Sigs and party count mismatch".to_string(),
            ));
        }
        Ok(())
    }

    // Add joiners to the request.
    pub fn update(&mut self, reply_msg: SignRequest) -> Result<(), GeneralError> {
        self.check_msg(&reply_msg)?;
        // TODO: should verify that VK is valid and in trusted list ?

        // This should always be just inserting one so we don't need to be too worried about efficiency here.
        let new_pairs = reply_msg
            .party_vk
            .into_iter()
            .zip(reply_msg.sigs.into_iter())
            .filter(|(vk, _)| !self.party_vk.contains(vk))
            .collect::<Vec<_>>();

        if new_pairs.is_empty() {
            return Ok(());
        }

        for (vk, sig) in new_pairs {
            self.party_vk.push(vk);
            self.sigs.push(sig);
        }
        Ok(())
    }
}

/*****************************************************************************
 * Support structs for SignNode.
 *****************************************************************************/

// Helper to do the actual signature for a given request using the context
// and relay. Made general for testing.
pub async fn do_sign_relay<R: Relay>(
    ctx: Arc<DeviceLocalData>,
    req: SignRequest,
    party_id: usize,
    relay: R,
) -> Result<Signature, GeneralError> {
    let hash = req.get_msg_hash();
    let setup_msg = SignSetupMessage::new(
        req.instance.into(),
        &ctx.sk,
        party_id,
        req.party_vk,
        ctx.keyshare.0.clone(),
    )
    .with_hash(hash)
    .with_ttl(Duration::from_secs(10));
    let mut rng = ChaCha20Rng::from_entropy();
    Ok(Signature(sign_run(setup_msg, rng.gen(), relay).await?.0))
}

// Encapsulate a signing session originating from us.
// Waits for others to join and then sends start.
pub struct SignOriginatingSession {
    pub ctx: Arc<DeviceLocalData>,
    pub req: SignRequest,
}

impl SignOriginatingSession {
    /// Make a session for a new request to sign the given bytes.
    pub fn from_bytes(ctx: Arc<DeviceLocalData>, bytes: Vec<u8>) -> Self {
        let instance = InstanceId::from_entropy();
        let req = SignRequest::for_message_bytes(&instance, bytes, ctx.my_vk(), &ctx.sk);
        Self { ctx, req }
    }

    /// Make a session for a new request to sign the given string.
    pub fn from_string(ctx: Arc<DeviceLocalData>, string: &str) -> Self {
        Self::from_bytes(ctx, string.as_bytes().to_vec())
    }

    pub fn get_req_bytes(&self) -> Vec<u8> {
        self.req.to_bytes()
    }

    /// Process a reply from another party.
    /// If the reply is valid, it will be added to the request.
    /// If the reply is invalid, an error will be returned.
    /// Returns true if we now have enough parties to sign.
    pub fn process_reply(&mut self, reply_bytes: &[u8]) -> Result<bool, GeneralError> {
        let reply = SignRequest::try_from(reply_bytes)?;
        reply.check_sigs()?;
        self.req.update(reply)?;
        Ok(self.req.party_vk.len() >= self.ctx.threshold() as usize)
    }

    // If we've gotten enough other parties to join, this produces the
    // message telling them which parties are involved.
    pub fn get_start_bytes(&mut self) -> Result<Vec<u8>, GeneralError> {
        if self.req.party_vk.len() < self.ctx.threshold() as usize {
            return Err(GeneralError::InvalidInput("Not enough parties".to_string()));
        }
        Ok(self.req.get_start_bytes())
    }

    pub async fn start_sign<R: Relay>(self, relay: R) -> Result<Signature, GeneralError> {
        // TODO: should probably check that we're ready, but this will get absorbed into something larger anyway.
        do_sign_relay(self.ctx, self.req, 0, relay).await
    }

    pub async fn process(
        mut self,
        net_if: Arc<dyn NetworkInterface>,
    ) -> Result<Signature, GeneralError> {
        // First we have to send out our request
        net_if.send(self.req.to_bytes()).await?;
        // Wait for others to join
        loop {
            let msg = net_if.receive().await?;
            if self.process_reply(&msg)? {
                break;
            }
        }
        net_if.send(self.req.get_start_bytes()).await?;
        // Now we can start the signing session
        do_sign_relay(self.ctx, self.req, 0, create_network_relay(net_if)).await
    }
}

// Encapsulation of joining signing session originated by another party.
// Sends out our joining message and then waits for the start before signing.
pub struct SignReplySession {
    pub ctx: Arc<DeviceLocalData>,
    pub req: Arc<SignRequest>,
}

impl SignReplySession {
    /// Join a signing request.
    /// If the request is valid, create a session for joining it.
    /// If the request is invalid, returns an error.
    pub fn join_request(
        ctx: Arc<DeviceLocalData>,
        req: Arc<SignRequest>,
    ) -> Result<Self, GeneralError> {
        if req.message.is_empty() {
            return Err(GeneralError::InvalidInput("No message".to_string()));
        }
        req.check_sigs()?;
        Ok(Self { ctx, req })
    }

    pub fn get_reply_bytes(&self) -> Vec<u8> {
        self.req
            .get_join_reply(&self.ctx.my_vk(), &self.ctx.sk)
            .to_bytes()
    }

    // A start message is valid if it has the correct instance and hash, starts
    // with the same VK, and has ours somewhere.
    pub fn check_start_msg(&self, msg: &SignRequest) -> Result<u8, GeneralError> {
        self.req.check_msg(msg)?;
        if msg.party_vk.len() < self.ctx.threshold() as usize {
            return Err(GeneralError::InvalidInput("Not enough parties".to_string()));
        }
        if msg.party_vk.first() != self.req.party_vk.first() {
            return Err(GeneralError::InvalidInput("Party VK mismatch".to_string()));
        }
        let Some(party_id) = msg.party_vk.iter().position(|vk| vk == self.ctx.my_vk()) else {
            return Err(GeneralError::InvalidInput("Our VK not in list".to_string()));
        };

        Ok(party_id as u8)
    }

    // Check that a start message is valid and we could start signing.
    // Returns our party ID if so.
    pub fn check_start_bytes(&self, bytes: &[u8]) -> Result<u8, GeneralError> {
        let msg = SignRequest::try_from(bytes)?;
        self.check_start_msg(&msg)
    }

    pub async fn check_and_start_sign<R: Relay>(
        self,
        msg: SignRequest,
        relay: R,
    ) -> Result<Signature, GeneralError> {
        let party_id = self.check_start_msg(&msg)?;
        do_sign_relay(self.ctx, msg, party_id.into(), relay).await
    }

    pub async fn process(
        self,
        net_if: Arc<dyn NetworkInterface>,
    ) -> Result<Signature, GeneralError> {
        // First we have to send out our reply

        net_if.send(self.get_reply_bytes()).await?;
        // Wait for start signal from the originator
        let (party_id, start_msg) = loop {
            let msg = net_if.receive().await?;
            let start_msg = SignRequest::try_from(msg.as_slice())?;
            match self.check_start_msg(&start_msg) {
                Ok(party_id) => break (party_id, start_msg),
                // Just ignore any invalid messages
                Err(_) => continue,
            }
        };

        // Now we can start the signing session
        do_sign_relay(
            self.ctx,
            start_msg,
            party_id.into(),
            create_network_relay(net_if),
        )
        .await
    }
}

/*****************************************************************************
 * DSG Node Representation.
 *****************************************************************************/

#[derive(Clone, uniffi::Object)]
pub struct SignNode {
    ctx: Arc<DeviceLocalData>,
}

impl SignNode {
    /// Make a new request to sign the given bytes.
    pub fn new_request_bytes(&self, bytes: Vec<u8>) -> SignOriginatingSession {
        SignOriginatingSession::from_bytes(self.ctx.clone(), bytes)
    }

    /// Make a new request to sign the given string.
    pub fn new_request_string(&self, string: &str) -> SignOriginatingSession {
        SignOriginatingSession::from_string(self.ctx.clone(), string)
    }

    /// Join a signing request.
    /// If the request is valid, gives the response to be sent to the original requester.
    /// If the request is invalid, returns an error.
    pub fn join_request(&self, req: Arc<SignRequest>) -> Result<SignReplySession, GeneralError> {
        SignReplySession::join_request(self.ctx.clone(), req)
    }
}

#[uniffi::export]
impl SignNode {
    #[uniffi::constructor]
    pub fn new(ctx: Arc<DeviceLocalData>) -> Self {
        Self { ctx }
    }

    // Get the next signing request from the network interface.
    pub async fn get_next_req(
        &self,
        net_if: Arc<dyn NetworkInterface>,
    ) -> Result<SignRequest, GeneralError> {
        let msg = net_if.receive().await?;
        SignRequest::try_from(msg.as_slice())
    }

    pub async fn do_sign_bytes(
        &self,
        bytes: Vec<u8>,
        net_if: Arc<dyn NetworkInterface>,
    ) -> Result<Signature, GeneralError> {
        let sess = self.new_request_bytes(bytes);
        sess.process(net_if).await
    }

    pub async fn do_sign_string(
        &self,
        string: &str,
        net_if: Arc<dyn NetworkInterface>,
    ) -> Result<Signature, GeneralError> {
        let sess = self.new_request_string(string);
        sess.process(net_if).await
    }

    pub async fn do_join_request(
        &self,
        req: Arc<SignRequest>,
        net_if: Arc<dyn NetworkInterface>,
    ) -> Result<Signature, GeneralError> {
        let sess = self.join_request(req)?;
        sess.process(net_if).await
    }
}

#[cfg(test)]
mod tests {
    use crate::net::InMemoryBridge;
    use crate::test::*;

    use super::*;

    #[test]
    pub fn test_sig_req() {
        let instance = InstanceId::from_entropy();
        let sk = Arc::new(NodeSecretKey::from_entropy());
        let msg = "Hello World";
        let sig_req =
            SignRequest::for_message_string(&instance, msg, &NodeVerifyingKey::from_sk(&sk), &sk);

        assert_eq!(sig_req.instance, instance);
        assert_eq!(sig_req.message.as_ref(), msg.as_bytes());
        assert_eq!(sig_req.party_vk.len(), 1);
        assert_eq!(sig_req.party_vk[0], NodeVerifyingKey::from_sk(&sk));
        assert_eq!(sig_req.sigs.len(), 1);
        assert_eq!(sig_req.get_msg_hash(), hash_string(msg));
        assert!(sig_req.check_sigs().is_ok());
    }

    #[test]
    pub fn test_sig_reply() {
        let instance = InstanceId::from_entropy();
        let sk = Arc::new(NodeSecretKey::from_entropy());
        let msg = "Hello World";
        let sig_req =
            SignRequest::for_message_string(&instance, msg, &NodeVerifyingKey::from_sk(&sk), &sk);
        let sk2 = Arc::new(NodeSecretKey::from_entropy());
        let sig_reply = sig_req.get_join_reply(&NodeVerifyingKey::from_sk(&sk2), &sk2);

        assert_eq!(sig_reply.instance, instance);
        assert!(sig_reply.message.is_empty());
        assert_eq!(sig_reply.hash, Some(hash_string(msg)));
        assert_eq!(sig_reply.party_vk.len(), 1);
        assert_eq!(sig_reply.party_vk[0], NodeVerifyingKey::from_sk(&sk2));
        assert_eq!(sig_reply.sigs.len(), 1);
        assert!(sig_reply.check_sigs().is_ok());
    }

    #[test]
    pub fn test_sig_req_update() {
        let instance = InstanceId::from_entropy();
        let sk = Arc::new(NodeSecretKey::from_entropy());
        let msg = "Hello World";
        let mut sig_req =
            SignRequest::for_message_string(&instance, msg, &NodeVerifyingKey::from_sk(&sk), &sk);
        let sk2 = Arc::new(NodeSecretKey::from_entropy());
        let sig_reply = sig_req.get_join_reply(&NodeVerifyingKey::from_sk(&sk2), &sk2);
        sig_req.update(sig_reply).unwrap();

        assert_eq!(sig_req.instance, instance);
        assert_eq!(sig_req.message.as_ref(), msg.as_bytes());
        assert_eq!(sig_req.party_vk.len(), 2);
        assert_eq!(sig_req.party_vk[0], NodeVerifyingKey::from_sk(&sk));
        assert_eq!(sig_req.party_vk[1], NodeVerifyingKey::from_sk(&sk2));
        assert_eq!(sig_req.sigs.len(), 2);
        assert_eq!(sig_req.get_msg_hash(), hash_string(msg));
        assert!(sig_req.check_sigs().is_ok());

        let start_msg = SignRequest::try_from(sig_req.get_start_bytes().as_slice()).unwrap();
        assert_eq!(start_msg.instance, instance);
        assert!(start_msg.message.is_empty());
        assert_eq!(start_msg.hash, Some(hash_string(msg)));
        assert_eq!(start_msg.party_vk.len(), 2);
        assert_eq!(start_msg.party_vk[0], NodeVerifyingKey::from_sk(&sk));
        assert_eq!(start_msg.party_vk[1], NodeVerifyingKey::from_sk(&sk2));
        assert_eq!(start_msg.sigs.len(), 2);
        assert!(start_msg.check_sigs().is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_signing_manual() {
        let ctxs = gen_local_data_async(2, 3).await;

        // Value to be signed
        let message = "Hello World";
        let vk = ctxs[0].keyshare.vk();

        let nodes = ctxs
            .into_iter()
            .map(|ctx| SignNode::new(ctx))
            .collect::<Vec<_>>();

        // Node 0 generates a signing request and sends to all others.
        let mut og_sess = nodes[0].new_request_string(message);
        let req_bytes = og_sess.get_req_bytes();

        // Node 1 joins by sending a reply to Node 0.
        let req = SignRequest::try_from(req_bytes.as_slice()).unwrap();
        let join_sess = nodes[1].join_request(Arc::new(req)).unwrap();
        let reply_bytes = join_sess.get_reply_bytes();

        // Node 0 processes the reply and updates the request state.
        assert!(og_sess.process_reply(&reply_bytes).unwrap());

        // Node 0 generates the start message and sends it to all others.
        let start = og_sess.get_start_bytes().unwrap();

        // Node 1 receives the start message and checks it.
        assert_eq!(join_sess.check_start_bytes(&start).unwrap(), 1);
        let start_req = SignRequest::try_from(start.as_slice()).unwrap();

        /*
        // let vks: Vec<NodeVerifyingKey> = vks.into_iter().take(2).collect();
        // OK, I think I finally get it. The KeyShares encode the x points.
        // The VK and SKs are encoded as a list. So you can change the ordering,
        // but the vectors have to match.
        let vks = vec![vks[2].clone(), vks[0].clone()];
        let sks = vec![sks[2].clone(), sks[0].clone()];
        let shares = vec![shares[1].clone(), shares[2].clone()];
        */

        // Simulate running each independently
        let mut parties = tokio::task::JoinSet::new();
        let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();

        let relay = coord.connect();
        parties.spawn(async move { og_sess.start_sign(relay).await });

        let relay = coord.connect();
        parties.spawn(async move { join_sess.check_and_start_sign(start_req, relay).await });

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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_signing() {
        let (t, n) = (3usize, 5usize);
        let ctxs = gen_local_data_async(t as u8, n as u8).await;

        // Value to be signed
        let message = "Hello World";
        let vk = ctxs[0].keyshare.vk();

        let nodes = ctxs
            .into_iter()
            .map(|ctx| SignNode::new(ctx))
            .collect::<Vec<_>>();

        // Node 0 generates a signing request and sends to all others.
        let og_sess = nodes[n - 1].new_request_string(message);

        let coord = InMemoryBridge::new();
        let r1 = coord.connect();
        let nets = (1..t).map(|_| coord.connect()).collect::<Vec<_>>();
        let mut parties = tokio::task::JoinSet::new();
        parties.spawn(async move { og_sess.process(r1).await });

        for (n, net) in nodes.iter().zip(nets.into_iter()) {
            let req = n.get_next_req(net.clone()).await.unwrap();
            let join_sess = n.join_request(Arc::new(req)).unwrap();
            parties.spawn(async move { join_sess.process(net).await });
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_signing_shortcuts() {
        let (t, n) = (3usize, 5usize);
        let ctxs = gen_local_data_async(t as u8, n as u8).await;

        // Value to be signed
        let message = "Hello World";
        let vk = ctxs[0].keyshare.vk();

        let mut nodes = ctxs
            .into_iter()
            .map(|ctx| SignNode::new(ctx))
            .collect::<Vec<_>>();

        // Node 0 generates a signing request and sends to all others.

        let coord = InMemoryBridge::new();
        let r1 = coord.connect();
        let nets = (1..t).map(|_| coord.connect()).collect::<Vec<_>>();
        let mut parties = tokio::task::JoinSet::new();
        {
            let n = nodes.pop().unwrap();
            parties.spawn(async move { n.do_sign_string(message, r1).await });
        }

        for (n, net) in nodes.into_iter().zip(nets.into_iter()) {
            let req = n.get_next_req(net.clone()).await.unwrap();
            // Simulate getting approval
            parties.spawn(async move { n.do_join_request(Arc::new(req), net).await });
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
