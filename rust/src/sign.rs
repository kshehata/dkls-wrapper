use k256::sha2::{Digest, Sha256};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use signature::Signer;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use sl_dkls23::setup::sign::SetupMessage as SignSetupMessage;
use sl_dkls23::sign::run as sign_run;
use sl_dkls23::Relay;

use crate::error::GeneralError;
use crate::net::{create_network_relay, NetworkInterface};
use crate::types::*;

type MessageHash = [u8; 32];

/*****************************************************************************
 * Signature Request
 * Represents a signature request from another node, whether within the app
 * or on the wire.
 *****************************************************************************/

// Kind of message being signed.
// Right now it's just string vs an arbitrary byte array.
// In the future might be extended to other types of messages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum SignMessageType {
    String(String),
    Bytes(Vec<u8>),
}

impl SignMessageType {
    // Make this explicit to *always* use SHA-256.
    // Otherwise, if Rust changes something we'll have incompatible sigs.
    pub fn get_hash(&self) -> MessageHash {
        let mut hasher = Sha256::new();
        match self {
            SignMessageType::String(msg) => {
                hasher.update(msg.as_bytes());
            }
            SignMessageType::Bytes(msg) => {
                hasher.update(msg);
            }
        }
        hasher.finalize().into()
    }
}

// For UniFFI to get hashes

#[uniffi::export]
pub fn get_hash_string(msg: String) -> Vec<u8> {
    let msg = SignMessageType::String(msg);
    msg.get_hash().to_vec()
}

#[uniffi::export]
pub fn get_hash_bytes(msg: Vec<u8>) -> Vec<u8> {
    let msg = SignMessageType::Bytes(msg);
    msg.get_hash().to_vec()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignRequestType {
    Request(SignMessageType),
    Join,
    Start,
    Cancel,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, uniffi::Object)]
pub struct SignRequest {
    pub instance: InstanceId,
    pub req_type: SignRequestType,
    pub hash: MessageHash,
    pub sigs: Vec<(NodeVerifyingKey, Signature)>,
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
        let msg = SignMessageType::Bytes(message.clone());
        Self::new_request(instance, msg, vk, sk)
    }

    #[uniffi::constructor]
    pub fn for_message_string(
        instance: &InstanceId,
        message: &str,
        vk: &NodeVerifyingKey,
        sk: &NodeSecretKey,
    ) -> Self {
        let msg = SignMessageType::String(message.to_string());
        Self::new_request(instance, msg, vk, sk)
    }

    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, GeneralError> {
        Self::try_from(bytes.as_slice())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn instance(&self) -> InstanceId {
        self.instance
    }

    pub fn get_instance(&self) -> InstanceId {
        self.instance
    }

    // Only valid on a request.
    // This is extremely inefficient, but it's the only way in UniFFI.
    pub fn get_message(&self) -> Option<SignMessageType> {
        match &self.req_type {
            SignRequestType::Request(msg) => Some(msg.clone()),
            _ => None,
        }
    }

    // Vector for UniFFI
    pub fn get_msg_hash(&self) -> Vec<u8> {
        self.hash.to_vec()
    }

    // Helper that assumes there's only one VK.
    pub fn get_vk(&self) -> Option<Arc<NodeVerifyingKey>> {
        if self.sigs.len() != 1 {
            return None;
        }
        Some(Arc::new(self.sigs[0].0.clone()))
    }

    // Again inefficient but we don't have a choice when using UniFFI.
    pub fn party_vk(&self) -> Vec<Arc<NodeVerifyingKey>> {
        self.sigs
            .iter()
            .map(|(vk, _)| Arc::new(vk.clone()))
            .collect()
    }

    pub fn check_sigs(&self) -> Result<(), GeneralError> {
        match &self.req_type {
            SignRequestType::Start => {
                if self.sigs.len() <= 1 {
                    return Err(GeneralError::InvalidInput(
                        "Invalid number of signatures".to_string(),
                    ));
                }
                let mut vk_set = std::collections::HashSet::new();
                if !self.sigs.iter().all(|(vk, _)| vk_set.insert(vk)) {
                    return Err(GeneralError::InvalidInput(
                        "Duplicate VKs in signature list".to_string(),
                    ));
                }
            }
            _ => {
                if self.sigs.len() != 1 {
                    return Err(GeneralError::InvalidInput(
                        "Invalid number of signatures".to_string(),
                    ));
                }
            }
        };

        // Check that the hash in the message matches the hash in the request.
        if let SignRequestType::Request(msg) = &self.req_type {
            if msg.get_hash() != self.hash {
                return Err(GeneralError::InvalidInput(
                    "Message hash does not match request hash".to_string(),
                ));
            }
        }

        let req_hash = self.req_hash();
        for (vk, sig) in self.sigs.iter() {
            match vk.verify(&req_hash, sig) {
                Ok(_) => continue,
                Err(e) => {
                    // println!("Signature verification failed: {}", e);
                    return Err(GeneralError::SigningError(e.to_string()));
                }
            }
        }
        Ok(())
    }

    pub fn equals(&self, other: &SignRequest) -> bool {
        self == other
    }
}

impl SignRequest {
    fn empty(instance: &InstanceId, req: SignRequestType, hash: MessageHash) -> Self {
        Self {
            instance: *instance,
            req_type: req,
            hash,
            sigs: vec![],
        }
    }

    fn new(
        instance: &InstanceId,
        req: SignRequestType,
        hash: MessageHash,
        vk: &NodeVerifyingKey,
        sk: &NodeSecretKey,
    ) -> Self {
        let mut req = Self::empty(instance, req, hash);
        req.sign(vk, sk);
        req
    }

    fn new_request(
        instance: &InstanceId,
        msg: SignMessageType,
        vk: &NodeVerifyingKey,
        sk: &NodeSecretKey,
    ) -> Self {
        let hash = msg.get_hash();
        Self::new(instance, SignRequestType::Request(msg), hash, vk, sk)
    }

    pub fn req_hash(&self) -> MessageHash {
        let mut hasher = Sha256::new();
        hasher.update(&self.instance);
        hasher.update(&self.hash);
        // Need to avoid replays with cancel.
        if self.req_type == SignRequestType::Cancel {
            hasher.update(&[1]);
        } else {
            hasher.update(&[0]);
        }
        hasher.finalize().into()
    }

    pub fn sign(&mut self, vk: &NodeVerifyingKey, sk: &NodeSecretKey) {
        let sig = Signature(sk.sign(&self.req_hash()));
        self.sigs.push((vk.clone(), sig));
    }

    pub fn get_join_reply(&self, vk: &NodeVerifyingKey, sk: &NodeSecretKey) -> SignRequest {
        Self::new(&self.instance, SignRequestType::Join, self.hash, vk, sk)
    }

    pub fn get_cancel_req(&self, vk: &NodeVerifyingKey, sk: &NodeSecretKey) -> SignRequest {
        Self::new(&self.instance, SignRequestType::Cancel, self.hash, vk, sk)
    }

    // Assume we've added a bunch of joiners to the vector of party VKs.
    // Change the request type to Start and serialize to bytes.
    // (then swap back.)
    pub fn get_start_bytes(&mut self) -> Vec<u8> {
        let mut start_req = SignRequestType::Start;
        std::mem::swap(&mut self.req_type, &mut start_req);
        let bytes = self.to_bytes();
        std::mem::swap(&mut self.req_type, &mut start_req);
        bytes
    }

    // Check that a received request matches our own.
    // Return a result so callers can shortcut to error handling.
    pub fn check_matches(&self, other: &SignRequest) -> Result<(), GeneralError> {
        if other.instance != self.instance {
            return Err(GeneralError::InvalidInput("Instance mismatch".to_string()));
        }

        if self.hash != other.hash {
            return Err(GeneralError::InvalidInput(
                "Message hash mismatch".to_string(),
            ));
        }

        // Should never be comparing two requests for the same instance.
        // If this happens it's almost certainly a bug.
        // Rather than assert, return an error so the message can be dropped.
        match (&self.req_type, &other.req_type) {
            (SignRequestType::Request(_), SignRequestType::Request(_)) => {
                return Err(GeneralError::InvalidInput(
                    "Cannot have two requests".to_string(),
                ));
            }
            _ => {}
        }

        Ok(())
    }

    // Add joiners to the request.
    pub fn update(&mut self, reply_msg: SignRequest) -> Result<(), GeneralError> {
        self.check_matches(&reply_msg)?;
        // TODO: should verify that VK is valid and in trusted list ?

        // This should always be just inserting one so we don't need to be too
        // worried about efficiency here.
        // Just make sure we don't have the same VK more than once.
        let new_pairs = reply_msg
            .sigs
            .into_iter()
            .filter(|(vk, _)| !self.sigs.iter().any(|(v, _)| v == vk))
            .collect::<Vec<_>>();

        self.sigs.extend(new_pairs);
        Ok(())
    }

    // Remove a party from the request.
    pub fn remove_vk(&mut self, vk: &NodeVerifyingKey) {
        self.sigs.retain(|(v, _)| v != vk);
    }

    pub fn has_vk(&self, vk: &NodeVerifyingKey) -> bool {
        self.sigs.iter().any(|(v, _)| v == vk)
    }
}

/*****************************************************************************
 * Support structs for SignNode.
 *****************************************************************************/

use hex;
// Helper to do the actual signature for a given request using the context
// and relay. Made general for testing.
pub async fn do_sign_relay<R: Relay>(
    ctx: Arc<DeviceLocalData>,
    req: &SignRequest,
    party_id: usize,
    relay: R,
) -> Result<Signature, GeneralError> {
    let hash = req.hash;
    let party_vk = req.sigs.iter().map(|(k, _)| k).collect::<Vec<_>>();
    println!("doing sig for msg hash {:?}", hex::encode(hash));
    let setup_msg = SignSetupMessage::new(
        req.instance.into(),
        &ctx.sk,
        party_id,
        party_vk,
        ctx.keyshare.0.clone(),
    )
    .with_hash(hash)
    .with_ttl(Duration::from_secs(10));
    let mut rng = ChaCha20Rng::from_entropy();
    Ok(Signature(sign_run(setup_msg, rng.gen(), relay).await?.0))
}

// Callback on receiving a new signing request,
// and when a request is cancelled before being accepted.
#[uniffi::export(callback_interface)]
pub trait SignRequestListener: Send + Sync {
    fn receive_sign_request(&self, req: Arc<SignRequest>);
    fn cancel_sign_request(&self, req: Arc<SignRequest>);
}

// Callbacks for any signing request.
#[uniffi::export(callback_interface)]
pub trait SignResultListener: Send + Sync {
    // Devices involved in a signature changed.
    fn sign_devices_changed(&self, req: Arc<SignRequest>);
    // The actual DSG protocol started.
    fn sign_dsg_started(&self, req: Arc<SignRequest>);
    // Signature request was cancelled by originator.
    fn sign_cancelled(&self, req: Arc<SignRequest>);
    // Error occurred in DSG.
    fn sign_error(&self, req: Arc<SignRequest>, error: GeneralError);
    // DSG completed successfully.
    fn sign_result(&self, req: Arc<SignRequest>, result: Arc<Signature>);
}

type RequestItem = (Arc<SignRequest>, Box<dyn SignResultListener>);

/*****************************************************************************
 * DSG Node Representation.
 *****************************************************************************/

#[derive(uniffi::Object)]
pub struct SignNode {
    ctx: Arc<DeviceLocalData>,
    outgoing_reqs: Mutex<HashMap<InstanceId, RequestItem>>,
    incoming_reqs: Mutex<HashMap<InstanceId, Arc<SignRequest>>>,
    accepted_reqs: Mutex<HashMap<InstanceId, RequestItem>>,
    request_listener: RwLock<Option<Box<dyn SignRequestListener>>>,
    net_if: Arc<dyn NetworkInterface>,
}

#[uniffi::export]
impl SignNode {
    #[uniffi::constructor]
    pub fn new(ctx: Arc<DeviceLocalData>, net_if: Arc<dyn NetworkInterface>) -> Self {
        Self {
            ctx,
            outgoing_reqs: Mutex::new(HashMap::new()),
            incoming_reqs: Mutex::new(HashMap::new()),
            accepted_reqs: Mutex::new(HashMap::new()),
            request_listener: RwLock::new(None),
            net_if,
        }
    }

    pub fn set_request_listener(&self, listener: Box<dyn SignRequestListener>) {
        self.request_listener.write().unwrap().replace(listener);
    }

    // Request a signature on a string.
    pub async fn request_sign_string(
        &self,
        message: String,
        listener: Box<dyn SignResultListener>,
    ) -> Result<Arc<SignRequest>, GeneralError> {
        let req = self.new_request(SignMessageType::String(message), listener);
        self.net_if.send(req.to_bytes()).await?;
        Ok(req)
    }

    // Cancel a request that we either sent out or accepted.
    pub async fn cancel_request(&self, req: &SignRequest) -> Result<(), GeneralError> {
        let og_req = if let Some((req, _)) =
            self.outgoing_reqs.lock().unwrap().remove(&req.instance)
        {
            req
        } else if let Some((req, _)) = self.accepted_reqs.lock().unwrap().remove(&req.instance) {
            req
        } else {
            // Didn't have this request anyway.
            return Ok(());
        };
        let cancel_req = og_req.get_cancel_req(&self.ctx.my_vk(), &self.ctx.sk);
        self.net_if.send(cancel_req.to_bytes()).await?;
        Ok(())
    }

    // Request a signature on a byte array.
    pub async fn request_sign_bytes(
        &self,
        bytes: Vec<u8>,
        listener: Box<dyn SignResultListener>,
    ) -> Result<Arc<SignRequest>, GeneralError> {
        let req = self.new_request(SignMessageType::Bytes(bytes), listener);
        self.net_if.send(req.to_bytes()).await?;
        Ok(req)
    }

    // Accept a previously received signature request from another device.
    pub async fn accept_request(
        &self,
        req: Arc<SignRequest>,
        listener: Box<dyn SignResultListener>,
    ) -> Result<(), GeneralError> {
        self.accept_request_impl(req.clone(), listener)?;
        let join_req = req.get_join_reply(self.ctx.my_vk(), &self.ctx.sk);
        self.net_if.send(join_req.to_bytes()).await?;
        Ok(())
    }

    pub fn reject_request(&self, req: &SignRequest) {
        // Just remove the request from the queue, no need to reply.
        self.incoming_reqs.lock().unwrap().remove(&req.instance);
    }

    pub async fn message_loop(&self) -> Result<(), GeneralError> {
        loop {
            self.process_next_msg().await?;
        }
    }
}

impl SignNode {
    // Received a signing request from another device over the network.
    // Inform the listener, which can then call back to accept it.
    // Don't do accept it otherwise it would block the thread.
    pub fn receive_request(&self, req: SignRequest) {
        // Signature already checked and must be exactly 1.
        // New request. First check whether to accept it.

        // If we don't have a listener, then no point queueing the request.
        let guard = self.request_listener.read().unwrap();
        let Some(listener) = guard.as_ref() else {
            return;
        };
        let req = Arc::new(req);
        {
            self.incoming_reqs
                .lock()
                .unwrap()
                .insert(req.instance, req.clone());
        }
        listener.receive_sign_request(req);
    }

    // Received a join response, see if it's ours and if we're now ready.
    pub fn receive_join(&self, req: SignRequest) -> Result<Option<RequestItem>, GeneralError> {
        // Check if we have an outgoing request for this instance.
        let mut guard = self.outgoing_reqs.lock().unwrap();
        let Entry::Occupied(mut og_entry) = guard.entry(req.instance) else {
            // Not for us.
            return Ok(None);
        };
        // Checks the hash and updates our party list.
        let (og_req, listener) = og_entry.get_mut();
        Arc::make_mut(og_req).update(req)?;
        // Alert the listener that the party list has changed.
        listener.sign_devices_changed(og_req.clone());

        if og_req.sigs.len() >= self.ctx.threshold() as usize {
            // If we have enough parties to sign, then remove the
            // entry from the hashmap and return the request in order to
            // start the DSG.
            let og_item = og_entry.remove();
            return Ok(Some(og_item));
        }
        Ok(None)
    }

    // Received a start message, check if we have an accepted request for it.
    // If so, check that the request matches and return our party id.
    pub fn receive_start(
        &self,
        req: SignRequest,
    ) -> Result<Option<(RequestItem, usize)>, GeneralError> {
        let mut guard = self.accepted_reqs.lock().unwrap();
        let Entry::Occupied(og_entry) = guard.entry(req.instance) else {
            // If we don't have an accepted request, check if we have a pending request.
            let mut guard = self.incoming_reqs.lock().unwrap();
            if let Some(og_req) = guard.remove(&req.instance) {
                // Notify the UI that this pending request was cancelled.
                let guard = self.request_listener.read().unwrap();
                if let Some(listener) = guard.as_ref() {
                    listener.cancel_sign_request(og_req);
                }
                return Ok(None);
            }
            // Probably means we missed the request message.
            return Ok(None);
        };

        let og_req = &og_entry.get().0;
        og_req.check_matches(&req)?;

        if req.sigs.len() < self.ctx.threshold() as usize {
            return Err(GeneralError::InvalidInput(
                "Not enough signatures".to_string(),
            ));
        }

        // Assume that we've already checked sigs and that all VK are unique.
        let Some(party_id) = req.sigs.iter().position(|(vk, _)| vk == self.ctx.my_vk()) else {
            return Err(GeneralError::InvalidInput("Our VK not in list".to_string()));
        };

        // Remove the request from the accepted list.
        let (_, listener) = og_entry.remove();
        // Send back the new request because it has the start info.
        Ok(Some(((req.into(), listener), party_id)))
    }

    pub fn receive_cancel(&self, req: &SignRequest) {
        println!("receive_cancel: Instance ID: {}", hex::encode(req.instance));
        // Must have exactly one signature in a cancel message.
        let vk = &req.sigs[0].0;
        // Check if we have an outgoing request for this instance.
        if let Some((og_req, listener)) = self.outgoing_reqs.lock().unwrap().get_mut(&req.instance)
        {
            println!("receive_cancel: checking outgoing_reqs");
            // Remove the participant VK from the list.
            if og_req.check_matches(req).is_ok() {
                Arc::make_mut(og_req).remove_vk(vk);
                listener.sign_devices_changed(og_req.clone());
            }
        }
        // Check if we have an accepted request for this instance.
        if let Entry::Occupied(og_entry) = self.accepted_reqs.lock().unwrap().entry(req.instance) {
            println!("receive_cancel: found in accepted_reqs");
            let og_req = &og_entry.get().0;
            // The original request would only have had one VK so check that they match.
            if og_req.check_matches(req).is_ok() {
                if og_req.has_vk(vk) {
                    println!(
                        "receive_cancel: has_vk matched, removing from accepted_reqs and firing"
                    );
                    let (og_req, listener) = og_entry.remove();
                    listener.sign_cancelled(og_req);
                } else {
                    println!(
                        "receive_cancel: has_vk FAILED! og_req vks: {:?}",
                        og_req
                            .sigs
                            .iter()
                            .map(|s| hex::encode(s.0.to_bytes()))
                            .collect::<Vec<_>>()
                    );
                    println!("receive_cancel: search vk: {}", hex::encode(vk.to_bytes()));
                }
            } else {
                println!("receive_cancel: check_matches FAILED!");
            }
        };
        if let Entry::Occupied(og_entry) = self.incoming_reqs.lock().unwrap().entry(req.instance) {
            println!("receive_cancel: found in incoming_reqs");
            if og_entry.get().check_matches(req).is_ok() && og_entry.get().has_vk(vk) {
                let og_req = og_entry.remove();

                // Notify the UI that this pending request was cancelled.
                let guard = self.request_listener.read().unwrap();
                if let Some(listener) = guard.as_ref() {
                    listener.cancel_sign_request(og_req);
                }
            }
        };
    }

    // Get the next signing request from the network interface.
    pub async fn process_next_msg(&self) -> Result<(), GeneralError> {
        let msg_bytes = self.net_if.receive().await?;
        let req = SignRequest::try_from(msg_bytes.as_slice())?;
        req.check_sigs()?;

        let start_op = match &req.req_type {
            SignRequestType::Request(_) => {
                self.receive_request(req);
                None
            }
            SignRequestType::Join => {
                let start = self.receive_join(req)?;
                if let Some((mut start_req, listener)) = start {
                    let start_bytes = Arc::make_mut(&mut start_req).get_start_bytes();
                    self.net_if.send(start_bytes).await?;
                    Some(((start_req, listener), 0))
                } else {
                    None
                }
            }
            SignRequestType::Start => self.receive_start(req)?,
            SignRequestType::Cancel => {
                self.receive_cancel(&req);
                None
            }
        };

        // If we're clear to start, notify the listener and do it.
        if let Some(((start_req, listener), party_id)) = start_op {
            listener.sign_dsg_started(start_req.clone());
            let res = do_sign_relay(
                self.ctx.clone(),
                &start_req,
                party_id,
                create_network_relay(self.net_if.clone()),
            )
            .await;
            match res {
                Ok(sig) => listener.sign_result(start_req, Arc::new(sig)),
                Err(e) => listener.sign_error(start_req, e),
            }
        }
        Ok(())
    }

    // Internal helper to create a new signing request and add it to the queue.
    fn new_request(
        &self,
        msg: SignMessageType,
        listener: Box<dyn SignResultListener>,
    ) -> Arc<SignRequest> {
        let instance = InstanceId::from_entropy();
        let req = Arc::new(SignRequest::new_request(
            &instance,
            msg,
            self.ctx.my_vk(),
            &self.ctx.sk,
        ));
        {
            self.outgoing_reqs
                .lock()
                .unwrap()
                .insert(instance, (req.clone(), listener));
        }
        req
    }

    // Internal sync function to ensure we never leak mutexes.

    fn accept_request_impl(
        &self,
        req: Arc<SignRequest>,
        listener: Box<dyn SignResultListener>,
    ) -> Result<(), GeneralError> {
        let og_req = self.incoming_reqs.lock().unwrap().remove(&req.instance);
        let Some(og_req) = og_req else {
            return Err(GeneralError::InvalidInput("No such request".to_string()));
        };

        if og_req != req {
            return Err(GeneralError::InvalidInput("Request mismatch".to_string()));
        }
        self.accepted_reqs
            .lock()
            .unwrap()
            .insert(og_req.instance, (og_req, listener));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::InMemoryBridge;
    use crate::test::gen_local_data_async;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::time::{timeout, Duration};

    struct SharedState {
        received_req: Mutex<Option<Arc<SignRequest>>>,
        received_sig: Mutex<Option<Arc<Signature>>>,
        accept_signal: AtomicBool,
        sig_signal: AtomicBool,
        devices_changed_signal: AtomicBool,
        started_signal: AtomicBool,
        cancelled_signal: AtomicBool,
    }

    struct SharedListener {
        state: Arc<SharedState>,
    }

    impl SharedListener {
        fn new() -> (Self, Arc<SharedState>) {
            let state = Arc::new(SharedState {
                received_req: Mutex::new(None),
                received_sig: Mutex::new(None),
                accept_signal: AtomicBool::new(false),
                sig_signal: AtomicBool::new(false),
                devices_changed_signal: AtomicBool::new(false),
                started_signal: AtomicBool::new(false),
                cancelled_signal: AtomicBool::new(false),
            });
            (
                Self {
                    state: state.clone(),
                },
                state,
            )
        }
    }

    impl SignRequestListener for SharedListener {
        fn receive_sign_request(&self, req: Arc<SignRequest>) {
            *self.state.received_req.lock().unwrap() = Some(req);
            self.state.accept_signal.store(true, Ordering::SeqCst);
        }
        fn cancel_sign_request(&self, _req: Arc<SignRequest>) {
            self.state.cancelled_signal.store(true, Ordering::SeqCst);
        }
    }

    impl SignResultListener for SharedListener {
        fn sign_devices_changed(&self, _req: Arc<SignRequest>) {
            self.state
                .devices_changed_signal
                .store(true, Ordering::SeqCst);
        }
        fn sign_dsg_started(&self, _req: Arc<SignRequest>) {
            self.state.started_signal.store(true, Ordering::SeqCst);
        }
        fn sign_result(&self, _req: Arc<SignRequest>, result: Arc<Signature>) {
            *self.state.received_sig.lock().unwrap() = Some(result);
            self.state.sig_signal.store(true, Ordering::SeqCst);
        }
        fn sign_cancelled(&self, _req: Arc<SignRequest>) {
            self.state.cancelled_signal.store(true, Ordering::SeqCst);
        }
        fn sign_error(&self, _req: Arc<SignRequest>, _error: GeneralError) {}
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_2_party_sign() {
        let contexts = gen_local_data_async(2, 2).await;
        let bridge = InMemoryBridge::new();

        let node1 = Arc::new(SignNode::new(contexts[0].clone(), bridge.connect()));
        let node2 = Arc::new(SignNode::new(contexts[1].clone(), bridge.connect()));

        let (request_listener, state) = SharedListener::new();
        node2.set_request_listener(Box::new(request_listener));

        // Start message loops
        let n1 = node1.clone();
        let n2 = node2.clone();

        tokio::spawn(async move { n1.message_loop().await });
        tokio::spawn(async move { n2.message_loop().await });

        // Create a listener for node1 to capture the result
        let (res_listener, res_state) = SharedListener::new();

        // Request signature
        let msg = "Hello World".to_string();
        node1
            .request_sign_string(msg.clone(), Box::new(res_listener))
            .await
            .unwrap();

        // Wait for node2 to receive
        let start = std::time::Instant::now();
        while !state.accept_signal.load(Ordering::SeqCst) {
            if start.elapsed() > Duration::from_secs(1) {
                panic!("Timeout waiting for request");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Accept request on node2
        let req = state.received_req.lock().unwrap().take().unwrap();
        let (res_listener_2, _res_state_2) = SharedListener::new();
        node2
            .accept_request(req, Box::new(res_listener_2))
            .await
            .unwrap();

        // Wait for signature
        let start = std::time::Instant::now();
        while !res_state.sig_signal.load(Ordering::SeqCst) {
            if start.elapsed() > Duration::from_secs(5) {
                panic!("Timeout waiting for signature");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let sig = res_state.received_sig.lock().unwrap().take().unwrap();
        // Verify signature
        let group_vk = contexts[0].group_vk();
        group_vk.verify(msg.as_bytes(), &sig).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_3_party_sign() {
        // Use threshold 3 (3, 3)
        let contexts = gen_local_data_async(3, 3).await;
        let bridge = InMemoryBridge::new();

        let node1 = Arc::new(SignNode::new(contexts[0].clone(), bridge.connect()));
        let node2 = Arc::new(SignNode::new(contexts[1].clone(), bridge.connect()));
        let node3 = Arc::new(SignNode::new(contexts[2].clone(), bridge.connect()));

        let (request_listener2, state2) = SharedListener::new();
        node2.set_request_listener(Box::new(request_listener2));

        let (request_listener3, state3) = SharedListener::new();
        node3.set_request_listener(Box::new(request_listener3));

        // Start message loops
        let n1 = node1.clone();
        let n2 = node2.clone();
        let n3 = node3.clone();

        tokio::spawn(async move { n1.message_loop().await });
        tokio::spawn(async move { n2.message_loop().await });
        tokio::spawn(async move { n3.message_loop().await });

        // Create listener for node1 result
        let (res_listener, res_state) = SharedListener::new();

        // Request signature
        let msg = "Hello World 3".to_string();
        node1
            .request_sign_string(msg.clone(), Box::new(res_listener))
            .await
            .unwrap();

        // Wait for nodes to receive
        let start = std::time::Instant::now();
        while !state2.accept_signal.load(Ordering::SeqCst)
            || !state3.accept_signal.load(Ordering::SeqCst)
        {
            if start.elapsed() > Duration::from_secs(1) {
                panic!("Timeout waiting for request");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Accept request on other nodes
        let req2 = state2.received_req.lock().unwrap().take().unwrap();
        let (res_listener_2, _res_state_2) = SharedListener::new();
        node2
            .accept_request(req2, Box::new(res_listener_2))
            .await
            .unwrap();

        let req3 = state3.received_req.lock().unwrap().take().unwrap();
        let (res_listener_3, _res_state_3) = SharedListener::new();
        node3
            .accept_request(req3, Box::new(res_listener_3))
            .await
            .unwrap();

        // Wait for signature
        let start = std::time::Instant::now();
        while !res_state.sig_signal.load(Ordering::SeqCst) {
            if start.elapsed() > Duration::from_secs(5) {
                panic!("Timeout waiting for signature");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let sig = res_state.received_sig.lock().unwrap().take().unwrap();
        // Verify signature
        let group_vk = contexts[0].group_vk();
        group_vk.verify(msg.as_bytes(), &sig).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sim_join_invalid_hash() {
        let contexts = gen_local_data_async(2, 2).await;
        let bridge = InMemoryBridge::new();
        // Start sniffer early to ensure it subscribes
        let sniffer = bridge.connect();

        // Connect node1
        let node1 = Arc::new(SignNode::new(contexts[0].clone(), bridge.connect()));

        // Setup listener
        let (request_listener, _state) = SharedListener::new();
        node1.set_request_listener(Box::new(request_listener));

        // Start request
        let (res_listener, _res_state) = SharedListener::new();
        let msg = "test_sim_join_invalid_hash".to_string();
        node1
            .request_sign_string(msg.clone(), Box::new(res_listener))
            .await
            .unwrap();

        // Check if sniffer gets it
        let sent_bytes = timeout(Duration::from_secs(1), sniffer.receive()).await;
        if sent_bytes.is_err() {
            panic!("Sniffer timed out waiting for request");
        }
        let sent_bytes = sent_bytes.unwrap().unwrap();
        let og_req = SignRequest::try_from(sent_bytes.as_slice()).unwrap();

        let mut hash = og_req.hash;
        hash[0] = hash[0].wrapping_add(1);
        let bad_req = SignRequest::new(
            &og_req.instance,
            SignRequestType::Join,
            hash,
            contexts[1].my_vk(),
            &contexts[1].sk,
        );

        sniffer.send(bad_req.to_bytes()).await.unwrap();

        // Node1 processing
        let res = node1.process_next_msg().await;
        assert!(res.is_err());
        // GeneralError::InvalidInput formats as "Invalid input: {}"
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Message hash mismatch"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sim_join_unknown_session() {
        let contexts = gen_local_data_async(2, 2).await;
        let bridge = InMemoryBridge::new();
        let node1 = Arc::new(SignNode::new(contexts[0].clone(), bridge.connect()));

        // Setup listener
        let (request_listener, _state) = SharedListener::new();
        node1.set_request_listener(Box::new(request_listener));

        // Unknown instance ID
        let instance = InstanceId::from_entropy();
        let msg_hash = [0u8; 32];

        let req = SignRequest::new(
            &instance,
            SignRequestType::Join,
            msg_hash,
            contexts[1].my_vk(),
            &contexts[1].sk,
        );

        let sniffer = bridge.connect();
        sniffer.send(req.to_bytes()).await.unwrap();

        // process_next_msg should return Ok(()) but do nothing (not for us)
        let res = node1.process_next_msg().await;
        assert!(res.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sim_start_unknown_session() {
        let contexts = gen_local_data_async(2, 2).await;
        let bridge = InMemoryBridge::new();
        let node1 = Arc::new(SignNode::new(contexts[0].clone(), bridge.connect()));

        let msg_hash = [0u8; 32];
        let instance = InstanceId::from_entropy();

        // Create start request (needs > 1 sigs for Start type check to pass)
        let mut start_req = SignRequest::empty(&instance, SignRequestType::Start, msg_hash);
        start_req.sign(contexts[0].my_vk(), &contexts[0].sk);
        start_req.sign(contexts[1].my_vk(), &contexts[1].sk);

        let sniffer = bridge.connect();
        sniffer.send(start_req.to_bytes()).await.unwrap();

        // This should return Ok(None) because instance is unknown, so it just ignores it.
        // It consumes the message and returns Ok.
        let res = timeout(Duration::from_secs(1), node1.process_next_msg()).await;
        assert!(res.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sim_start_not_enough_parties() {
        // Threshold 3, but we only provide 2 signatures in the Start message.
        let contexts = gen_local_data_async(3, 3).await;
        let bridge = InMemoryBridge::new();
        let node1 = Arc::new(SignNode::new(contexts[0].clone(), bridge.connect()));

        // Setup dummy request content
        let instance = InstanceId::from_entropy();

        // Inject an accepted request so receive_start proceeds to check signatures
        let req_bytes = vec![1, 2, 3];
        let req = Arc::new(SignRequest::for_message_bytes(
            &instance,
            req_bytes,
            contexts[0].my_vk(),
            &contexts[0].sk,
        ));

        // Have to manually inject request.
        node1
            .incoming_reqs
            .lock()
            .unwrap()
            .insert(req.instance, req.clone());
        let (res_listener, _res_state) = SharedListener::new();
        node1
            .accept_request(req.clone(), Box::new(res_listener))
            .await
            .unwrap();

        // Now create Start request with only 2 signatures (threshold 3)
        let mut start_req = SignRequest::empty(&instance, SignRequestType::Start, req.hash);
        start_req.sign(contexts[0].my_vk(), &contexts[0].sk);
        start_req.sign(contexts[1].my_vk(), &contexts[1].sk);

        let sniffer = bridge.connect();
        sniffer.send(start_req.to_bytes()).await.unwrap();

        let res = node1.process_next_msg().await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.to_string().contains("Not enough signatures"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sim_req_then_start_then_accept() {
        let contexts = gen_local_data_async(2, 2).await;
        let bridge = InMemoryBridge::new();
        // Connect node0 (us) and node1 (them)
        let node1 = Arc::new(SignNode::new(contexts[0].clone(), bridge.connect()));
        // Note: contexts[0] is us, contexts[1] is them.

        let (request_listener, state) = SharedListener::new();
        node1.set_request_listener(Box::new(request_listener));

        // 1. Receive Request from Node 1
        let instance = InstanceId::from_entropy();
        let msg = "test_sim_req_then_start_then_accept";
        let req =
            SignRequest::for_message_string(&instance, &msg, contexts[1].my_vk(), &contexts[1].sk);

        let sniffer = bridge.connect();
        sniffer.send(req.to_bytes()).await.unwrap();

        // Node1 processes request
        // Wait for it to be processed
        let res = node1.process_next_msg().await;
        assert!(res.is_ok());

        // Check listener got it
        {
            let lock = state.received_req.lock().unwrap();
            assert!(lock.is_some());
        }

        // 2. Receive Start message (from Node 1)
        // Hash of the message to sign
        let mut start_req = SignRequest::empty(&instance, SignRequestType::Start, req.hash);
        start_req.sign(contexts[0].my_vk(), &contexts[0].sk);
        start_req.sign(contexts[1].my_vk(), &contexts[1].sk);
        sniffer.send(start_req.to_bytes()).await.unwrap();

        // Node1 processes Start
        // receive_start will look for request in accepted_reqs -> not there.
        // look in incoming_reqs -> finds it, removes it, returns Ok(None).
        // It consumes the message and returns Ok.
        let res = timeout(Duration::from_secs(1), node1.process_next_msg()).await;
        assert!(res.is_ok());

        // 3. User tries to accept
        // The request we got from listener
        let req_arc = state.received_req.lock().unwrap().take().unwrap();
        let (res_listener, _res_state) = SharedListener::new();
        let res = node1.accept_request(req_arc, Box::new(res_listener)).await;

        // Should fail because request was removed from incoming_reqs
        let err = res.unwrap_err();
        assert!(err.to_string().contains("No such request"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sim_accept_unknown_instance() {
        let contexts = gen_local_data_async(2, 2).await;
        let bridge = InMemoryBridge::new();
        let node1 = Arc::new(SignNode::new(contexts[0].clone(), bridge.connect()));

        let instance = InstanceId::from_entropy();
        let req = SignRequest::for_message_string(
            &instance,
            "test",
            contexts[0].my_vk(),
            &contexts[0].sk,
        );

        let (res_listener, _res_state) = SharedListener::new();
        let res = node1
            .accept_request(Arc::new(req), Box::new(res_listener))
            .await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("No such request"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sim_accept_wrong_hash() {
        let contexts = gen_local_data_async(2, 2).await;
        let bridge = InMemoryBridge::new();
        let node1 = Arc::new(SignNode::new(contexts[0].clone(), bridge.connect()));

        let (request_listener, state) = SharedListener::new();
        node1.set_request_listener(Box::new(request_listener));

        // Receive valid request
        let instance = InstanceId::from_entropy();
        let req = SignRequest::for_message_string(
            &instance,
            "test_sim_accept_wrong_hash",
            contexts[0].my_vk(),
            &contexts[0].sk,
        );

        let sniffer = bridge.connect();
        sniffer.send(req.to_bytes()).await.unwrap();
        node1.process_next_msg().await.unwrap();

        // Wait for listener to get it
        while state.received_req.lock().unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Create a different request with same instance but DIFFERENT content
        let bad_req = SignRequest::for_message_string(
            &instance,
            "modified content",
            contexts[0].my_vk(),
            &contexts[0].sk,
        );

        let (res_listener, _res_state) = SharedListener::new();
        let res = node1
            .accept_request(Arc::new(bad_req), Box::new(res_listener))
            .await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Request mismatch"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_cancel_incoming_request() {
        let contexts = gen_local_data_async(2, 2).await;
        let bridge = InMemoryBridge::new();
        let node1 = Arc::new(SignNode::new(contexts[0].clone(), bridge.connect()));
        let node2 = Arc::new(SignNode::new(contexts[1].clone(), bridge.connect()));

        let (request_listener, state2) = SharedListener::new();
        node2.set_request_listener(Box::new(request_listener));

        let n1 = node1.clone();
        let n2 = node2.clone();
        tokio::spawn(async move { n1.message_loop().await });
        tokio::spawn(async move { n2.message_loop().await });

        let (res_listener, _res_state1) = SharedListener::new();
        let msg = "Cancel Incoming".to_string();
        let req = node1
            .request_sign_string(msg.clone(), Box::new(res_listener))
            .await
            .unwrap();

        // Wait for node2 to receive
        let start = std::time::Instant::now();
        while !state2.accept_signal.load(Ordering::SeqCst) {
            if start.elapsed() > Duration::from_secs(1) {
                panic!("Timeout waiting for request");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Now cancel from node1
        node1.cancel_request(&req).await.unwrap();

        // Wait for node2 to process cancel
        let start = std::time::Instant::now();
        while !state2.cancelled_signal.load(Ordering::SeqCst) {
            if start.elapsed() > Duration::from_secs(1) {
                panic!("Timeout waiting for cancel");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_cancel_accepted_request() {
        let contexts = gen_local_data_async(3, 3).await; // Use threshold 3 so it doesn't start
        let bridge = InMemoryBridge::new();
        let node1 = Arc::new(SignNode::new(contexts[0].clone(), bridge.connect()));
        let node2 = Arc::new(SignNode::new(contexts[1].clone(), bridge.connect()));

        let (request_listener, state2) = SharedListener::new();
        node2.set_request_listener(Box::new(request_listener));

        let n1 = node1.clone();
        let n2 = node2.clone();
        tokio::spawn(async move { n1.message_loop().await });
        tokio::spawn(async move { n2.message_loop().await });

        let (res_listener, _res_state1) = SharedListener::new();
        let msg = "Cancel Accepted".to_string();
        let req = node1
            .request_sign_string(msg.clone(), Box::new(res_listener))
            .await
            .unwrap();

        // Wait for node2 to receive
        let start = std::time::Instant::now();
        while !state2.accept_signal.load(Ordering::SeqCst) {
            if start.elapsed() > Duration::from_secs(1) {
                panic!("Timeout waiting for request");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let state2_req = state2.received_req.lock().unwrap().take().unwrap();
        let (res_listener2, state2_res_listener) = SharedListener::new();
        node2
            .accept_request(state2_req, Box::new(res_listener2))
            .await
            .unwrap();

        // Give it a tiny bit of time to propagate the Join message
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Cancel from node1 (the originator)
        node1.cancel_request(&req).await.unwrap();

        // Wait for node2 to process cancel (should fire sign_cancelled on result listener)
        let start = std::time::Instant::now();
        while !state2_res_listener.cancelled_signal.load(Ordering::SeqCst) {
            if start.elapsed() > Duration::from_secs(1) {
                panic!("Timeout waiting for cancel on accepted request");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_cancel_participation() {
        let contexts = gen_local_data_async(3, 3).await; // Use threshold 3 so it doesn't start
        let bridge = InMemoryBridge::new();
        let node1 = Arc::new(SignNode::new(contexts[0].clone(), bridge.connect()));
        let node2 = Arc::new(SignNode::new(contexts[1].clone(), bridge.connect()));

        let (request_listener, state2) = SharedListener::new();
        node2.set_request_listener(Box::new(request_listener));

        let n1 = node1.clone();
        let n2 = node2.clone();
        tokio::spawn(async move { n1.message_loop().await });
        tokio::spawn(async move { n2.message_loop().await });

        let (res_listener_1, state1_res_listener) = SharedListener::new();
        let msg = "Cancel Participation".to_string();
        let _ = node1
            .request_sign_string(msg.clone(), Box::new(res_listener_1))
            .await
            .unwrap();

        // Wait for node2 to receive
        while !state2.accept_signal.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let state2_req = state2.received_req.lock().unwrap().take().unwrap();
        let (res_listener_2, _state2_res_listener) = SharedListener::new();
        node2
            .accept_request(state2_req.clone(), Box::new(res_listener_2))
            .await
            .unwrap();

        // It accepted, Node1 should receive a Join and devices_changed might fire?
        // Wait actually, does it fire sign_devices_changed?
        // Let's cancel from Node2 (participant)
        node2.cancel_request(&state2_req).await.unwrap();

        // Wait for node1 to process cancel (should fire sign_devices_changed on result listener)
        let start = std::time::Instant::now();
        while !state1_res_listener
            .devices_changed_signal
            .load(Ordering::SeqCst)
        {
            if start.elapsed() > Duration::from_secs(1) {
                panic!("Timeout waiting for participant cancel on originator");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
