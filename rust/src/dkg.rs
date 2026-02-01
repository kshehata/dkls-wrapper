use std::borrow::Cow;
use std::sync::{Arc, RwLock};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use signature::Signer;

use tokio::sync::Notify;

use sl_dkls23::keygen::run as keygen_run;
use sl_dkls23::setup::keygen::SetupMessage as KeygenSetup;

use crate::error::GeneralError;
use crate::net::{create_network_relay, NetworkInterface};
use crate::types::*;

/*****************************************************************************
 * DKG Node.
 * This is the interface to the rest of the world for setting up a DKG session.
 *****************************************************************************/

#[derive(uniffi::Object)]
pub struct DKGNode {
    // Need interior mutability for state,
    // Option so that we can replace it dynamically.
    state: RwLock<Option<Box<dyn DKGInternalState>>>,
    listeners: RwLock<Vec<Box<dyn DKGStateChangeListener>>>,
    setup_listeners: RwLock<Vec<Box<dyn DKGSetupChangeListener>>>,
    context: DKGContext,
    setup_if: Arc<dyn NetworkInterface>,
    dkg_if: Arc<dyn NetworkInterface>,
    await_msg_kick: Notify,
}

#[uniffi::export(callback_interface)]
pub trait DKGSetupChangeListener: Send + Sync {
    fn on_setup_changed(&self, parties: Vec<Arc<DeviceInfo>>, my_id: u8);
}

#[uniffi::export(callback_interface)]
pub trait DKGStateChangeListener: Send + Sync {
    fn on_state_changed(&self, old_state: DKGState, new_state: DKGState);
}

#[uniffi::export]
impl DKGNode {
    #[uniffi::constructor]
    pub fn new(
        name: &str,
        instance: &InstanceId,
        threshold: u8,
        setup_if: Arc<dyn NetworkInterface>,
        dkg_if: Arc<dyn NetworkInterface>,
    ) -> Self {
        let context = DKGContext::new(
            instance.clone(),
            threshold,
            name.to_string(),
            NodeSecretKey::from_entropy(),
        );
        let parties = Arc::new(vec![context.dev.clone()]);
        Self {
            state: RwLock::new(Some(DKGReadyState::new(parties, 0, threshold))),
            listeners: RwLock::new(Vec::new()),
            setup_listeners: RwLock::new(Vec::new()),
            context,
            setup_if,
            dkg_if,
            await_msg_kick: Notify::new(),
        }
    }

    #[uniffi::constructor]
    pub fn from_qr(
        name: &str,
        qr_data: Arc<QRData>,
        setup_if: Arc<dyn NetworkInterface>,
        dkg_if: Arc<dyn NetworkInterface>,
    ) -> Self {
        let context = DKGContext::new(
            qr_data.instance.clone(),
            qr_data.threshold,
            name.to_string(),
            NodeSecretKey::from_entropy(),
        );
        Self {
            state: RwLock::new(Some(DKGWaitForNetState::new(qr_data))),
            listeners: RwLock::new(Vec::new()),
            setup_listeners: RwLock::new(Vec::new()),
            context,
            setup_if,
            dkg_if,
            await_msg_kick: Notify::new(),
        }
    }

    #[uniffi::constructor]
    pub fn try_from_qr_bytes(
        name: &str,
        qr_bytes: &Vec<u8>,
        setup_if: Arc<dyn NetworkInterface>,
        dkg_if: Arc<dyn NetworkInterface>,
    ) -> Result<Self, GeneralError> {
        let qr_data = QRData::try_from(qr_bytes.as_slice())?;
        Ok(Self::from_qr(name, Arc::new(qr_data), setup_if, dkg_if))
    }

    pub fn get_name(&self) -> String {
        self.context.dev.friendly_name.clone()
    }

    pub fn get_qr_bytes(&self) -> Result<Vec<u8>, GeneralError> {
        Ok(self.get_qr()?.to_bytes())
    }

    pub fn get_state(&self) -> DKGState {
        self.state.read().unwrap().as_ref().unwrap().get_state()
    }

    pub fn add_state_change_listener(&self, listener: Box<dyn DKGStateChangeListener>) {
        self.listeners.write().unwrap().push(listener);
    }

    pub fn add_setup_change_listener(&self, listener: Box<dyn DKGSetupChangeListener>) {
        // Also notify the listener immediately with the current setup if available.
        // TODO: should probably refactor both of these into one call.
        if let (Ok(parties), Ok(my_id)) = {
            let guard = self.state.read().unwrap();
            let state = guard.as_ref().unwrap();
            let parties = state.get_party_list();
            let my_id = state.my_party_id();
            (parties, my_id)
        } {
            let parties = parties
                .iter()
                .map(|p| Arc::new(p.clone()))
                .collect::<Vec<_>>();
            listener.on_setup_changed(parties, my_id);
        }
        self.setup_listeners.write().unwrap().push(listener);
    }

    pub fn receive_qr_bytes(&self, qr_bytes: &Vec<u8>) -> Result<(), GeneralError> {
        let qr_data = QRData::try_from(qr_bytes.as_slice())?;
        self.receive_qr(qr_data)
    }

    pub fn get_result(&self) -> Result<Keyshare, GeneralError> {
        self.state.read().unwrap().as_ref().unwrap().get_result()
    }

    // User pressed the "go" button.
    pub async fn start_dkg(&self) -> Result<(), GeneralError> {
        let bytes_to_send = self.do_state_fn(|state| state.start_dkg(&self.context))?;
        if !bytes_to_send.is_empty() {
            self.setup_if.send(bytes_to_send).await?;
        }
        self.await_msg_kick.notify_waiters();
        Ok(())
    }

    // Call this on the thread to receive messages.
    // Recall to retry after errors.
    pub async fn message_loop(&self) -> Result<(), GeneralError> {
        // HACK: Need to send the initial setup message if we're the first one.

        // println!(
        //     "{:?} Message loop start in state {:?}",
        //     self.context.friendly_name,
        //     self.get_state()
        // );
        if self.get_state() == DKGState::WaitForParties
            || self.get_state() == DKGState::WaitForSetup
        {
            // println!("{:?} Sending setup message", self.context.friendly_name);
            let setup_bytes = self
                .state
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .get_bytes_to_send(&self.context)
                .unwrap();
            self.setup_if.send(setup_bytes).await?;
        }

        while self.get_state() != DKGState::Running {
            // If message received cancelled then fall through.
            match self.process_next_setup_msg().await {
                Err(GeneralError::Cancelled) => break,
                res => res?,
            }
        }
        // Start the actual DKG
        let (parties, party_id) = {
            let guard = self.state.read().unwrap();
            let state = guard.as_ref().unwrap();
            if state.get_state() != DKGState::Running {
                // println!("{:?} Not Running!?!", self.context.friendly_name);
                return Err(GeneralError::InvalidState(
                    "Calculated state is running but stored state is not?".to_string(),
                ));
            }
            (
                state.get_party_list().unwrap(),
                state.my_party_id().unwrap(),
            )
        };

        // println!("{:?} Starting DKG", self.context.friendly_name);
        let res = self.do_dkg_internal(parties.clone(), party_id).await;
        // println!("{:?} DKG Complete?", self.context.friendly_name);

        let _ = self.do_state_fn(|_| (DKGFinishedState::new(parties, res, party_id), Ok(false)));
        Ok(())
    }
}

impl DKGNode {
    pub fn get_qr(&self) -> Result<QRData, GeneralError> {
        let qr = QRData {
            instance: self.context.instance.clone(),
            threshold: self.context.threshold,
            party_id: self.state.read().unwrap().as_ref().unwrap().my_party_id()?,
            vk: self.context.dev.vk.clone(),
        };
        Ok(qr)
    }

    pub fn receive_qr(&self, qr: QRData) -> Result<(), GeneralError> {
        let (maybe_party_list, my_id) = {
            let mut guard = self.state.write().unwrap();
            let state = guard.as_mut().unwrap();
            state.scan_qr(qr)?;
            (state.get_party_list().ok(), state.my_party_id().ok())
        };
        if let (Some(party_list), Some(my_id)) = (maybe_party_list, my_id) {
            self.notify_setup_listeners(party_list, my_id);
        }
        Ok(())
    }

    // Shortcut to receive and parse a setup message.
    async fn get_next_msg_interruptable(&self) -> Result<SignedDKGSetupMessage<'_>, GeneralError> {
        let receive_fut = self.setup_if.receive();
        let stop_fut = self.await_msg_kick.notified();

        let data = tokio::select! {
            res = receive_fut => res?,
            _ = stop_fut => return Err(GeneralError::Cancelled),
        };
        let msg = SignedDKGSetupMessage::try_from(data.as_slice())?;
        // Don't bother even checking signatures if instance or params don't match.
        if &self.context.instance != msg.setup.instance.as_ref()
            || self.context.threshold != msg.setup.threshold
        {
            return Err(GeneralError::InvalidSetupMessage);
        }
        msg.verify()?;
        Ok(msg)
    }

    async fn process_next_setup_msg(&self) -> Result<(), GeneralError> {
        // println!("{:?} Waiting for setup message", self.context.friendly_name);
        let setup_msg = self.get_next_msg_interruptable().await?;
        // println!("{:?} Received setup message", self.context.friendly_name);
        let bytes_to_send =
            self.do_state_fn(|state| state.receive_setup_msg(&self.context, setup_msg))?;
        if !bytes_to_send.is_empty() {
            self.setup_if.send(bytes_to_send).await?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn test_handle_setup_msg(
        &self,
        setup_msg: SignedDKGSetupMessage,
    ) -> Result<Vec<u8>, GeneralError> {
        self.do_state_fn(|state| state.receive_setup_msg(&self.context, setup_msg))
    }

    async fn do_dkg_internal(
        &self,
        parties: Arc<PartyList>,
        party_id: u8,
    ) -> Result<Keyshare, GeneralError> {
        // TODO: should maybe put a Mutex here to make sure it never runs twice?

        let vkrefs: Vec<&NodeVerifyingKey> = parties.iter().map(|dev| &dev.vk).collect();
        let ranks = vec![0u8; parties.len() as usize];
        let setup_msg = KeygenSetup::new(
            self.context.instance.into(),
            &self.context.sk,
            party_id.into(),
            vkrefs,
            &ranks,
            self.context.threshold.into(),
        );

        let mut rng = ChaCha20Rng::from_entropy();

        // println!("{:?} keygen_run", self.context.friendly_name);
        let result = keygen_run(
            setup_msg,
            rng.gen(),
            create_network_relay(self.dkg_if.clone()),
        )
        .await
        .map(|k| Keyshare(Arc::new(k)))
        .map_err(GeneralError::from);
        // println!("{:?} keygen_run done", self.context.friendly_name);

        result
    }

    // helper to do all the complicated magic of taking the state
    // out of the guard, running a function, putting it back,
    // and notifying listeners.
    fn do_state_fn<F>(&self, f: F) -> Result<Vec<u8>, GeneralError>
    where
        F: FnOnce(
            Box<dyn DKGInternalState>,
        ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>),
    {
        let (old_state_enum, new_state_enum, res, old_parties, new_parties, my_id) = {
            let mut guard = self.state.write().unwrap();
            let current_state = guard.take().unwrap();
            let old_state_enum = current_state.get_state();
            let old_parties = current_state.get_party_list().ok();
            let (new_state, res) = f(current_state);
            let new_state_enum = new_state.get_state();
            let new_parties = new_state.get_party_list().ok();
            let my_id = new_state.my_party_id().ok();

            // If the state_fn indicated to send an update to the network,
            // get the signed state message and serialize it before doing
            // anything else. If not, avoid doing this work.
            let res = match res {
                Ok(true) => new_state.get_bytes_to_send(&self.context),
                Ok(false) => Ok(vec![]),
                Err(e) => Err(e),
            };
            *guard = Some(new_state);
            (
                old_state_enum,
                new_state_enum,
                res,
                old_parties,
                new_parties,
                my_id,
            )
        };

        // Update listeners of changes.
        self.notify_listeners(old_state_enum, new_state_enum);
        if let (Some(parties), Some(my_id)) = (new_parties, my_id) {
            match old_parties {
                Some(s2) if s2 == parties => (),
                _ => self.notify_setup_listeners(parties, my_id),
            }
        }

        res
    }

    fn notify_listeners(&self, old_state: DKGState, new_state: DKGState) {
        if old_state == new_state {
            return;
        }
        let listeners = self.listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.on_state_changed(old_state, new_state);
        }
    }

    fn notify_setup_listeners(&self, parties: Arc<PartyList>, my_id: u8) {
        // Have to convert to Vec<Arc<DeviceInfo>> for UniFFI
        let parties = parties
            .iter()
            .map(|p| Arc::new(p.clone()))
            .collect::<Vec<_>>();
        let listeners = self.setup_listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.on_setup_changed(parties.clone(), my_id);
        }
    }
}

/*****************************************************************************
 * Messages
 *****************************************************************************/

// QR Code data for setting up DKG.
// TODO: hash of setup or signature ?
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Object)]
pub struct QRData {
    // TODO: should make all of these read-only.
    pub instance: InstanceId,
    pub threshold: u8,
    pub party_id: u8,
    pub vk: NodeVerifyingKey,
}

// TODO: there has to be a better way than repeating this boilerplate for every message.
impl TryFrom<&[u8]> for QRData {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        postcard::from_bytes(value).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }
}

impl TryFrom<&str> for QRData {
    type Error = GeneralError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        serde_json::from_str(value).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }
}

#[uniffi::export]
impl QRData {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: &[u8]) -> Result<Arc<QRData>, GeneralError> {
        Ok(Arc::new(Self::try_from(bytes)?))
    }

    #[uniffi::constructor]
    pub fn from_string(s: &str) -> Result<Arc<QRData>, GeneralError> {
        Ok(Arc::new(Self::try_from(s)?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn get_instance(&self) -> InstanceId {
        self.instance
    }

    pub fn get_party_id(&self) -> u8 {
        self.party_id
    }

    pub fn get_vk(&self) -> NodeVerifyingKey {
        self.vk.clone()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
enum DKGSetupSubMessage<'a> {
    Join(Cow<'a, DeviceInfo>),
    Confirm(Arc<PartyList>),
    Start(Arc<PartyList>),
}

type PartyList = Vec<DeviceInfo>;

fn verify_qr(list: &mut PartyList, qr: &QRData) -> Result<(), GeneralError> {
    if list.len() <= qr.party_id as usize || list[qr.party_id as usize].vk != qr.vk {
        return Err(GeneralError::InvalidInput(
            "Setup and QR mismatch".to_string(),
        ));
    }
    list[qr.party_id as usize].verified = true;

    Ok(())
}

fn is_prefix_of(list: &PartyList, new_list: &PartyList) -> bool {
    // Make sure there are at least as many parties.
    if new_list.len() < list.len() {
        return false;
    }

    // Check that VKs and friendly names are the same.
    list.iter()
        .zip(new_list.iter())
        .all(|(a, b)| (a.vk == b.vk) && (a.friendly_name == b.friendly_name))
}

fn matches(list: &PartyList, new_list: &PartyList) -> bool {
    list.len() == new_list.len() && is_prefix_of(list, new_list)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct DKGSetupMessage<'a> {
    instance: Cow<'a, InstanceId>,
    threshold: u8,
    message: DKGSetupSubMessage<'a>,
}

impl<'a> TryFrom<&[u8]> for DKGSetupMessage<'a> {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        postcard::from_bytes(value).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }
}

impl<'a> TryFrom<&str> for DKGSetupMessage<'a> {
    type Error = GeneralError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        serde_json::from_str(value).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }
}

impl<'a> DKGSetupMessage<'a> {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn get_vk(&self, party_id: u8) -> Result<&NodeVerifyingKey, GeneralError> {
        match &self.message {
            DKGSetupSubMessage::Join(device) => Ok(&device.vk),
            DKGSetupSubMessage::Confirm(parties) | DKGSetupSubMessage::Start(parties) => parties
                .get(party_id as usize)
                .map(|p| &p.vk)
                .ok_or(GeneralError::InvalidInput("Invalid party ID".to_string())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct SignedDKGSetupMessage<'a> {
    setup: DKGSetupMessage<'a>,
    party_id: u8,
    sig: Cow<'a, Signature>,
}

impl<'a> TryFrom<&[u8]> for SignedDKGSetupMessage<'a> {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        postcard::from_bytes(value).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }
}

impl<'a> TryFrom<&str> for SignedDKGSetupMessage<'a> {
    type Error = GeneralError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        serde_json::from_str(value).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }
}

impl<'a> SignedDKGSetupMessage<'a> {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn from_sig(setup: DKGSetupMessage<'a>, party_id: u8, sig: Cow<'a, Signature>) -> Self {
        Self {
            setup,
            party_id,
            sig,
        }
    }

    pub fn sign(setup: DKGSetupMessage<'a>, party_id: u8, sk: &NodeSecretKey) -> Self {
        let sig = Signature(sk.try_sign(setup.to_bytes().as_ref()).unwrap());
        Self {
            setup,
            party_id,
            sig: Cow::Owned(sig),
        }
    }

    pub fn gen_sig(setup: &DKGSetupMessage, sk: &NodeSecretKey) -> Signature {
        Signature(sk.try_sign(setup.to_bytes().as_ref()).unwrap())
    }

    pub fn gen_confirm_sig(parties: Arc<PartyList>, ctx: &DKGContext) -> Signature {
        Self::gen_sig(
            &DKGSetupMessage {
                instance: Cow::Borrowed(&ctx.instance),
                threshold: ctx.threshold,
                message: DKGSetupSubMessage::Confirm(parties),
            },
            &ctx.sk,
        )
    }

    pub fn verify(&self) -> Result<(), GeneralError> {
        Self::verify_for_setup(&self.setup, self.party_id as usize, &self.sig)
    }

    // Helper to verify a signature without constructing a SignedDKGSetupMessage.
    pub fn verify_for_setup(
        setup: &DKGSetupMessage,
        party_id: usize,
        sig: &Signature,
    ) -> Result<(), GeneralError> {
        let vk = setup.get_vk(party_id as u8)?;
        vk.verify(setup.to_bytes().as_ref(), sig)
    }
}

/*****************************************************************************
 * DKG State Machine
 *****************************************************************************/

#[derive(Debug, PartialEq, Clone, Copy, uniffi::Enum)]
pub enum DKGState {
    WaitForSetup,
    WaitForSigs,
    WaitForParties,
    Ready,
    Running,
    Finished,
}

struct DKGContext {
    instance: InstanceId,
    threshold: u8,
    dev: DeviceInfo,
    sk: NodeSecretKey,
}

impl DKGContext {
    fn new(instance: InstanceId, threshold: u8, friendly_name: String, sk: NodeSecretKey) -> Self {
        let dev = DeviceInfo::for_sk(friendly_name, &sk);
        Self {
            instance,
            threshold,
            dev,
            sk,
        }
    }
}

trait DKGInternalState: Send + Sync + 'static {
    fn get_state(&self) -> DKGState;

    fn my_party_id(&self) -> Result<u8, GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot get party ID in current state.".to_string(),
        ))
    }

    fn get_party_list(&self) -> Result<Arc<PartyList>, GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot get party list in current state.".to_string(),
        ))
    }

    // Used for getting setup message to send to the network.
    fn get_bytes_to_send(&self, _context: &DKGContext) -> Result<Vec<u8>, GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot get setup handle in current state.".to_string(),
        ))
    }

    fn scan_qr(&mut self, _: QRData) -> Result<(), GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot scan QR in current state.".to_string(),
        ))
    }

    // Received a setup message from the network. Handle it,
    // and return the new state along with a result.
    // Must always have a new state since this consumes the old state.
    // The result is "true" to indicate that we should send an
    // update message to the network.
    fn receive_setup_msg(
        self: Box<Self>,
        context: &DKGContext,
        setup_msg: SignedDKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>);

    // User wants to trigger the DKG to start (not from the net!).
    // Returns true if we should send an update message to the network.
    // (which should be any time its successful, this is just to make
    // it consistent with receive_setup_msg.)
    fn start_dkg(
        self: Box<Self>,
        context: &DKGContext,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>);

    fn get_result(&self) -> Result<Keyshare, GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot get result in current state.".to_string(),
        ))
    }
}

/*****************************************************************************
 * Waiting for Network State.
 * In this state, we've gotten an initial QR code and we're waiting for a
 * setup message from the network.
 *****************************************************************************/

struct DKGWaitForNetState {
    qr_data: Arc<QRData>,
}

impl DKGWaitForNetState {
    fn new(qr_data: Arc<QRData>) -> Box<Self> {
        Box::new(Self { qr_data })
    }
}

impl DKGInternalState for DKGWaitForNetState {
    fn get_state(&self) -> DKGState {
        DKGState::WaitForSetup
    }

    fn get_bytes_to_send(&self, context: &DKGContext) -> Result<Vec<u8>, GeneralError> {
        let join_msg = DKGSetupMessage {
            instance: Cow::Borrowed(&context.instance),
            threshold: context.threshold,
            message: DKGSetupSubMessage::Join(Cow::Borrowed(&context.dev)),
        };
        // Join messages use party_id 0 (ignored).
        let msg = SignedDKGSetupMessage::sign(join_msg, 0, &context.sk);
        Ok(msg.to_bytes())
    }

    fn receive_setup_msg(
        self: Box<Self>,
        context: &DKGContext,
        setup_msg: SignedDKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        // Instance ID must match scanned QR.
        if setup_msg.setup.instance.as_ref() != &context.instance {
            return (self, Err(GeneralError::InvalidSetupMessage));
        }

        // Make sure this is confirmation and get details.
        let parties = match setup_msg.setup.message {
            DKGSetupSubMessage::Confirm(parties) => parties,
            _ => return (self, Err(GeneralError::InvalidSetupMessage)),
        };

        // Verify inviter is in parties (sanity check)
        if self.qr_data.party_id as usize >= parties.len()
            || parties[self.qr_data.party_id as usize].vk != self.qr_data.vk
        {
            return (self, Err(GeneralError::InvalidSetupMessage));
        }

        // Find ourselves
        let Some(my_party_id) = parties.iter().position(|p| p.vk == context.dev.vk) else {
            // TODO: pretty sure this is wrong, Gemini.
            // We might receive a confirm message before our join message has been processed.
            // In this case, we just ignore the message and wait for the updated one.
            return (self, Ok(false));
        };

        // This should be impossible: our party ID matches the sender's party ID.
        if my_party_id == setup_msg.party_id as usize {
            return (self, Err(GeneralError::InvalidSetupMessage));
        }

        // If there are only two parties, then we already have all sigs needed.
        let state: Box<dyn DKGInternalState> = if parties.len() == 2 {
            DKGReadyState::new(parties, my_party_id as u8, context.threshold)
        } else {
            // Create the new state with our signature.
            let mut new_state = DKGWaitForSigs::new(parties, my_party_id as u8, context);
            // Add the received signature.
            new_state.add_signature(setup_msg.party_id, setup_msg.sig.into_owned());
            new_state
        };
        (state, Ok(true))
    }

    fn start_dkg(
        self: Box<Self>,
        _context: &DKGContext,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot start from current state.".to_string(),
            )),
        )
    }
}

/*****************************************************************************
 * Wait for Signatures state.
 * In this state, we have proposed a setup and we are waiting for everyone
 * else to sign it.
 *****************************************************************************/

struct DKGWaitForSigs {
    parties: Arc<PartyList>,
    party_id: u8,
    signatures: Vec<Option<Signature>>,
}

impl DKGWaitForSigs {
    fn new(parties: Arc<PartyList>, party_id: u8, ctx: &DKGContext) -> Box<Self> {
        let num_parties = parties.len();
        let my_sig = SignedDKGSetupMessage::gen_confirm_sig(parties.clone(), ctx);
        let mut state = Box::new(Self {
            parties,
            party_id,
            signatures: vec![None; num_parties as usize],
        });
        // Sign the proposal ourselves.
        state.add_signature(party_id, my_sig);
        state
    }

    fn add_signature(&mut self, party_id: u8, sig: Signature) {
        if (party_id as usize) < self.signatures.len() {
            self.signatures[party_id as usize] = Some(sig);
        }
    }

    fn has_all_signatures(&self) -> bool {
        self.signatures.iter().all(|s| s.is_some())
    }
}

impl DKGInternalState for DKGWaitForSigs {
    fn get_state(&self) -> DKGState {
        DKGState::WaitForSigs
    }

    fn my_party_id(&self) -> Result<u8, GeneralError> {
        Ok(self.party_id)
    }

    fn get_party_list(&self) -> Result<Arc<PartyList>, GeneralError> {
        Ok(self.parties.clone())
    }

    fn get_bytes_to_send(&self, ctx: &DKGContext) -> Result<Vec<u8>, GeneralError> {
        let setup = DKGSetupMessage {
            instance: Cow::Borrowed(&ctx.instance),
            threshold: ctx.threshold,
            message: DKGSetupSubMessage::Confirm(self.parties.clone()),
        };
        let msg = SignedDKGSetupMessage::from_sig(
            setup,
            self.party_id,
            Cow::Borrowed(self.signatures[self.party_id as usize].as_ref().unwrap()),
        );
        Ok(msg.to_bytes())
    }

    fn scan_qr(&mut self, qr_data: QRData) -> Result<(), GeneralError> {
        verify_qr(Arc::make_mut(&mut self.parties), &qr_data)
    }

    fn receive_setup_msg(
        mut self: Box<Self>,
        ctx: &DKGContext,
        setup_msg: SignedDKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        // Instance and threshold should be checked vs context in DKGNode.

        // Cannot handle joins or start in this state.
        let DKGSetupSubMessage::Confirm(parties) = setup_msg.setup.message else {
            return (self, Err(GeneralError::InvalidSetupMessage));
        };

        // New details must match exactly.
        if !matches(&self.parties, &parties) {
            return (self, Err(GeneralError::InvalidSetupMessage));
        }

        self.add_signature(setup_msg.party_id, setup_msg.sig.into_owned());

        if self.has_all_signatures() {
            let ready = DKGReadyState::new(parties, self.party_id, ctx.threshold);
            (ready, Ok(false))
        } else {
            (self, Ok(false))
        }
    }

    fn start_dkg(
        self: Box<Self>,
        _: &DKGContext,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot start while waiting for signatures.".to_string(),
            )),
        )
    }
}

/*****************************************************************************
 * Ready state.
 * In this state, we have the setup data and we're ready to start the DKG,
 * but we're waiting in case more devices join.
 *****************************************************************************/

struct DKGReadyState {
    parties: Arc<PartyList>,
    party_id: u8,
    threshold: u8,
}

impl DKGReadyState {
    fn new(parties: Arc<PartyList>, party_id: u8, threshold: u8) -> Box<Self> {
        Box::new(Self {
            parties,
            party_id,
            threshold,
        })
    }
}

impl DKGInternalState for DKGReadyState {
    fn get_state(&self) -> DKGState {
        if self.parties.len() < self.threshold.into() {
            DKGState::WaitForParties
        } else {
            DKGState::Ready
        }
    }

    fn my_party_id(&self) -> Result<u8, GeneralError> {
        Ok(self.party_id)
    }

    fn get_party_list(&self) -> Result<Arc<PartyList>, GeneralError> {
        Ok(self.parties.clone())
    }

    fn get_bytes_to_send(&self, ctx: &DKGContext) -> Result<Vec<u8>, GeneralError> {
        let setup = DKGSetupMessage {
            instance: Cow::Borrowed(&ctx.instance),
            threshold: ctx.threshold,
            message: DKGSetupSubMessage::Confirm(self.parties.clone()),
        };
        let msg = SignedDKGSetupMessage::sign(setup, self.party_id, &ctx.sk);
        Ok(msg.to_bytes())
    }

    fn scan_qr(&mut self, qr_data: QRData) -> Result<(), GeneralError> {
        verify_qr(Arc::make_mut(&mut self.parties), &qr_data)
    }

    fn receive_setup_msg(
        mut self: Box<Self>,
        context: &DKGContext,
        setup_msg: SignedDKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        // Instance and threshold should be checked vs context in DKGNode.

        match setup_msg.setup.message {
            DKGSetupSubMessage::Join(device) => {
                // Assume sig is already verified.
                Arc::make_mut(&mut self.parties).push(device.into_owned());
                let state = DKGWaitForSigs::new(self.parties, self.party_id, context);
                (state, Ok(true))
            }

            DKGSetupSubMessage::Confirm(parties) => {
                // Reject if parties somehow differ, since at this point all
                // parties should have been confirmed.
                if !is_prefix_of(&self.parties, &parties) {
                    return (self, Err(GeneralError::InvalidSetupMessage));
                }
                match parties.len() - self.parties.len() {
                    0 => {
                        // Somehow got an extra confirmation message ?
                        return (self, Ok(false));
                    }
                    1 => {
                        // Got a confirmation before the join message.
                        // Just move to the wait for sigs state state.
                        let mut state = DKGWaitForSigs::new(parties, self.party_id, context);
                        state.add_signature(setup_msg.party_id, setup_msg.sig.into_owned());
                        return (state, Ok(true));
                    }
                    _ => {
                        // Differ by more than 1 party, not allowed.
                        return (self, Err(GeneralError::InvalidSetupMessage));
                    }
                }
            }
            DKGSetupSubMessage::Start(new_parties) => {
                // Check details match
                if !matches(&self.parties, &new_parties) {
                    return (self, Err(GeneralError::InvalidSetupMessage));
                }
                if self.parties.len() < context.threshold as usize {
                    return (
                        self,
                        Err(GeneralError::InvalidState("Not enough parties".to_string())),
                    );
                }
                (DKGRunningState::new(self.parties, self.party_id), Ok(false))
            }
        }
    }

    fn start_dkg(
        self: Box<Self>,
        ctx: &DKGContext,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        if self.parties.len() < ctx.threshold.into() {
            (
                self,
                Err(GeneralError::InvalidState(
                    "Not enough parties to start DKG.".to_string(),
                )),
            )
        } else {
            (DKGRunningState::new(self.parties, self.party_id), Ok(true))
        }
    }
}

/*****************************************************************************
 * Running state.
 * DKG is running, can't get any intermediate results.
 *****************************************************************************/

struct DKGRunningState {
    parties: Arc<PartyList>,
    party_id: u8,
}

impl DKGRunningState {
    fn new(parties: Arc<PartyList>, party_id: u8) -> Box<Self> {
        Box::new(Self { parties, party_id })
    }
}

impl DKGInternalState for DKGRunningState {
    fn get_state(&self) -> DKGState {
        DKGState::Running
    }

    fn my_party_id(&self) -> Result<u8, GeneralError> {
        Ok(self.party_id)
    }

    fn get_party_list(&self) -> Result<Arc<PartyList>, GeneralError> {
        Ok(self.parties.clone())
    }

    fn get_bytes_to_send(&self, ctx: &DKGContext) -> Result<Vec<u8>, GeneralError> {
        let setup = DKGSetupMessage {
            instance: Cow::Borrowed(&ctx.instance),
            threshold: ctx.threshold,
            message: DKGSetupSubMessage::Start(self.parties.clone()),
        };
        let msg = SignedDKGSetupMessage::sign(setup, self.party_id, &ctx.sk);
        Ok(msg.to_bytes())
    }

    fn receive_setup_msg(
        self: Box<Self>,
        _context: &DKGContext,
        _setup_msg: SignedDKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot receive setup message in current state.".to_string(),
            )),
        )
    }

    fn start_dkg(
        self: Box<Self>,
        _: &DKGContext,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "DKG already started.".to_string(),
            )),
        )
    }
}

/*****************************************************************************
 * Finished state.
 * Really just provides access to the result and marks the DKG as finished.
 *****************************************************************************/

struct DKGFinishedState {
    parties: Arc<PartyList>,
    result: Result<Keyshare, GeneralError>,
    party_id: u8,
}

impl DKGFinishedState {
    fn new(
        parties: Arc<PartyList>,
        result: Result<Keyshare, GeneralError>,
        party_id: u8,
    ) -> Box<Self> {
        Box::new(Self {
            parties,
            result,
            party_id,
        })
    }
}

impl DKGInternalState for DKGFinishedState {
    fn get_state(&self) -> DKGState {
        DKGState::Finished
    }

    fn get_party_list(&self) -> Result<Arc<PartyList>, GeneralError> {
        Ok(self.parties.clone())
    }

    fn my_party_id(&self) -> Result<u8, GeneralError> {
        Ok(self.party_id)
    }

    fn receive_setup_msg(
        self: Box<Self>,
        _context: &DKGContext,
        _setup_msg: SignedDKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot receive setup message in current state.".to_string(),
            )),
        )
    }

    fn start_dkg(
        self: Box<Self>,
        _: &DKGContext,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot start from current state.".to_string(),
            )),
        )
    }

    fn get_result(&self) -> Result<Keyshare, GeneralError> {
        self.result.clone()
    }
}

/*****************************************************************************
 * Tests
 *****************************************************************************/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::InMemoryBridge;

    use std::time::Duration;
    use tokio::sync::watch;
    use tokio::time::timeout;

    /*****************************************************************************
     * Top Level DKGNode Tests.
     *****************************************************************************/

    fn spawn_node(
        js: &mut tokio::task::JoinSet<()>,
        node: Arc<DKGNode>,
    ) -> tokio::task::AbortHandle {
        js.spawn(async move {
            let res = node.message_loop().await;
            println!("Node {} finished with result: {:?}", node.get_name(), res);
        })
    }

    struct DKGStateReceiver {
        rx: watch::Receiver<DKGState>,
    }

    impl DKGStateReceiver {
        fn watch_node(node: &DKGNode) -> Self {
            let (tx, rx) = watch::channel(node.get_state());
            let listener = AsyncStateListener {
                tx,
                debug_name: node.get_name(),
            };
            node.add_state_change_listener(Box::new(listener));
            Self { rx }
        }

        async fn wait_for_state(&mut self, target: DKGState, timeout_ms: u64) -> bool {
            if *self.rx.borrow() == target {
                return true;
            }
            let result = timeout(Duration::from_millis(timeout_ms), async {
                while self.rx.changed().await.is_ok() {
                    if *self.rx.borrow() == target {
                        return true;
                    }
                }
                false
            })
            .await;

            match result {
                Ok(v) => v,
                Err(_) => {
                    println!("Timeout waiting for state {:?}", target);
                    false
                }
            }
        }
    }

    struct AsyncStateListener {
        tx: watch::Sender<DKGState>,
        debug_name: String,
    }

    impl DKGStateChangeListener for AsyncStateListener {
        fn on_state_changed(&self, _old: DKGState, new: DKGState) {
            if !self.debug_name.is_empty() {
                println!(
                    "{} saw state change from {:?} to {:?}",
                    self.debug_name, _old, new
                );
            }
            let _ = self.tx.send(new);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_node_2_parties() {
        println!("Starting DKG Node 2 Party Test");
        let instance = InstanceId::from_entropy();

        let setup_coord = InMemoryBridge::new();
        let dkg_coord = InMemoryBridge::new();

        let mut nodes = vec![Arc::new(DKGNode::new(
            "Node1",
            &instance,
            2,
            setup_coord.connect(),
            dkg_coord.connect(),
        ))];

        assert_eq!(nodes[0].get_state(), DKGState::WaitForParties);
        let mut state_watchers = vec![DKGStateReceiver::watch_node(&nodes[0])];

        let mut parties = tokio::task::JoinSet::new();
        spawn_node(&mut parties, nodes[0].clone());

        let qr = Arc::new(nodes[0].get_qr().unwrap());
        assert_eq!(qr.instance, instance);
        assert_eq!(qr.party_id, 0);
        // TODO: check vk

        nodes.push(Arc::new(DKGNode::from_qr(
            "Node2",
            qr.clone(),
            setup_coord.connect(),
            dkg_coord.connect(),
        )));

        assert_eq!(nodes[1].get_state(), DKGState::WaitForSetup);
        state_watchers.push(DKGStateReceiver::watch_node(&nodes[1]));
        spawn_node(&mut parties, nodes[1].clone());

        // Wait for both nodes to become ready.
        for watcher in &mut state_watchers {
            assert!(watcher.wait_for_state(DKGState::Ready, 2000).await);
        }

        assert!(nodes[0].start_dkg().await.is_ok());

        // Wait for both nodes to finish DKG.
        for watcher in &mut state_watchers {
            assert!(watcher.wait_for_state(DKGState::Finished, 5000).await);
        }

        let result1 = nodes[0].get_result().expect("Node1 result");
        let result2 = nodes[1].get_result().expect("Node2 result");
        assert_eq!(result1.0.key_id, result2.0.key_id);
        assert_eq!(result1.0.party_id, 0);
        assert_eq!(result2.0.party_id, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_node_3_parties() {
        println!("Starting DKG Node 3 Party Test");
        let instance = InstanceId::from_entropy();

        let setup_coord = InMemoryBridge::new();
        let dkg_coord = InMemoryBridge::new();

        let mut nodes = vec![Arc::new(DKGNode::new(
            "Node1",
            &instance,
            3,
            setup_coord.connect(),
            dkg_coord.connect(),
        ))];

        assert_eq!(nodes[0].get_state(), DKGState::WaitForParties);
        let mut state_watchers = vec![DKGStateReceiver::watch_node(&nodes[0])];

        let mut parties = tokio::task::JoinSet::new();
        spawn_node(&mut parties, nodes[0].clone());

        let qr = Arc::new(nodes[0].get_qr().unwrap());
        assert_eq!(qr.instance, instance);
        assert_eq!(qr.party_id, 0);
        // TODO: check vk

        for i in 1..3 {
            nodes.push(Arc::new(DKGNode::from_qr(
                format!("Node{}", i + 1).as_str(),
                qr.clone(),
                setup_coord.connect(),
                dkg_coord.connect(),
            )));
            assert_eq!(nodes[i].get_state(), DKGState::WaitForSetup);
            state_watchers.push(DKGStateReceiver::watch_node(&nodes[i]));
            spawn_node(&mut parties, nodes[i].clone());

            // Wait for all nodes to become ready.
            let exp_state = if i < 2 {
                DKGState::WaitForParties
            } else {
                DKGState::Ready
            };
            for watcher in &mut state_watchers {
                assert!(watcher.wait_for_state(exp_state, 2000).await);
            }
        }

        // by now all nodes should be started and in ready state.
        // should be able to start DKG from any node.
        assert!(nodes[1].start_dkg().await.is_ok());

        // Wait for all nodes to finish DKG.
        for watcher in &mut state_watchers {
            assert!(watcher.wait_for_state(DKGState::Finished, 5000).await);
        }

        // Check results
        let mut results = nodes
            .iter()
            .enumerate()
            .map(|(i, node)| {
                node.get_result()
                    .expect(format!("Node {} result", i).as_str())
            })
            .collect::<Vec<_>>();

        let last_res = results.pop().unwrap();
        assert!(
            results.iter().all(|r| r.0.key_id == last_res.0.key_id),
            "All key IDs equal."
        );
    }

    #[test]
    fn test_join_wait_for_sigs() {
        let instance = InstanceId::from_entropy();
        let (parties, party_sk) = make_sample_parties(2);

        let qr = QRData {
            instance: instance.clone(),
            threshold: 2,
            party_id: 0,
            vk: parties[0].vk.clone(),
        };

        let setup_if = InMemoryBridge::new();
        let dkg_if = InMemoryBridge::new();

        // Node 3 is joining
        let node3 = Arc::new(DKGNode::from_qr(
            "Node3",
            Arc::new(qr),
            setup_if.connect(),
            dkg_if.connect(),
        ));

        // Construct message from parties that we are joining
        let mut new_party_list = parties.clone();

        // Make sure we add Node 3 to the list so it sees itself confirmed
        let node3_vk = DeviceInfo::for_sk("Node3".to_string(), &node3.context.sk).vk;
        let node3_dev = DeviceInfo {
            friendly_name: "Node3".to_string(),
            vk: node3_vk,
            verified: true,
        };
        Arc::make_mut(&mut new_party_list).push(node3_dev);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&instance),
                threshold: 2,
                message: DKGSetupSubMessage::Confirm(new_party_list),
            },
            0, // Signed by party 0
            &party_sk[0],
        );

        let _ = node3.test_handle_setup_msg(msg).unwrap();
        assert_eq!(node3.get_state(), DKGState::WaitForSigs);
    }

    /*****************************************************************************
     * Test Helpers.
     *****************************************************************************/

    fn make_sample_parties(n: u8) -> (Arc<PartyList>, Vec<Arc<NodeSecretKey>>) {
        let party_sk = (0..n)
            .map(|_| Arc::new(NodeSecretKey::from_entropy()))
            .collect::<Vec<_>>();
        (
            Arc::new(
                party_sk
                    .iter()
                    .enumerate()
                    .map(|(i, sk)| DeviceInfo::for_sk(format!("Dev{}", i).to_string(), sk))
                    .collect::<PartyList>(),
            ),
            party_sk,
        )
    }

    fn make_sample_setup(t: u8, n: u8) -> (DKGSetupMessage<'static>, Vec<Arc<NodeSecretKey>>) {
        let (parties, party_sk) = make_sample_parties(n);
        let setup = DKGSetupMessage {
            instance: Cow::Owned(InstanceId::from_entropy()),
            threshold: t,
            message: DKGSetupSubMessage::Confirm(parties),
        };
        (setup, party_sk)
    }

    fn make_test_context() -> DKGContext {
        make_test_context_for_sk(NodeSecretKey::from_entropy())
    }

    fn make_test_context_for_sk(sk: NodeSecretKey) -> DKGContext {
        DKGContext::new(InstanceId::from_entropy(), 2, "TestNode".to_string(), sk)
    }

    fn make_test_context_for_sk_arc(sk: &Arc<NodeSecretKey>) -> DKGContext {
        DKGContext::new(
            InstanceId::from_entropy(),
            2,
            "TestNode".to_string(),
            sk.as_ref().clone(),
        )
    }

    fn expect_sent_msg(
        state: &Box<dyn DKGInternalState>,
        ctx: &DKGContext,
        exp_party_id: u8,
        exp_parties: &PartyList,
    ) {
        let sent_bytes = state.get_bytes_to_send(ctx).unwrap();
        let sent_msg = SignedDKGSetupMessage::try_from(sent_bytes.as_slice()).unwrap();
        sent_msg.verify().expect("Failed to verify signature.");
        assert_eq!(
            sent_msg.setup.instance.as_ref(),
            &ctx.instance,
            "Instance ID mismatch"
        );
        assert_eq!(
            sent_msg.setup.threshold, ctx.threshold,
            "Threshold mismatch"
        );
        assert_eq!(sent_msg.party_id, exp_party_id, "Party ID mismatch");
        let DKGSetupSubMessage::Confirm(parties) = sent_msg.setup.message else {
            panic!("Expected Confirm message");
        };
        assert_eq!(parties.as_ref(), exp_parties, "Party list mismatch");
    }

    /*****************************************************************************
     * Simple tests of signed messages.
     *****************************************************************************/

    #[test]
    pub fn test_sign_dkg_setup_msg_ok() {
        let (setup, party_sk) = make_sample_setup(3, 5);
        let signed = SignedDKGSetupMessage::sign(setup, 1, &party_sk[1]);
        assert!(signed.verify().is_ok());
    }

    #[test]
    pub fn test_sign_dkg_setup_msg_wrong_id() {
        let (setup, party_sk) = make_sample_setup(3, 5);
        let signed = SignedDKGSetupMessage::sign(setup, 0, &party_sk[1]);
        assert!(signed.verify().is_err());
    }

    #[test]
    pub fn test_sign_dkg_setup_msg_invalid_id() {
        let (setup, party_sk) = make_sample_setup(2, 3);
        let signed = SignedDKGSetupMessage::sign(setup, 3, &party_sk[0]);
        assert!(signed.verify().is_err());
    }

    /*****************************************************************************
     * Wait for Network State Tests.
     *****************************************************************************/

    #[test]
    fn test_wait_for_net_receive_valid_setup() {
        let (parties, party_sk) = make_sample_parties(3);
        let ctx = make_test_context_for_sk_arc(&party_sk[2]);

        let qr = QRData {
            instance: ctx.instance.clone(),
            threshold: 2,
            party_id: 0,
            vk: parties[0usize].vk.clone(),
        };
        let wait_state = DKGWaitForNetState::new(Arc::new(qr));

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&ctx.instance),
                threshold: 2,
                message: DKGSetupSubMessage::Confirm(parties.clone()),
            },
            1,
            &party_sk[1],
        );

        let (new_state, res) = wait_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Ok(true)));
        assert_eq!(new_state.get_state(), DKGState::WaitForSigs);

        let new_setup_parties = new_state.get_party_list().unwrap();
        assert_eq!(new_setup_parties.as_ref(), parties.as_ref());
        expect_sent_msg(&new_state, &ctx, 2, &parties);
    }

    #[test]
    fn test_wait_for_net_receive_valid_setup_2_parties() {
        let (parties, party_sk) = make_sample_parties(2);
        let ctx = make_test_context_for_sk_arc(&party_sk[1]);

        let qr = QRData {
            instance: ctx.instance.clone(),
            threshold: 2,
            party_id: 0,
            vk: parties[0usize].vk.clone(),
        };
        let wait_state = DKGWaitForNetState::new(Arc::new(qr));

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&ctx.instance),
                threshold: 2,
                message: DKGSetupSubMessage::Confirm(parties.clone()),
            },
            0,
            &party_sk[0],
        );

        let (new_state, res) = wait_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Ok(true)));
        assert_eq!(new_state.get_state(), DKGState::Ready);

        let new_setup_parties = new_state.get_party_list().unwrap();
        assert_eq!(new_setup_parties.as_ref(), parties.as_ref());
        expect_sent_msg(&new_state, &ctx, 1, &parties);
    }

    #[test]
    fn test_wait_for_net_receive_invalid_setup() {
        let (parties, party_sk) = make_sample_parties(3);
        let ctx = make_test_context_for_sk_arc(&party_sk[2]);

        let qr = QRData {
            instance: ctx.instance.clone(),
            threshold: 2,
            party_id: 0,
            vk: parties[0usize].vk.clone(),
        };
        let wait_state = DKGWaitForNetState::new(Arc::new(qr));

        let other_instance = InstanceId::from_entropy();
        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&other_instance),
                threshold: 2,
                message: DKGSetupSubMessage::Confirm(parties.clone()),
            },
            0,
            &party_sk[0],
        );

        let (new_state, res) = wait_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Err(GeneralError::InvalidSetupMessage)));
        assert_eq!(new_state.get_state(), DKGState::WaitForSetup);
    }

    /*****************************************************************************
     * Wait for Signatures State Tests.
     *****************************************************************************/

    #[test]
    fn test_wait_for_sigs_basics() {
        let (parties, party_sk) = make_sample_parties(3);
        let ctx = make_test_context_for_sk_arc(&party_sk[1]);
        let wait_state: Box<dyn DKGInternalState> = DKGWaitForSigs::new(parties.clone(), 1, &ctx);
        assert_eq!(wait_state.get_state(), DKGState::WaitForSigs);
        assert_eq!(wait_state.get_party_list().unwrap(), parties);
        assert_eq!(wait_state.my_party_id().unwrap(), 1);
        expect_sent_msg(&wait_state, &ctx, 1, &parties);
    }

    #[test]
    fn test_wait_for_sigs_receive_invalid_party_list() {
        let (parties, party_sk) = make_sample_parties(3);
        let ctx = make_test_context_for_sk_arc(&party_sk[1]);
        let wait_state = DKGWaitForSigs::new(parties.clone(), 1, &ctx);

        let (bad_parties, _) = make_sample_parties(3); // Different parties
        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&ctx.instance),
                threshold: 2,
                message: DKGSetupSubMessage::Confirm(bad_parties),
            },
            0,
            &party_sk[0],
        );

        let (new_state, res) = wait_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Err(GeneralError::InvalidSetupMessage)));
        assert_eq!(new_state.get_state(), DKGState::WaitForSigs);
    }

    #[test]
    fn test_wait_for_sigs_receive_setup_ok() {
        let (parties, party_sk) = make_sample_parties(3);
        let ctx = make_test_context_for_sk_arc(&party_sk[1]);
        let wait_state = DKGWaitForSigs::new(parties.clone(), 1, &ctx);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&ctx.instance),
                threshold: 2,
                message: DKGSetupSubMessage::Confirm(parties.clone()),
            },
            2,
            &party_sk[2],
        );

        let (new_state, res) = wait_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Ok(false)));
        assert_eq!(new_state.get_state(), DKGState::WaitForSigs);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&ctx.instance),
                threshold: 2,
                message: DKGSetupSubMessage::Confirm(parties.clone()),
            },
            0,
            &party_sk[0],
        );

        let (new_state, res) = new_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Ok(false)));
        assert_eq!(new_state.get_state(), DKGState::Ready);
    }

    /*****************************************************************************
     * Ready State Tests.
     *****************************************************************************/

    #[test]
    fn test_ready_state_basics() {
        let (parties, party_sk) = make_sample_parties(3);
        let ctx = make_test_context_for_sk_arc(&party_sk[1]);
        let ready_state: Box<dyn DKGInternalState> = DKGReadyState::new(parties.clone(), 1, 2);
        assert_eq!(ready_state.get_state(), DKGState::Ready);
        assert_eq!(ready_state.get_party_list().unwrap(), parties);
        assert_eq!(ready_state.my_party_id().unwrap(), 1);
        expect_sent_msg(&ready_state, &ctx, 1, &parties);
    }

    #[test]
    fn test_ready_receive_setup_consistency_incompatible_party_list_shorter() {
        let instance = InstanceId::from_entropy();
        let (parties, party_sk) = make_sample_parties(3);
        let ready_state = DKGReadyState::new(parties.clone(), 1, 2);
        let ctx = make_test_context_for_sk_arc(&party_sk[1]);

        let mut short_parties = parties.clone();
        Arc::make_mut(&mut short_parties).pop();
        let bad_msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&instance),
                threshold: 2,
                message: DKGSetupSubMessage::Confirm(short_parties),
            },
            0,
            &party_sk[0],
        );
        let (new_state, res) = ready_state.receive_setup_msg(&ctx, bad_msg);
        assert!(matches!(res, Err(GeneralError::InvalidSetupMessage)));
        assert_eq!(new_state.get_state(), DKGState::Ready);
    }

    #[test]
    fn test_ready_receive_setup_consistency_incompatible_party_list_different() {
        let instance = InstanceId::from_entropy();
        let (parties, party_sk) = make_sample_parties(3);
        let ready_state = DKGReadyState::new(parties.clone(), 1, 2);
        let ctx = make_test_context_for_sk_arc(&party_sk[1]);

        let (different_parties, _) = make_sample_parties(3);
        let bad_msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&instance),
                threshold: 2,
                message: DKGSetupSubMessage::Confirm(different_parties),
            },
            0,
            &party_sk[0],
        );

        let (new_state, res) = ready_state.receive_setup_msg(&ctx, bad_msg);
        assert!(matches!(res, Err(GeneralError::InvalidSetupMessage)));
        assert_eq!(new_state.get_state(), DKGState::Ready);
    }

    #[test]
    fn test_ready_receive_setup_add_party() {
        let (parties, party_sk) = make_sample_parties(3);
        let ctx = make_test_context_for_sk_arc(&party_sk[0]);
        let instance = &ctx.instance;

        let short_parties = Arc::new(
            parties[..parties.len() as usize - 1]
                .iter()
                .cloned()
                .collect::<PartyList>(),
        );
        let ready_state = DKGReadyState::new(short_parties.clone(), 0, 2);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&instance),
                threshold: 2,
                message: DKGSetupSubMessage::Confirm(parties.clone()),
            },
            1,
            &party_sk[1],
        );

        let (new_state, res) = ready_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Ok(true)));
        assert_eq!(new_state.get_state(), DKGState::WaitForSigs);

        let new_setup_parties = new_state.get_party_list().unwrap();
        assert_eq!(new_setup_parties.len(), 3);
        assert_eq!(new_setup_parties.as_ref(), parties.as_ref());

        expect_sent_msg(&new_state, &ctx, 0, &parties);
    }

    #[test]
    fn test_ready_receive_setup_join_many_parties() {
        let (parties, party_sk) = make_sample_parties(2);
        let ctx = make_test_context_for_sk_arc(&party_sk[0]);
        let instance = &ctx.instance;
        let ready_state = DKGReadyState::new(parties.clone(), 0, 2);

        let join_sk = NodeSecretKey::from_entropy();
        let join_device = DeviceInfo::for_sk("JoinDev".to_string(), &join_sk);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&instance),
                threshold: 2,
                message: DKGSetupSubMessage::Join(Cow::Borrowed(&join_device)),
            },
            0,
            &join_sk,
        );

        let (new_state, res) = ready_state.receive_setup_msg(&ctx, msg);

        assert!(matches!(res, Ok(true)));
        assert_eq!(new_state.get_state(), DKGState::WaitForSigs);

        let mut exp_parties = (*parties).clone();
        exp_parties.push(join_device.clone());
        expect_sent_msg(&new_state, &ctx, 0, &exp_parties);
    }

    #[test]
    fn test_ready_receive_setup_start_not_enough_parties() {
        let (parties, party_sk) = make_sample_parties(2);
        let mut ctx = make_test_context_for_sk_arc(&party_sk[1]);
        ctx.threshold = 3;
        let instance = &ctx.instance;
        let ready_state = DKGReadyState::new(parties.clone(), 1, 3);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&instance),
                threshold: 3,
                message: DKGSetupSubMessage::Start(parties.clone()),
            },
            0,
            &party_sk[0],
        );

        let (new_state, res) = ready_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));
        assert_eq!(new_state.get_state(), DKGState::WaitForParties);
    }

    #[test]
    fn test_ready_receive_setup_start_success() {
        let (parties, party_sk) = make_sample_parties(2);
        let ctx = make_test_context_for_sk_arc(&party_sk[0]);
        let instance = &ctx.instance;
        let ready_state = DKGReadyState::new(parties.clone(), 0, 2);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&instance),
                threshold: 2,
                message: DKGSetupSubMessage::Start(parties.clone()),
            },
            1,
            &party_sk[1],
        );

        let (new_state, res) = ready_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Ok(false)));
        assert_eq!(new_state.get_state(), DKGState::Running);
    }

    /*****************************************************************************
     * Running State Tests.
     *****************************************************************************/

    #[test]
    fn test_running_state_basics() {
        let (parties, party_sk) = make_sample_parties(3);
        let ctx = make_test_context_for_sk_arc(&party_sk[0]);
        let running_state = DKGRunningState::new(parties.clone(), 0);
        assert_eq!(running_state.get_state(), DKGState::Running);
        assert_eq!(running_state.get_party_list().unwrap(), parties.clone());
        assert_eq!(running_state.my_party_id().unwrap(), 0);

        let sent_bytes = running_state.get_bytes_to_send(&ctx).unwrap();
        let sent_msg = SignedDKGSetupMessage::try_from(sent_bytes.as_slice()).unwrap();
        sent_msg.verify().expect("Failed to verify signature.");
        assert_eq!(
            sent_msg.setup.instance.as_ref(),
            &ctx.instance,
            "Instance ID mismatch"
        );
        assert_eq!(
            sent_msg.setup.threshold, ctx.threshold,
            "Threshold mismatch"
        );
        assert_eq!(sent_msg.party_id, 0, "Party ID mismatch");
        let DKGSetupSubMessage::Start(sent_parties) = sent_msg.setup.message else {
            panic!("Expected Start message");
        };
        assert_eq!(
            sent_parties.as_ref(),
            parties.as_ref(),
            "Party list mismatch"
        );
    }

    #[test]
    fn test_running_state_rejects_receive_setup() {
        // This should never happen, but good to make sure it doesn't crash or something.
        let (parties, party_sk) = make_sample_parties(3);
        let ctx = make_test_context_for_sk_arc(&party_sk[0]);
        let running_state = DKGRunningState::new(parties.clone(), 0);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&ctx.instance),
                threshold: 2,
                message: DKGSetupSubMessage::Confirm(parties.clone()),
            },
            1,
            &party_sk[1],
        );

        let (new_state, res) = running_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));
        assert_eq!(new_state.get_state(), DKGState::Running);
    }

    #[test]
    fn test_running_state_rejects_start_dkg() {
        let (parties, party_sk) = make_sample_parties(3);
        let ctx = make_test_context_for_sk_arc(&party_sk[0]);
        let running_state = DKGRunningState::new(parties.clone(), 0);
        let (new_state, res) = running_state.start_dkg(&ctx);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));
        assert_eq!(new_state.get_state(), DKGState::Running);
    }

    /*****************************************************************************
     * Finished State Tests.
     *****************************************************************************/

    #[test]
    fn test_finished_state_basics() {
        let (parties, _) = make_sample_parties(3);
        let finished_state =
            DKGFinishedState::new(parties.clone(), Err(GeneralError::Cancelled), 0);
        assert_eq!(finished_state.get_state(), DKGState::Finished);
        assert_eq!(finished_state.get_party_list().unwrap(), parties.clone());
        assert_eq!(finished_state.my_party_id().unwrap(), 0);
        assert!(matches!(
            finished_state.get_result(),
            Err(GeneralError::Cancelled)
        ));
    }

    #[test]
    fn test_finished_state_rejects_receive_setup() {
        // This should never happen, but good to make sure it doesn't crash or something.
        let (parties, party_sk) = make_sample_parties(3);
        let ctx = make_test_context_for_sk_arc(&party_sk[0]);
        let finished_state =
            DKGFinishedState::new(parties.clone(), Err(GeneralError::Cancelled), 0);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage {
                instance: Cow::Borrowed(&ctx.instance),
                threshold: 2,
                message: DKGSetupSubMessage::Confirm(parties.clone()),
            },
            1,
            &party_sk[1],
        );

        let (new_state, res) = finished_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));
        assert_eq!(new_state.get_state(), DKGState::Finished);
    }

    #[test]
    fn test_finished_state_rejects_start_dkg() {
        let (parties, party_sk) = make_sample_parties(3);
        let ctx = make_test_context_for_sk_arc(&party_sk[0]);
        let finished_state =
            DKGFinishedState::new(parties.clone(), Err(GeneralError::Cancelled), 0);
        let (new_state, res) = finished_state.start_dkg(&ctx);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));
        assert_eq!(new_state.get_state(), DKGState::Finished);
    }
}
