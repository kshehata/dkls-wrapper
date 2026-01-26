use std::sync::{Arc, RwLock};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use signature::Signer;
use sl_dkls23::setup;
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
    fn on_setup_changed(&self, setup: Arc<DKGSetupMessage>);
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
        let context = DKGContext {
            friendly_name: name.to_string(),
            sk: NodeSecretKey::from_entropy(),
        };
        let setup = DKGSetupMessage {
            instance: *instance,
            threshold,
            parties: vec![DeviceInfo::for_sk(name.to_string(), &context.sk)],
            start: false,
        };
        Self {
            state: RwLock::new(Some(DKGReadyState::new(setup, 0))),
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
        let context = DKGContext {
            friendly_name: name.to_string(),
            sk: NodeSecretKey::from_entropy(),
        };
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
        if let Ok(setup) = self.state.read().unwrap().as_ref().unwrap().get_setup() {
            listener.on_setup_changed(setup);
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
        if self.get_state() == DKGState::WaitForParties {
            // println!("{:?} Sending setup message", self.context.friendly_name);
            let setup_bytes = self
                .state
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .get_signed_setup(&self.context)
                .unwrap()
                .to_bytes();
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
        let (setup, party_id) = {
            let guard = self.state.read().unwrap();
            let state = guard.as_ref().unwrap();
            if state.get_state() != DKGState::Running {
                // println!("{:?} Not Running!?!", self.context.friendly_name);
                return Err(GeneralError::InvalidState(
                    "Calculated state is running but stored state is not?".to_string(),
                ));
            }
            (state.get_setup().unwrap(), state.my_party_id().unwrap())
        };

        // println!("{:?} Starting DKG", self.context.friendly_name);
        let res = self.do_dkg_internal(setup.clone(), party_id).await;
        // println!("{:?} DKG Complete?", self.context.friendly_name);

        let _ = self.do_state_fn(|_| (DKGFinishedState::new(setup, res, party_id), Ok(false)));
        Ok(())
    }
}

impl DKGNode {
    pub fn get_qr(&self) -> Result<QRData, GeneralError> {
        self.state.read().unwrap().as_ref().unwrap().get_qr()
    }

    pub fn receive_qr(&self, qr: QRData) -> Result<(), GeneralError> {
        let maybe_setup = {
            let mut guard = self.state.write().unwrap();
            let state = guard.as_mut().unwrap();
            state.scan_qr(qr)?;
            state.get_setup().ok()
        };
        if let Some(setup) = maybe_setup {
            self.notify_setup_listeners(setup);
        }
        Ok(())
    }

    // Shortcut to receive and parse a setup message.
    async fn get_next_msg_interruptable(&self) -> Result<SignedDKGSetupMessage, GeneralError> {
        let receive_fut = self.setup_if.receive();
        let stop_fut = self.await_msg_kick.notified();

        let data = tokio::select! {
            res = receive_fut => res?,
            _ = stop_fut => return Err(GeneralError::Cancelled),
        };
        let msg = SignedDKGSetupMessage::try_from(data.as_slice())?;
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

    async fn do_dkg_internal(
        &self,
        setup: Arc<DKGSetupMessage>,
        party_id: u8,
    ) -> Result<Keyshare, GeneralError> {
        // TODO: should maybe put a Mutex here to make sure it never runs twice?

        let vkrefs: Vec<&NodeVerifyingKey> = setup.parties.iter().map(|dev| &dev.vk).collect();
        let ranks = vec![0u8; setup.parties.len()];
        let setup_msg = KeygenSetup::new(
            setup.instance.into(),
            &self.context.sk,
            party_id.into(),
            vkrefs,
            &ranks,
            setup.threshold.into(),
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
        let (old_state_enum, new_state_enum, res, old_setup, new_setup) = {
            let mut guard = self.state.write().unwrap();
            let current_state = guard.take().unwrap();
            let old_state_enum = current_state.get_state();
            let old_setup = current_state.get_setup().ok();
            let (new_state, res) = f(current_state);
            let new_state_enum = new_state.get_state();
            let new_setup = new_state.get_setup().ok();

            // If the state_fn indicated to send an update to the network,
            // get the signed state message and serialize it before doing
            // anything else. If not, avoid doing this work.
            let res = match res {
                Ok(true) => match new_state.get_signed_setup(&self.context) {
                    Ok(s) => Ok(s.to_bytes()),
                    Err(e) => Err(e),
                },
                Ok(false) => Ok(vec![]),
                Err(e) => Err(e),
            };
            *guard = Some(new_state);
            (old_state_enum, new_state_enum, res, old_setup, new_setup)
        };

        // Update listeners of changes.
        self.notify_listeners(old_state_enum, new_state_enum);
        if let Some(setup) = new_setup {
            match old_setup {
                Some(s2) if s2 == setup => (),
                _ => self.notify_setup_listeners(setup),
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

    fn notify_setup_listeners(&self, setup: Arc<DKGSetupMessage>) {
        let listeners = self.setup_listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.on_setup_changed(setup.clone());
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

// TODO: need signatures for this.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, uniffi::Object)]
pub struct DKGSetupMessage {
    pub instance: InstanceId,
    pub threshold: u8,
    pub parties: Vec<DeviceInfo>,
    pub start: bool,
}

impl TryFrom<&[u8]> for DKGSetupMessage {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        postcard::from_bytes(value).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }
}

impl TryFrom<&str> for DKGSetupMessage {
    type Error = GeneralError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        serde_json::from_str(value).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }
}

#[uniffi::export]
impl DKGSetupMessage {
    pub fn get_instance(&self) -> InstanceId {
        self.instance
    }

    pub fn get_threshold(&self) -> u8 {
        self.threshold
    }

    pub fn get_parties(&self) -> Vec<Arc<DeviceInfo>> {
        self.parties.iter().map(|d| Arc::new(d.clone())).collect()
    }
}

impl DKGSetupMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    fn verify_qr(&mut self, qr: &QRData) -> Result<(), GeneralError> {
        if self.instance != qr.instance
            || self.parties.len() <= qr.party_id as usize
            || self.parties[qr.party_id as usize].vk != qr.vk
        {
            return Err(GeneralError::InvalidInput(
                "Setup and QR mismatch".to_string(),
            ));
        }
        self.parties[qr.party_id as usize].verified = true;

        Ok(())
    }

    fn add_ourself(&mut self, name: &str, sk: &NodeSecretKey) -> u8 {
        self.parties.push(DeviceInfo::for_sk(name.to_string(), sk));
        self.parties.len() as u8 - 1
    }

    // NB: self is the NEW setup message.
    // This checks that the new setup message is consistent with the existing setup message.
    fn verify_existing(
        &mut self,
        existing_setup: &DKGSetupMessage,
    ) -> Result<&mut Self, GeneralError> {
        // Make sure setup is consistent.
        if existing_setup.instance != self.instance
            || existing_setup.threshold != self.threshold
            || existing_setup.parties.len() > self.parties.len()
        {
            return Err(GeneralError::InvalidSetupMessage);
        }

        // Copy the verified field from the existing setup message.
        for i in 0..existing_setup.parties.len() {
            self.parties[i].verified = existing_setup.parties[i].verified;
        }

        // If any of the device infos are different, reject the setup.
        if self.parties[..existing_setup.parties.len()] != existing_setup.parties {
            return Err(GeneralError::InvalidSetupMessage);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, uniffi::Object)]
struct SignedDKGSetupMessage {
    setup: Arc<DKGSetupMessage>,
    party_id: u8,
    sig: Signature,
    start: bool,
}

impl TryFrom<&[u8]> for SignedDKGSetupMessage {
    type Error = GeneralError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        postcard::from_bytes(value).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }
}

impl TryFrom<&str> for SignedDKGSetupMessage {
    type Error = GeneralError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        serde_json::from_str(value).map_err(|e| GeneralError::InvalidInput(e.to_string()))
    }
}

impl SignedDKGSetupMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

impl SignedDKGSetupMessage {
    pub fn sign(setup: Arc<DKGSetupMessage>, party_id: u8, sk: &NodeSecretKey) -> Self {
        let sig = Signature(sk.try_sign(setup.to_bytes().as_ref()).unwrap());
        Self {
            setup,
            party_id,
            sig,
            start: false,
        }
    }

    pub fn verify(&self) -> Result<(), GeneralError> {
        if self.party_id >= self.setup.parties.len() as u8 {
            return Err(GeneralError::InvalidInput("Invalid party ID".to_string()));
        }
        self.setup.parties[self.party_id as usize]
            .vk
            .verify(self.setup.to_bytes().as_ref(), &self.sig)
    }
}

/*****************************************************************************
 * DKG State Machine
 *****************************************************************************/

#[derive(Debug, PartialEq, Clone, Copy, uniffi::Enum)]
pub enum DKGState {
    WaitForSetup,
    WaitForParties,
    Ready,
    Running,
    Finished,
}

struct DKGContext {
    friendly_name: String,
    sk: NodeSecretKey,
}

trait DKGInternalState: Send + Sync + 'static {
    fn get_state(&self) -> DKGState;

    fn my_party_id(&self) -> Result<u8, GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot get party ID in current state.".to_string(),
        ))
    }

    fn get_qr(&self) -> Result<QRData, GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot get QR in current state.".to_string(),
        ))
    }

    fn get_setup(&self) -> Result<Arc<DKGSetupMessage>, GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot get setup handle in current state.".to_string(),
        ))
    }

    fn get_signed_setup(
        &self,
        _context: &DKGContext,
    ) -> Result<SignedDKGSetupMessage, GeneralError> {
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

    fn receive_setup_msg(
        self: Box<Self>,
        context: &DKGContext,
        setup_msg: SignedDKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        // Assume signatures are already verified.
        let mut setup = Arc::unwrap_or_clone(setup_msg.setup);
        if let Err(e) = setup.verify_qr(&self.qr_data) {
            return (self, Err(e));
        }
        let party_id = setup.add_ourself(&context.friendly_name, &context.sk);

        // Always have to send an update to the network.
        (DKGReadyState::new(setup, party_id), Ok(true))
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
 * Ready state.
 * In this state, we have the setup data and we're ready to start the DKG,
 * but we're waiting in case more devices join.
 *****************************************************************************/

struct DKGReadyState {
    setup: Arc<DKGSetupMessage>,
    party_id: u8,
}

impl DKGReadyState {
    fn new(setup: DKGSetupMessage, party_id: u8) -> Box<Self> {
        Box::new(Self {
            setup: Arc::new(setup),
            party_id,
        })
    }
}

impl DKGInternalState for DKGReadyState {
    fn get_state(&self) -> DKGState {
        if self.setup.parties.len() < self.setup.threshold as usize {
            DKGState::WaitForParties
        } else {
            DKGState::Ready
        }
    }

    fn my_party_id(&self) -> Result<u8, GeneralError> {
        Ok(self.party_id)
    }

    fn get_qr(&self) -> Result<QRData, GeneralError> {
        Ok(QRData {
            instance: self.setup.instance,
            party_id: self.party_id,
            vk: self.setup.parties[self.party_id as usize].vk.clone(),
        })
    }

    fn get_setup(&self) -> Result<Arc<DKGSetupMessage>, GeneralError> {
        Ok(self.setup.clone())
    }

    fn get_signed_setup(
        &self,
        context: &DKGContext,
    ) -> Result<SignedDKGSetupMessage, GeneralError> {
        Ok(SignedDKGSetupMessage::sign(
            self.setup.clone(),
            self.party_id,
            &context.sk,
        ))
    }

    fn scan_qr(&mut self, qr_data: QRData) -> Result<(), GeneralError> {
        Arc::make_mut(&mut self.setup).verify_qr(&qr_data)
    }

    fn receive_setup_msg(
        self: Box<Self>,
        _context: &DKGContext,
        mut setup_msg: SignedDKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        let mut new_setup = Arc::unwrap_or_clone(setup_msg.setup);

        // This gets a little complicated with signatures.
        // Normal cases: all of the previous parties match.
        //  -> Due to network reordering, can take any sig
        //     (i.e. might get sig from actual party after
        //     some other party)
        //   In this case add the new parties and collect sigs.
        //
        // Reordering case: if we get some other order,
        // only accept it if it's signed by *our* previous
        // party ID 0.
        // Should also check that we didn't previously receive
        // a different prefix, i.e. ID 0 can't equivocate.

        // Make sure setup is consistent.
        if self.setup.instance != new_setup.instance
            || self.setup.threshold != new_setup.threshold
            || self.setup.parties.len() > new_setup.parties.len()
        {
            return (self, Err(GeneralError::InvalidSetupMessage));
        }

        // Copy the verified field from the existing setup message.
        for i in 0..self.setup.parties.len() {
            new_setup.parties[i].verified = self.setup.parties[i].verified;
        }

        // If any of the device infos are different, reject the setup.
        if new_setup.parties[..self.setup.parties.len()] != self.setup.parties {
            return (self, Err(GeneralError::InvalidSetupMessage));
        }

        // Check if we got the start flag, and if so
        // check that we have enough parties to start.
        if new_setup.start {
            // println!("{} received start flag", _context.friendly_name);
            if new_setup.parties.len() < new_setup.threshold as usize {
                new_setup.start = false;
                return (
                    Self::new(new_setup, self.party_id),
                    Err(GeneralError::InvalidState(
                        "Not enough parties to start DKG.".to_string(),
                    )),
                );
            }
            // TODO: does this need to be true?
            (
                DKGRunningState::new(Arc::new(new_setup), self.party_id),
                Ok(false),
            )
        } else {
            (Self::new(new_setup, self.party_id), Ok(false))
        }
    }

    fn start_dkg(
        mut self: Box<Self>,
        _context: &DKGContext,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        if self.setup.parties.len() < self.setup.threshold as usize {
            (
                self,
                Err(GeneralError::InvalidState(
                    "Not enough parties to start DKG.".to_string(),
                )),
            )
        } else {
            Arc::make_mut(&mut self.setup).start = true;
            (DKGRunningState::new(self.setup, self.party_id), Ok(true))
        }
    }
}

/*****************************************************************************
 * Running state.
 * DKG is running, can't get any intermediate results.
 *****************************************************************************/

struct DKGRunningState {
    setup: Arc<DKGSetupMessage>,
    party_id: u8,
}

impl DKGRunningState {
    fn new(setup: Arc<DKGSetupMessage>, party_id: u8) -> Box<Self> {
        Box::new(Self { setup, party_id })
    }
}

impl DKGInternalState for DKGRunningState {
    fn get_state(&self) -> DKGState {
        DKGState::Running
    }

    fn my_party_id(&self) -> Result<u8, GeneralError> {
        Ok(self.party_id)
    }

    fn get_setup(&self) -> Result<Arc<DKGSetupMessage>, GeneralError> {
        Ok(self.setup.clone())
    }

    fn get_signed_setup(
        &self,
        context: &DKGContext,
    ) -> Result<SignedDKGSetupMessage, GeneralError> {
        Ok(SignedDKGSetupMessage::sign(
            self.setup.clone(),
            self.party_id,
            &context.sk,
        ))
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
    setup: Arc<DKGSetupMessage>,
    result: Result<Keyshare, GeneralError>,
    party_id: u8,
}

impl DKGFinishedState {
    fn new(
        setup: Arc<DKGSetupMessage>,
        result: Result<Keyshare, GeneralError>,
        party_id: u8,
    ) -> Box<Self> {
        Box::new(Self {
            setup,
            result,
            party_id,
        })
    }
}

impl DKGInternalState for DKGFinishedState {
    fn get_state(&self) -> DKGState {
        DKGState::Finished
    }

    fn my_party_id(&self) -> Result<u8, GeneralError> {
        Ok(self.party_id)
    }

    fn get_qr(&self) -> Result<QRData, GeneralError> {
        Ok(QRData {
            instance: self.setup.instance,
            party_id: self.party_id,
            vk: self.setup.parties[self.party_id as usize].vk.clone(),
        })
    }

    fn get_setup(&self) -> Result<Arc<DKGSetupMessage>, GeneralError> {
        Ok(self.setup.clone())
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
    use k256::elliptic_curve::group::GroupEncoding;
    use std::time::Duration;
    use tokio::time::sleep;

    fn spawn_node(
        js: &mut tokio::task::JoinSet<()>,
        node: Arc<DKGNode>,
    ) -> tokio::task::AbortHandle {
        js.spawn(async move {
            let _ = node.message_loop().await;
        })
    }

    async fn wait_for_state(node: Arc<DKGNode>, state: DKGState, iters: u64) -> bool {
        for _ in 0..iters {
            // println!(
            //     "{} is in state {:?}",
            //     node.context.friendly_name,
            //     node.get_state()
            // );
            if node.get_state() == state {
                return true;
            }
            sleep(Duration::from_millis(10)).await;
        }
        false
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_node() {
        println!("Starting DKG Node Test");
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

        let mut parties = tokio::task::JoinSet::new();
        spawn_node(&mut parties, nodes[1].clone());
        spawn_node(&mut parties, nodes[0].clone());

        // Wait for both nodes to become ready.
        assert!(wait_for_state(nodes[1].clone(), DKGState::Ready, 50).await);
        assert!(wait_for_state(nodes[0].clone(), DKGState::Ready, 50).await);

        assert!(nodes[0].start_dkg().await.is_ok());
        // assert!(nodes[1].start_dkg().await.is_ok());

        // Wait for both nodes to finish DKG.
        assert!(wait_for_state(nodes[1].clone(), DKGState::Finished, 500).await);
        assert!(wait_for_state(nodes[0].clone(), DKGState::Finished, 500).await);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_state_listener() {
        struct TestListener {
            changes: Arc<RwLock<Vec<(DKGState, DKGState)>>>,
        }

        impl DKGStateChangeListener for TestListener {
            fn on_state_changed(&self, old: DKGState, new: DKGState) {
                self.changes.write().unwrap().push((old, new));
            }
        }

        let changes = Arc::new(RwLock::new(Vec::new()));
        let listener = TestListener {
            changes: changes.clone(),
        };

        let instance = InstanceId::from_entropy();
        let setup_if = InMemoryBridge::new();
        let dkg_if = InMemoryBridge::new();
        let other_conn = setup_if.connect();

        let node = Arc::new(DKGNode::new(
            "ListenerNode",
            &instance,
            2,
            setup_if.connect(),
            dkg_if.connect(),
        ));

        node.add_state_change_listener(Box::new(listener));

        let node_ref = node.clone();
        tokio::spawn(async move {
            let _ = node_ref.message_loop().await;
        });

        // 1. Receive the initial setup message (broadcast by node).
        // It broadcasts because it starts in WaitForParties (1 < 2).
        let received_bytes = other_conn.receive().await.unwrap();
        let mut setup_msg = DKGSetupMessage::try_from(received_bytes.as_slice()).unwrap();

        // 2. Add another party to it.
        let other_sk = NodeSecretKey::from_entropy();
        let other_id = setup_msg.add_ourself("OtherNode", &other_sk);

        // 3. Send it back.
        let signed_msg = SignedDKGSetupMessage::sign(Arc::new(setup_msg), other_id, &other_sk);
        other_conn.send(signed_msg.to_bytes()).await.unwrap();

        // 4. Wait for state change to Ready.
        assert!(wait_for_state(node.clone(), DKGState::Ready, 50).await);

        let changes_vec = changes.read().unwrap();
        // We expect at least one transition to Ready.
        // Depending on timing, we might see intermediate states if any (none here).
        // Transition: WaitForParties -> Ready.
        assert!(!changes_vec.is_empty());
        assert_eq!(
            changes_vec.last().unwrap(),
            &(DKGState::WaitForParties, DKGState::Ready)
        );
    }

    fn make_sample_setup(t: u8, n: u8) -> (Arc<DKGSetupMessage>, Vec<Arc<NodeSecretKey>>) {
        let party_sk = (0..n)
            .map(|_| Arc::new(NodeSecretKey::from_entropy()))
            .collect::<Vec<_>>();
        let devices = party_sk
            .iter()
            .enumerate()
            .map(|(i, sk)| DeviceInfo::for_sk(format!("Dev{}", i).to_string(), sk))
            .collect::<Vec<_>>();
        let setup = Arc::new(DKGSetupMessage {
            instance: InstanceId::from_entropy(),
            threshold: t,
            parties: devices,
            start: false,
        });
        (setup, party_sk)
    }

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
    fn make_test_context() -> DKGContext {
        DKGContext {
            friendly_name: "test".to_string(),
            sk: NodeSecretKey::from_entropy(),
        }
    }

    #[test]
    fn test_ready_receive_setup_consistency_mismatched_instance() {
        let (setup, _) = make_sample_setup(2, 3);
        let party_id = 0;
        let ready_state = DKGReadyState::new((*setup).clone(), party_id);
        let ctx = make_test_context();

        let mut bad_setup = (*setup).clone();
        bad_setup.instance = InstanceId::from_entropy();
        let bad_msg = SignedDKGSetupMessage::sign(Arc::new(bad_setup), 0, &ctx.sk);
        let boxed_state: Box<dyn DKGInternalState> = ready_state;
        let (_, res) = boxed_state.receive_setup_msg(&ctx, bad_msg);
        assert!(matches!(res, Err(GeneralError::InvalidSetupMessage)));
    }

    #[test]
    fn test_ready_receive_setup_consistency_mismatched_threshold() {
        let (setup, _) = make_sample_setup(2, 3);
        let party_id = 0;
        let ready_state = DKGReadyState::new((*setup).clone(), party_id);
        let ctx = make_test_context();

        let mut bad_setup = (*setup).clone();
        bad_setup.threshold = 100;
        let bad_msg = SignedDKGSetupMessage::sign(Arc::new(bad_setup), 0, &ctx.sk);
        let boxed_state: Box<dyn DKGInternalState> = ready_state;
        let (_, res) = boxed_state.receive_setup_msg(&ctx, bad_msg);
        assert!(matches!(res, Err(GeneralError::InvalidSetupMessage)));
    }

    #[test]
    fn test_ready_receive_setup_consistency_incompatible_party_list_shorter() {
        let (setup, _) = make_sample_setup(2, 3);
        let party_id = 0;
        let ready_state = DKGReadyState::new((*setup).clone(), party_id);
        let ctx = make_test_context();

        let mut bad_setup = (*setup).clone();
        bad_setup.parties.pop();
        let bad_msg = SignedDKGSetupMessage::sign(Arc::new(bad_setup), 0, &ctx.sk);
        let boxed_state: Box<dyn DKGInternalState> = ready_state;
        let (_, res) = boxed_state.receive_setup_msg(&ctx, bad_msg);
        assert!(matches!(res, Err(GeneralError::InvalidSetupMessage)));
    }

    #[test]
    fn test_ready_receive_setup_consistency_incompatible_party_list_different() {
        let (setup, _) = make_sample_setup(2, 3);
        let party_id = 0;
        let ready_state = DKGReadyState::new((*setup).clone(), party_id);
        let ctx = make_test_context();

        let (setup2, _) = make_sample_setup(2, 3);
        let bad_msg = SignedDKGSetupMessage::sign(setup2, 0, &ctx.sk);
        let boxed_state: Box<dyn DKGInternalState> = ready_state;
        let (_, res) = boxed_state.receive_setup_msg(&ctx, bad_msg);
        assert!(matches!(res, Err(GeneralError::InvalidSetupMessage)));
    }

    #[test]
    fn test_ready_receive_setup_add_party() {
        let (setup, _) = make_sample_setup(2, 3);
        // Start with only 2 parties known
        let mut partial_setup = (*setup).clone();
        let extra_party = partial_setup.parties.pop().unwrap();

        let party_id = 0;
        let ready_state = DKGReadyState::new(partial_setup.clone(), party_id);
        let ctx = make_test_context();

        // Receive full setup
        let msg = SignedDKGSetupMessage::sign(setup.clone(), 0, &ctx.sk);
        let boxed_state: Box<dyn DKGInternalState> = ready_state;
        let (new_state, res) = boxed_state.receive_setup_msg(&ctx, msg);

        assert!(res.is_ok());
        let new_setup = new_state.get_setup().unwrap();
        assert_eq!(new_setup.parties.len(), 3);
        assert_eq!(new_setup.parties[2].vk, extra_party.vk);
    }

    #[test]
    fn test_ready_receive_setup_start_not_enough_parties() {
        let (setup, _) = make_sample_setup(3, 2); // Threshold 3, but only 2 parties
        let party_id = 0;
        let ready_state = DKGReadyState::new((*setup).clone(), party_id);
        let ctx = make_test_context();

        let mut start_setup = (*setup).clone();
        start_setup.start = true;
        let msg = SignedDKGSetupMessage::sign(Arc::new(start_setup), 0, &ctx.sk);

        let boxed_state: Box<dyn DKGInternalState> = ready_state;
        let (new_state, res) = boxed_state.receive_setup_msg(&ctx, msg);

        // Should return error, state should NOT be running
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));
        assert_ne!(new_state.get_state(), DKGState::Running);
        // Should have reset start flag
        assert!(!new_state.get_setup().unwrap().start);
    }

    #[test]
    fn test_ready_receive_setup_start_success() {
        let (setup, _) = make_sample_setup(2, 2); // Threshold 2, 2 parties (enough)
        let party_id = 0;
        let ready_state = DKGReadyState::new((*setup).clone(), party_id);
        let ctx = make_test_context();

        let mut start_setup = (*setup).clone();
        start_setup.start = true;
        let msg = SignedDKGSetupMessage::sign(Arc::new(start_setup), 0, &ctx.sk);

        let boxed_state: Box<dyn DKGInternalState> = ready_state;
        let (new_state, res) = boxed_state.receive_setup_msg(&ctx, msg);

        assert!(res.is_ok());
        assert_eq!(new_state.get_state(), DKGState::Running);
    }

    #[test]
    fn test_wait_for_net_receive_valid_setup() {
        let (setup, _) = make_sample_setup(2, 3);
        let party_id = 0;
        let qr = QRData {
            instance: setup.instance,
            party_id: party_id,
            vk: setup.parties[party_id as usize].vk.clone(),
        };
        let wait_state = DKGWaitForNetState::new(Arc::new(qr));
        let ctx = make_test_context();

        let msg = SignedDKGSetupMessage::sign(setup.clone(), 0, &ctx.sk);

        let boxed_state: Box<dyn DKGInternalState> = wait_state;
        let (new_state, res) = boxed_state.receive_setup_msg(&ctx, msg);

        assert!(res.is_ok());
        assert_eq!(new_state.get_state(), DKGState::Ready);
        let new_setup = new_state.get_setup().unwrap();
        // Should have added ourselves
        assert_eq!(new_setup.parties.len(), setup.parties.len() + 1);
        assert_eq!(new_setup.parties.last().unwrap().friendly_name, "test");
    }

    #[test]
    fn test_wait_for_net_receive_invalid_setup() {
        let (setup, _) = make_sample_setup(2, 3);
        let party_id = 0;
        let mut qr = QRData {
            instance: setup.instance,
            party_id: party_id,
            vk: setup.parties[party_id as usize].vk.clone(),
        };
        qr.instance = InstanceId::from_entropy(); // Mismatch instance

        let wait_state = DKGWaitForNetState::new(Arc::new(qr));
        let ctx = make_test_context();

        let msg = SignedDKGSetupMessage::sign(setup.clone(), 0, &ctx.sk);

        let boxed_state: Box<dyn DKGInternalState> = wait_state;
        let (_, res) = boxed_state.receive_setup_msg(&ctx, msg);

        assert!(matches!(res, Err(GeneralError::InvalidInput(_))));
    }

    #[test]
    fn test_running_state_rejects_receive_setup() {
        let (setup, _) = make_sample_setup(2, 3);
        let running_state = DKGRunningState::new(setup.clone(), 0);
        let ctx = make_test_context();

        let msg = SignedDKGSetupMessage::sign(setup.clone(), 0, &ctx.sk);
        let boxed_state: Box<dyn DKGInternalState> = running_state;
        let (new_state, res) = boxed_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));

        // Ensure state is still running
        assert_eq!(new_state.get_state(), DKGState::Running);
    }

    #[test]
    fn test_running_state_rejects_start_dkg() {
        let (setup, _) = make_sample_setup(2, 3);
        let running_state = DKGRunningState::new(setup.clone(), 0);
        let ctx = make_test_context();

        let boxed_state: Box<dyn DKGInternalState> = running_state;
        let (_, res) = boxed_state.start_dkg(&ctx);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));
    }

    #[test]
    fn test_finished_state_rejects_receive_setup() {
        let (setup, _) = make_sample_setup(2, 3);
        let finished_state = DKGFinishedState::new(setup.clone(), Err(GeneralError::Cancelled), 0);
        let ctx = make_test_context();

        let msg = SignedDKGSetupMessage::sign(setup.clone(), 0, &ctx.sk);
        let boxed_state: Box<dyn DKGInternalState> = finished_state;
        let (new_state, res) = boxed_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));

        // Ensure state is still finished
        assert_eq!(new_state.get_state(), DKGState::Finished);
    }

    #[test]
    fn test_finished_state_rejects_start_dkg() {
        let (setup, _) = make_sample_setup(2, 3);
        let finished_state = DKGFinishedState::new(setup.clone(), Err(GeneralError::Cancelled), 0);
        let ctx = make_test_context();

        let boxed_state: Box<dyn DKGInternalState> = finished_state;
        let (_, res) = boxed_state.start_dkg(&ctx);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));
    }
}
