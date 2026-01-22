use std::sync::{Arc, RwLock};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use sl_dkls23::keygen::run as keygen_run;
use sl_dkls23::setup::keygen::SetupMessage as KeygenSetup;

use crate::error::GeneralError;
use crate::net::{create_network_relay, NetworkInterface};
use crate::types::*;

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

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
            party_id: 0,
            parties: vec![DeviceInfo::for_sk(name.to_string(), &context.sk)],
            start: false,
        };
        Self {
            state: RwLock::new(Some(DKGReadyState::new(setup))),
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
        Ok(Self::from_qr(name, qr_data, setup_if, dkg_if))
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
                .get_setup()
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
        let setup = {
            let guard = self.state.read().unwrap();
            let state = guard.as_ref().unwrap();
            if state.get_state() != DKGState::Running {
                // println!("{:?} Not Running!?!", self.context.friendly_name);
                return Err(GeneralError::InvalidState(
                    "Calculated state is running but stored state is not?".to_string(),
                ));
            }
            state.get_setup().unwrap()
        };

        // println!("{:?} Starting DKG", self.context.friendly_name);
        let res = self.do_dkg_internal(setup.clone()).await;
        // println!("{:?} DKG Complete?", self.context.friendly_name);

        let _ = self.do_state_fn(|_| (DKGFinishedState::new(setup, res), Ok(false)));
        Ok(())
    }
}

impl DKGNode {
    pub fn from_qr(
        name: &str,
        qr_data: QRData,
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
    async fn get_next_msg_interruptable(&self) -> Result<DKGSetupMessage, GeneralError> {
        let receive_fut = self.setup_if.receive();
        let stop_fut = self.await_msg_kick.notified();

        let data = tokio::select! {
            res = receive_fut => res?,
            _ = stop_fut => return Err(GeneralError::Cancelled),
        };
        DKGSetupMessage::try_from(data.as_slice())
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

    async fn do_dkg_internal(&self, setup: Arc<DKGSetupMessage>) -> Result<Keyshare, GeneralError> {
        // TODO: should maybe put a Mutex here to make sure it never runs twice?

        let vkrefs: Vec<&NodeVerifyingKey> = setup.parties.iter().map(|dev| &dev.vk).collect();
        let ranks = vec![0u8; setup.parties.len()];
        let setup_msg = KeygenSetup::new(
            setup.instance.into(),
            &self.context.sk,
            setup.party_id.into(),
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
            *guard = Some(new_state);
            (old_state_enum, new_state_enum, res, old_setup, new_setup)
        };

        // If the state_fn indicated to send an update to the network,
        // get the bytes here from the setup message.
        // Need to do this first or listeners may change things.
        let res = res.map(|send_update| {
            if send_update {
                new_setup.as_ref().map(|s| s.to_bytes()).unwrap_or_default()
            } else {
                vec![]
            }
        });

        // Update listeners of changes.
        self.notify_listeners(old_state_enum, new_state_enum);
        if old_setup != new_setup {
            if let Some(setup) = new_setup {
                self.notify_setup_listeners(setup);
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
#[derive(Clone, Debug, Serialize, Deserialize)]
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

impl QRData {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

// TODO: need signatures for this.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, uniffi::Object)]
pub struct DKGSetupMessage {
    pub instance: InstanceId,
    pub threshold: u8,
    pub party_id: u8,
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

    pub fn get_my_party_id(&self) -> u8 {
        self.party_id
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

    fn add_ourself(&mut self, name: &str, sk: &NodeSecretKey) -> &mut Self {
        // add ourselves to the list of parties.
        self.party_id = self.parties.len() as u8;
        self.parties.push(DeviceInfo::for_sk(name.to_string(), sk));
        self
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
        setup_msg: DKGSetupMessage,
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
    qr_data: QRData,
}

impl DKGWaitForNetState {
    fn new(qr_data: QRData) -> Box<Self> {
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
        mut setup_msg: DKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        if let Err(e) = setup_msg.verify_qr(&self.qr_data) {
            return (self, Err(e));
        }
        setup_msg.add_ourself(&context.friendly_name, &context.sk);

        // Always have to send an update to the network.
        (DKGReadyState::new(setup_msg), Ok(true))
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
}

impl DKGReadyState {
    fn new(setup: DKGSetupMessage) -> Box<Self> {
        Box::new(Self {
            setup: Arc::new(setup),
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

    fn get_qr(&self) -> Result<QRData, GeneralError> {
        Ok(QRData {
            instance: self.setup.instance,
            party_id: self.setup.party_id,
            vk: self.setup.parties[self.setup.party_id as usize].vk.clone(),
        })
    }

    fn get_setup(&self) -> Result<Arc<DKGSetupMessage>, GeneralError> {
        Ok(self.setup.clone())
    }

    fn scan_qr(&mut self, qr_data: QRData) -> Result<(), GeneralError> {
        Arc::make_mut(&mut self.setup).verify_qr(&qr_data)
    }

    fn receive_setup_msg(
        self: Box<Self>,
        _context: &DKGContext,
        mut setup_msg: DKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        if let Err(e) = setup_msg.verify_existing(&self.setup) {
            return (self, Err(e));
        }
        setup_msg.party_id = self.setup.party_id;

        // Check if we got the start flag, and if so
        // check that we have enough parties to start.
        if setup_msg.start {
            // println!("{} received start flag", _context.friendly_name);
            if setup_msg.parties.len() < setup_msg.threshold as usize {
                setup_msg.start = false;
                return (
                    Self::new(setup_msg),
                    Err(GeneralError::InvalidState(
                        "Not enough parties to start DKG.".to_string(),
                    )),
                );
            }
            // TODO: does this need to be true?
            (DKGRunningState::new(Arc::new(setup_msg)), Ok(false))
        } else {
            (Self::new(setup_msg), Ok(false))
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
            (DKGRunningState::new(self.setup), Ok(true))
        }
    }
}

/*****************************************************************************
 * Running state.
 * DKG is running, can't get any intermediate results.
 *****************************************************************************/

struct DKGRunningState {
    setup: Arc<DKGSetupMessage>,
}

impl DKGRunningState {
    fn new(setup: Arc<DKGSetupMessage>) -> Box<Self> {
        Box::new(Self { setup })
    }
}

impl DKGInternalState for DKGRunningState {
    fn get_state(&self) -> DKGState {
        DKGState::Running
    }

    fn get_setup(&self) -> Result<Arc<DKGSetupMessage>, GeneralError> {
        Ok(self.setup.clone())
    }

    fn receive_setup_msg(
        self: Box<Self>,
        _context: &DKGContext,
        _setup_msg: DKGSetupMessage,
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
}

impl DKGFinishedState {
    fn new(setup: Arc<DKGSetupMessage>, result: Result<Keyshare, GeneralError>) -> Box<Self> {
        Box::new(Self { setup, result })
    }
}

impl DKGInternalState for DKGFinishedState {
    fn get_state(&self) -> DKGState {
        DKGState::Finished
    }

    fn get_qr(&self) -> Result<QRData, GeneralError> {
        Ok(QRData {
            instance: self.setup.instance,
            party_id: self.setup.party_id,
            vk: self.setup.parties[self.setup.party_id as usize].vk.clone(),
        })
    }

    fn get_setup(&self) -> Result<Arc<DKGSetupMessage>, GeneralError> {
        Ok(self.setup.clone())
    }

    fn receive_setup_msg(
        self: Box<Self>,
        _context: &DKGContext,
        _setup_msg: DKGSetupMessage,
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

        let qr = nodes[0].get_qr().unwrap();
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

    #[tokio::test]
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
        setup_msg.add_ourself("OtherNode", &other_sk);

        // 3. Send it back.
        other_conn.send(setup_msg.to_bytes()).await.unwrap();

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
}
