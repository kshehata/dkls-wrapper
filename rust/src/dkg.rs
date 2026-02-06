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
    fn on_setup_changed(&self, devices: DeviceList, my_id: u8);
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
        let devices = vec![context.dev.clone()];
        Self {
            state: RwLock::new(Some(DKGReadyState::new(devices, 0, threshold))),
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
        if let Ok((devices, my_id)) = self
            .state
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .get_device_list()
        {
            listener.on_setup_changed(devices, my_id);
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

    pub fn get_local_data(&self) -> Result<DeviceLocalData, GeneralError> {
        let guard = self.state.read().unwrap();
        let state = guard.as_ref().unwrap();
        let keyshare = state.get_result()?;
        let (devices, my_index) = state.get_device_list()?;
        Ok(DeviceLocalData {
            keyshare,
            my_index,
            sk: self.context.sk.clone(),
            devices,
        })
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
        if self.get_state() == DKGState::WaitForDevices
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
                Err(GeneralError::InvalidSetupMessage) => {
                    println!("Ignoring invalid setup message.");
                    continue;
                }
                Err(GeneralError::Cancelled) => break,
                res => res?,
            }
        }
        // Start the actual DKG
        let (devices, device_index) = {
            let guard = self.state.read().unwrap();
            let state = guard.as_ref().unwrap();
            if state.get_state() != DKGState::Running {
                // println!("{:?} Not Running!?!", self.context.friendly_name);
                return Err(GeneralError::InvalidState(
                    "Calculated state is running but stored state is not?".to_string(),
                ));
            }
            state.get_device_list().unwrap()
        };

        // println!("{:?} Starting DKG", self.context.friendly_name);
        let res = self.do_dkg_internal(&devices, device_index).await;
        // println!("{:?} DKG Complete?", self.context.friendly_name);

        let _ =
            self.do_state_fn(|_| (DKGFinishedState::new(devices, res, device_index), Ok(false)));
        Ok(())
    }
}

impl DKGNode {
    pub fn get_qr(&self) -> Result<QRData, GeneralError> {
        let qr = QRData {
            instance: self.context.instance.clone(),
            threshold: self.context.threshold,
            device_index: self
                .state
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .my_device_index()?,
            vk: self.context.dev.vk.clone(),
        };
        Ok(qr)
    }

    pub fn receive_qr(&self, qr: QRData) -> Result<(), GeneralError> {
        let (devices, my_id) = self.state.write().unwrap().as_mut().unwrap().scan_qr(&qr)?;
        self.notify_setup_listeners(devices, my_id);
        Ok(())
    }

    pub fn get_device_list(&self) -> Result<(DeviceList, u8), GeneralError> {
        self.state
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .get_device_list()
            .clone()
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
        devices: &DeviceList,
        device_index: u8,
    ) -> Result<Keyshare, GeneralError> {
        // TODO: should maybe put a Mutex here to make sure it never runs twice?

        let vkrefs: Vec<&NodeVerifyingKey> = devices.iter().map(|dev| &dev.vk).collect();
        let ranks = vec![0u8; devices.len() as usize];
        let setup_msg = KeygenSetup::new(
            self.context.instance.into(),
            &self.context.sk,
            device_index.into(),
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
        let (old_state_enum, new_state_enum, res, old_devices, new_devices) = {
            let mut guard = self.state.write().unwrap();
            let current_state = guard.take().unwrap();
            let old_state_enum = current_state.get_state();
            let old_devices = current_state.get_device_list().ok();
            let (new_state, res) = f(current_state);
            let new_state_enum = new_state.get_state();
            let new_devices = new_state.get_device_list().ok();

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
                old_devices,
                new_devices,
            )
        };

        // Update listeners of changes.
        self.notify_listeners(old_state_enum, new_state_enum);
        if let Some((devices, my_id)) = new_devices {
            match old_devices {
                Some((d2, _)) if d2 == devices => (),
                _ => self.notify_setup_listeners(devices, my_id),
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

    fn notify_setup_listeners(&self, devices: DeviceList, my_id: u8) {
        let listeners = self.setup_listeners.read().unwrap();
        for listener in listeners.iter() {
            listener.on_setup_changed(devices.clone(), my_id);
        }
    }
}

/*****************************************************************************
 * Messages
 *****************************************************************************/

// QR Code data for setting up DKG.
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Object)]
pub struct QRData {
    // TODO: should make all of these read-only.
    pub instance: InstanceId,
    pub threshold: u8,
    pub device_index: u8,
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

    pub fn get_device_index(&self) -> u8 {
        self.device_index
    }

    pub fn get_vk(&self) -> NodeVerifyingKey {
        self.vk.clone()
    }
}

// Wrapper around DeviceInfo so we can serialize it without
// the verified bit and makes it easy to compare.
// We need to store Arc<DeviceInfo> to pass to UniFFI anyway,
// so might as well just wrap that instead of using Cow.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct DeviceNetTransfer<'a> {
    friendly_name: Cow<'a, String>,
    vk: Cow<'a, NodeVerifyingKey>,
}

impl<'a> From<&'a DeviceInfo> for DeviceNetTransfer<'a> {
    fn from(value: &'a DeviceInfo) -> Self {
        Self {
            friendly_name: Cow::Borrowed(&value.friendly_name),
            vk: Cow::Borrowed(&value.vk),
        }
    }
}

impl<'a> From<DeviceNetTransfer<'a>> for DeviceInfo {
    fn from(value: DeviceNetTransfer<'a>) -> Self {
        DeviceInfo::new(value.friendly_name.into_owned(), value.vk.into_owned())
    }
}

impl<'a> PartialEq<DeviceInfo> for DeviceNetTransfer<'a> {
    fn eq(&self, other: &DeviceInfo) -> bool {
        self.friendly_name.as_ref() == &other.friendly_name && self.vk.as_ref() == &other.vk
    }
}

fn verify_qr(list: &mut DeviceList, qr: &QRData) -> Result<(), GeneralError> {
    if list.len() <= qr.device_index as usize || list[qr.device_index as usize].vk != qr.vk {
        return Err(GeneralError::InvalidInput(
            "Setup and QR mismatch".to_string(),
        ));
    }
    Arc::make_mut(&mut list[qr.device_index as usize]).verified = true;

    Ok(())
}

// Checks that all of the devices in the first list match the beginning of the second.
fn list_prefix_matches(list: &DeviceList, new_list: &[DeviceNetTransfer]) -> bool {
    (new_list.len() >= list.len())
        && list
            .iter()
            .zip(new_list.iter())
            .all(|(a, b)| b == a.as_ref())
}

// Check that the two lists match exactly other than the verified bit.
fn list_matches(list: &DeviceList, new_list: &[DeviceNetTransfer]) -> bool {
    (new_list.len() == list.len())
        && list
            .iter()
            .zip(new_list.iter())
            .all(|(a, b)| b == a.as_ref())
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
enum DKGSetupMessageType {
    Join,
    Confirm,
    Start,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct DKGSetupMessage<'a> {
    msg_type: DKGSetupMessageType,
    instance: Cow<'a, InstanceId>,
    threshold: u8,
    devices: Vec<DeviceNetTransfer<'a>>,
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
    pub fn make_join(instance: &'a InstanceId, threshold: u8, device: &'a DeviceInfo) -> Self {
        Self {
            msg_type: DKGSetupMessageType::Join,
            instance: Cow::Borrowed(instance),
            threshold,
            devices: vec![device.into()],
        }
    }

    pub fn make_confirm(instance: &'a InstanceId, threshold: u8, devices: &'a DeviceList) -> Self {
        Self {
            msg_type: DKGSetupMessageType::Confirm,
            instance: Cow::Borrowed(instance),
            threshold,
            devices: devices.iter().map(|d| d.as_ref().into()).collect(),
        }
    }

    pub fn make_start(instance: &'a InstanceId, threshold: u8, devices: &'a DeviceList) -> Self {
        Self {
            msg_type: DKGSetupMessageType::Start,
            instance: Cow::Borrowed(instance),
            threshold,
            devices: devices.iter().map(|d| d.as_ref().into()).collect(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct SignedDKGSetupMessage<'a> {
    setup: DKGSetupMessage<'a>,
    device_index: u8,
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

    pub fn from_sig(setup: DKGSetupMessage<'a>, device_index: u8, sig: Cow<'a, Signature>) -> Self {
        Self {
            setup,
            device_index,
            sig,
        }
    }

    pub fn sign(setup: DKGSetupMessage<'a>, device_index: u8, sk: &NodeSecretKey) -> Self {
        let sig = Signature(sk.try_sign(setup.to_bytes().as_ref()).unwrap());
        Self {
            setup,
            device_index,
            sig: Cow::Owned(sig),
        }
    }

    pub fn gen_sig(setup: &DKGSetupMessage, sk: &NodeSecretKey) -> Signature {
        Signature(sk.try_sign(setup.to_bytes().as_ref()).unwrap())
    }

    pub fn make_confirm(devices: &'a DeviceList, device_index: u8, ctx: &'a DKGContext) -> Self {
        let setup = DKGSetupMessage::make_confirm(&ctx.instance, ctx.threshold, devices);
        Self::sign(setup, device_index, &ctx.sk)
    }

    pub fn make_start(devices: &'a DeviceList, device_index: u8, ctx: &'a DKGContext) -> Self {
        let setup = DKGSetupMessage::make_start(&ctx.instance, ctx.threshold, devices);
        Self::sign(setup, device_index, &ctx.sk)
    }

    pub fn verify(&self) -> Result<(), GeneralError> {
        Self::verify_for_setup(&self.setup, self.device_index as usize, &self.sig)
    }

    // Helper to verify a signature without constructing a SignedDKGSetupMessage.
    pub fn verify_for_setup(
        setup: &DKGSetupMessage,
        device_index: usize,
        sig: &Signature,
    ) -> Result<(), GeneralError> {
        // Only in the case of a join message we have to check that only 1 device is in the list.
        if setup.msg_type == DKGSetupMessageType::Join
            && (device_index != 0 || setup.devices.len() != 1)
        {
            return Err(GeneralError::InvalidInput(
                "Invalid join message".to_string(),
            ));
        }
        let Some(dev) = setup.devices.get(device_index) else {
            return Err(GeneralError::InvalidInput(
                "Invalid device index".to_string(),
            ));
        };
        dev.vk.verify(setup.to_bytes().as_ref(), sig)
    }
}

/*****************************************************************************
 * DKG State Machine
 *****************************************************************************/

#[derive(Debug, PartialEq, Clone, Copy, uniffi::Enum)]
pub enum DKGState {
    WaitForSetup,
    WaitForSigs,
    WaitForDevices,
    Ready,
    Running,
    Finished,
}

struct DKGContext {
    instance: InstanceId,
    threshold: u8,
    dev: Arc<DeviceInfo>,
    sk: NodeSecretKey,
}

impl DKGContext {
    fn new(instance: InstanceId, threshold: u8, friendly_name: String, sk: NodeSecretKey) -> Self {
        let mut dev = DeviceInfo::for_sk(friendly_name, &sk);
        dev.verified = true;
        Self {
            instance,
            threshold,
            dev: Arc::new(dev),
            sk,
        }
    }
}

trait DKGInternalState: Send + Sync + 'static {
    fn get_state(&self) -> DKGState;

    fn my_device_index(&self) -> Result<u8, GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot get device index in current state.".to_string(),
        ))
    }

    // Get the list of devices, and the index of this device in the list.
    // DeviceList is a vector of arcs, so it's cheap to clone.
    // We'll usually return a clone of what's in the state var.
    fn get_device_list(&self) -> Result<(DeviceList, u8), GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot get device list in current state.".to_string(),
        ))
    }

    // Used for getting setup message to send to the network.
    fn get_bytes_to_send(&self, _context: &DKGContext) -> Result<Vec<u8>, GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot get setup handle in current state.".to_string(),
        ))
    }

    // We scanned a QR code of another device. Update the device list,
    // and return it here so we can update the UI.
    fn scan_qr(&mut self, _: &QRData) -> Result<(DeviceList, u8), GeneralError> {
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
        let join_msg =
            DKGSetupMessage::make_join(&context.instance, context.threshold, &context.dev);
        // Join messages use device_index 0 (ignored).
        let msg = SignedDKGSetupMessage::sign(join_msg, 0, &context.sk);
        Ok(msg.to_bytes())
    }

    fn receive_setup_msg(
        self: Box<Self>,
        context: &DKGContext,
        setup_msg: SignedDKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        // Instance ID must match scanned QR.
        // (This should have been checked already, but being defensive.)
        if setup_msg.setup.instance.as_ref() != &context.instance {
            return (self, Err(GeneralError::InvalidSetupMessage));
        }

        // Make sure this is confirmation and get details.
        if setup_msg.setup.msg_type != DKGSetupMessageType::Confirm {
            return (self, Err(GeneralError::InvalidSetupMessage));
        }

        // Verify inviter is in devices (sanity check)
        let devices = setup_msg.setup.devices;
        if self.qr_data.device_index as usize >= devices.len()
            || devices[self.qr_data.device_index as usize].vk.as_ref() != &self.qr_data.vk
        {
            return (self, Err(GeneralError::InvalidSetupMessage));
        }

        // Find ourselves
        let Some(my_device_index) = devices
            .iter()
            .position(|p| p.vk.as_ref() == &context.dev.vk)
        else {
            return (self, Err(GeneralError::InvalidSetupMessage));
        };

        // This should be impossible: our device index matches the sender's device index.
        if my_device_index == setup_msg.device_index as usize {
            return (self, Err(GeneralError::InvalidSetupMessage));
        }

        // Convert the list into a Vec<DeviceInfo>.
        // TODO: might be slightly more efficient if we do all 3 steps in one pass ?
        let mut devices: Vec<DeviceInfo> = devices.into_iter().map(|d| d.into()).collect();

        // Mark both ourselves and the inviter as verified.
        devices[my_device_index].verified = true;
        devices[self.qr_data.device_index as usize].verified = true;

        // And then convert to Arcs
        let devices: DeviceList = devices.into_iter().map(Arc::new).collect();

        // If there are only two devices, then we already have all sigs needed.
        let state: Box<dyn DKGInternalState> = if devices.len() == 2 {
            DKGReadyState::new(devices, my_device_index as u8, context.threshold)
        } else {
            // Create the new state with our signature.
            let mut new_state = DKGWaitForSigs::new(devices, my_device_index as u8, context);
            // Add the received signature.
            new_state.add_signature(setup_msg.device_index, setup_msg.sig.into_owned());
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
    devices: DeviceList,
    device_index: u8,
    signatures: Vec<Option<Signature>>,
}

impl DKGWaitForSigs {
    fn new(devices: DeviceList, device_index: u8, ctx: &DKGContext) -> Box<Self> {
        let num_devices = devices.len();
        let my_sig = {
            let setup = DKGSetupMessage::make_confirm(&ctx.instance, ctx.threshold, &devices);
            SignedDKGSetupMessage::gen_sig(&setup, &ctx.sk)
        };
        let mut state = Box::new(Self {
            devices,
            device_index,
            signatures: vec![None; num_devices as usize],
        });
        // Sign the proposal ourselves.
        state.add_signature(device_index, my_sig);
        state
    }

    fn add_signature(&mut self, device_index: u8, sig: Signature) {
        // TODO: should we flag this is out of bounds ?
        if (device_index as usize) < self.signatures.len() {
            self.signatures[device_index as usize] = Some(sig);
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

    fn my_device_index(&self) -> Result<u8, GeneralError> {
        Ok(self.device_index)
    }

    fn get_device_list(&self) -> Result<(DeviceList, u8), GeneralError> {
        Ok((self.devices.clone(), self.device_index))
    }

    fn get_bytes_to_send(&self, ctx: &DKGContext) -> Result<Vec<u8>, GeneralError> {
        let setup = DKGSetupMessage::make_confirm(&ctx.instance, ctx.threshold, &self.devices);
        let msg = SignedDKGSetupMessage::from_sig(
            setup,
            self.device_index,
            Cow::Borrowed(
                self.signatures[self.device_index as usize]
                    .as_ref()
                    .unwrap(),
            ),
        );
        Ok(msg.to_bytes())
    }

    fn scan_qr(&mut self, qr_data: &QRData) -> Result<(DeviceList, u8), GeneralError> {
        verify_qr(&mut self.devices, qr_data)?;
        Ok((self.devices.clone(), self.device_index))
    }

    fn receive_setup_msg(
        mut self: Box<Self>,
        ctx: &DKGContext,
        setup_msg: SignedDKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        // Instance and threshold should be checked vs context in DKGNode.

        // Cannot handle joins or start in this state.
        if setup_msg.setup.msg_type != DKGSetupMessageType::Confirm {
            return (self, Err(GeneralError::InvalidSetupMessage));
        }

        // New details must match exactly.
        if !list_matches(&self.devices, setup_msg.setup.devices.as_ref()) {
            return (self, Err(GeneralError::InvalidSetupMessage));
        }

        self.add_signature(setup_msg.device_index, setup_msg.sig.into_owned());

        if self.has_all_signatures() {
            let ready = DKGReadyState::new(self.devices, self.device_index, ctx.threshold);
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
    devices: DeviceList,
    device_index: u8,
    threshold: u8,
}

impl DKGReadyState {
    fn new(devices: DeviceList, device_index: u8, threshold: u8) -> Box<Self> {
        Box::new(Self {
            devices,
            device_index,
            threshold,
        })
    }
}

impl DKGInternalState for DKGReadyState {
    fn get_state(&self) -> DKGState {
        if self.devices.len() < self.threshold.into() {
            DKGState::WaitForDevices
        } else {
            DKGState::Ready
        }
    }

    fn my_device_index(&self) -> Result<u8, GeneralError> {
        Ok(self.device_index)
    }

    fn get_device_list(&self) -> Result<(DeviceList, u8), GeneralError> {
        Ok((self.devices.clone(), self.device_index))
    }

    fn get_bytes_to_send(&self, ctx: &DKGContext) -> Result<Vec<u8>, GeneralError> {
        let msg = SignedDKGSetupMessage::make_confirm(&self.devices, self.device_index, &ctx);
        Ok(msg.to_bytes())
    }

    fn scan_qr(&mut self, qr_data: &QRData) -> Result<(DeviceList, u8), GeneralError> {
        verify_qr(&mut self.devices, qr_data)?;
        Ok((self.devices.clone(), self.device_index))
    }

    fn receive_setup_msg(
        mut self: Box<Self>,
        context: &DKGContext,
        mut setup_msg: SignedDKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        // Instance and threshold should be checked vs context in DKGNode.

        match setup_msg.setup.msg_type {
            DKGSetupMessageType::Join => {
                // Assume sig is already verified, and that index and length are correct.
                self.devices
                    .push(Arc::new(setup_msg.setup.devices.pop().unwrap().into()));
                let state = DKGWaitForSigs::new(self.devices, self.device_index, context);
                (state, Ok(true))
            }

            DKGSetupMessageType::Confirm => {
                // Reject if devices somehow differ, since at this point all
                // devices should have been confirmed.
                if !list_prefix_matches(&self.devices, &setup_msg.setup.devices) {
                    return (self, Err(GeneralError::InvalidSetupMessage));
                }
                match setup_msg.setup.devices.len() - self.devices.len() {
                    0 => {
                        // Somehow got an extra confirmation message ?
                        return (self, Ok(false));
                    }
                    1 => {
                        // Got a confirmation before the join message.
                        // Just move to the wait for sigs state state.
                        self.devices
                            .push(Arc::new(setup_msg.setup.devices.pop().unwrap().into()));
                        let mut state =
                            DKGWaitForSigs::new(self.devices, self.device_index, context);
                        state.add_signature(setup_msg.device_index, setup_msg.sig.into_owned());
                        return (state, Ok(true));
                    }
                    _ => {
                        // Differ by more than 1 device, not allowed.
                        return (self, Err(GeneralError::InvalidSetupMessage));
                    }
                }
            }
            DKGSetupMessageType::Start => {
                // Check details match
                if !list_matches(&self.devices, &setup_msg.setup.devices) {
                    return (self, Err(GeneralError::InvalidSetupMessage));
                }
                if self.devices.len() < context.threshold as usize {
                    return (
                        self,
                        Err(GeneralError::InvalidState("Not enough devices".to_string())),
                    );
                }
                (
                    DKGRunningState::new(self.devices, self.device_index),
                    Ok(false),
                )
            }
        }
    }

    fn start_dkg(
        self: Box<Self>,
        ctx: &DKGContext,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        if self.devices.len() < ctx.threshold.into() {
            (
                self,
                Err(GeneralError::InvalidState(
                    "Not enough devices to start DKG.".to_string(),
                )),
            )
        } else {
            (
                DKGRunningState::new(self.devices, self.device_index),
                Ok(true),
            )
        }
    }
}

/*****************************************************************************
 * Running state.
 * DKG is running, can't get any intermediate results.
 *****************************************************************************/

struct DKGRunningState {
    devices: DeviceList,
    device_index: u8,
}

impl DKGRunningState {
    fn new(devices: DeviceList, device_index: u8) -> Box<Self> {
        Box::new(Self {
            devices,
            device_index,
        })
    }
}

impl DKGInternalState for DKGRunningState {
    fn get_state(&self) -> DKGState {
        DKGState::Running
    }

    fn my_device_index(&self) -> Result<u8, GeneralError> {
        Ok(self.device_index)
    }

    fn get_device_list(&self) -> Result<(DeviceList, u8), GeneralError> {
        Ok((self.devices.clone(), self.device_index))
    }

    fn get_bytes_to_send(&self, ctx: &DKGContext) -> Result<Vec<u8>, GeneralError> {
        let msg = SignedDKGSetupMessage::make_start(&self.devices, self.device_index, &ctx);
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
    devices: DeviceList,
    result: Result<Keyshare, GeneralError>,
    device_index: u8,
}

impl DKGFinishedState {
    fn new(
        devices: DeviceList,
        result: Result<Keyshare, GeneralError>,
        device_index: u8,
    ) -> Box<Self> {
        Box::new(Self {
            devices,
            result,
            device_index,
        })
    }
}

impl DKGInternalState for DKGFinishedState {
    fn get_state(&self) -> DKGState {
        DKGState::Finished
    }

    fn get_device_list(&self) -> Result<(DeviceList, u8), GeneralError> {
        Ok((self.devices.clone(), self.device_index))
    }

    fn my_device_index(&self) -> Result<u8, GeneralError> {
        Ok(self.device_index)
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
    async fn test_dkg_node_2_devices() {
        println!("Starting DKG Node 2 Device Test");
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

        assert_eq!(nodes[0].get_state(), DKGState::WaitForDevices);
        let mut state_watchers = vec![DKGStateReceiver::watch_node(&nodes[0])];

        let mut devices = tokio::task::JoinSet::new();
        spawn_node(&mut devices, nodes[0].clone());

        let qr = Arc::new(nodes[0].get_qr().unwrap());
        assert_eq!(qr.instance, instance);
        assert_eq!(qr.device_index, 0);
        // TODO: check vk

        nodes.push(Arc::new(DKGNode::from_qr(
            "Node2",
            qr.clone(),
            setup_coord.connect(),
            dkg_coord.connect(),
        )));

        assert_eq!(nodes[1].get_state(), DKGState::WaitForSetup);
        state_watchers.push(DKGStateReceiver::watch_node(&nodes[1]));
        spawn_node(&mut devices, nodes[1].clone());

        // Wait for both nodes to become ready.
        for watcher in &mut state_watchers {
            assert!(watcher.wait_for_state(DKGState::Ready, 2000).await);
        }

        // Check verification status
        assert!(nodes[0].get_device_list().unwrap().0[0].verified);
        assert!(!nodes[0].get_device_list().unwrap().0[1].verified);
        assert!(nodes[1].get_device_list().unwrap().0[0].verified);
        assert!(nodes[1].get_device_list().unwrap().0[1].verified);

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

        assert!(nodes[0].get_device_list().unwrap().0[0].verified);
        assert!(!nodes[0].get_device_list().unwrap().0[1].verified);
        assert!(nodes[1].get_device_list().unwrap().0[0].verified);
        assert!(nodes[1].get_device_list().unwrap().0[1].verified);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_node_3_devices() {
        println!("Starting DKG Node 3 Device Test");
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

        assert_eq!(nodes[0].get_state(), DKGState::WaitForDevices);
        let mut state_watchers = vec![DKGStateReceiver::watch_node(&nodes[0])];

        let mut devices = tokio::task::JoinSet::new();
        spawn_node(&mut devices, nodes[0].clone());

        let qr = Arc::new(nodes[0].get_qr().unwrap());
        assert_eq!(qr.instance, instance);
        assert_eq!(qr.device_index, 0);
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
            spawn_node(&mut devices, nodes[i].clone());

            // Wait for all nodes to become ready.
            let exp_state = if i < 2 {
                DKGState::WaitForDevices
            } else {
                DKGState::Ready
            };
            for watcher in &mut state_watchers {
                assert!(watcher.wait_for_state(exp_state, 2000).await);
            }
        }

        assert!(nodes[0].get_device_list().unwrap().0[0].verified);
        assert!(!nodes[0].get_device_list().unwrap().0[1].verified);
        assert!(!nodes[0].get_device_list().unwrap().0[2].verified);
        assert!(nodes[1].get_device_list().unwrap().0[0].verified);
        assert!(nodes[1].get_device_list().unwrap().0[1].verified);
        assert!(!nodes[1].get_device_list().unwrap().0[2].verified);
        assert!(nodes[2].get_device_list().unwrap().0[0].verified);
        assert!(!nodes[2].get_device_list().unwrap().0[1].verified);
        assert!(nodes[2].get_device_list().unwrap().0[2].verified);

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

        assert!(nodes[0].get_device_list().unwrap().0[0].verified);
        assert!(!nodes[0].get_device_list().unwrap().0[1].verified);
        assert!(!nodes[0].get_device_list().unwrap().0[2].verified);
        assert!(nodes[1].get_device_list().unwrap().0[0].verified);
        assert!(nodes[1].get_device_list().unwrap().0[1].verified);
        assert!(!nodes[1].get_device_list().unwrap().0[2].verified);
        assert!(nodes[2].get_device_list().unwrap().0[0].verified);
        assert!(!nodes[2].get_device_list().unwrap().0[1].verified);
        assert!(nodes[2].get_device_list().unwrap().0[2].verified);
    }

    #[test]
    fn test_join_wait_for_sigs() {
        let instance = InstanceId::from_entropy();
        let (mut devices, device_sks) = make_sample_devices(2);

        let qr = QRData {
            instance: instance.clone(),
            threshold: 2,
            device_index: 0,
            vk: devices[0].vk.clone(),
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

        devices.push(node3.context.dev.clone());

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_confirm(&instance, 2, &devices),
            0, // Signed by device 0
            &device_sks[0],
        );

        let _ = node3.test_handle_setup_msg(msg).unwrap();
        assert_eq!(node3.get_state(), DKGState::WaitForSigs);

        Arc::make_mut(&mut devices[0]).verified = true;
        Arc::make_mut(&mut devices[2]).verified = true;
        assert_eq!(node3.get_device_list().unwrap().0, devices);
    }

    /*****************************************************************************
     * Test Helpers.
     *****************************************************************************/

    fn make_sample_devices(n: u8) -> (DeviceList, Vec<Arc<NodeSecretKey>>) {
        let device_sks = (0..n)
            .map(|_| Arc::new(NodeSecretKey::from_entropy()))
            .collect::<Vec<_>>();
        (
            device_sks
                .iter()
                .enumerate()
                .map(|(i, sk)| Arc::new(DeviceInfo::for_sk(format!("Dev{}", i).to_string(), sk)))
                .collect::<DeviceList>(),
            device_sks,
        )
    }

    fn verify_devices(mut devices: DeviceList, id_list: &[usize]) -> DeviceList {
        for id in id_list {
            Arc::make_mut(&mut devices[*id]).verified = true;
        }
        devices
    }

    fn make_sample_setup_msg(t: u8, n: u8) -> (DKGSetupMessage<'static>, Vec<Arc<NodeSecretKey>>) {
        let device_sks = (0..n)
            .map(|_| Arc::new(NodeSecretKey::from_entropy()))
            .collect::<Vec<_>>();
        let devices = device_sks
            .iter()
            .enumerate()
            .map(|(i, sk)| DeviceNetTransfer {
                friendly_name: Cow::Owned(format!("Dev{}", i).to_string()),
                vk: Cow::Owned(NodeVerifyingKey::from_sk(sk)),
            })
            .collect::<Vec<_>>();
        let msg = DKGSetupMessage {
            msg_type: DKGSetupMessageType::Confirm,
            instance: Cow::Owned(InstanceId::from_entropy()),
            threshold: t,
            devices,
        };
        (msg, device_sks)
    }

    fn make_test_context(sk: &Arc<NodeSecretKey>) -> DKGContext {
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
        exp_device_index: u8,
        exp_devices: &DeviceList,
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
        assert_eq!(
            sent_msg.device_index, exp_device_index,
            "Device Index mismatch"
        );
        assert_eq!(
            sent_msg.setup.msg_type,
            DKGSetupMessageType::Confirm,
            "Expected Confirm message"
        );

        assert!(
            list_matches(exp_devices, sent_msg.setup.devices.as_ref()),
            "Device list mismatch"
        );
    }

    /*****************************************************************************
     * Simple tests of signed messages.
     *****************************************************************************/

    #[test]
    pub fn test_sign_dkg_setup_msg_ok() {
        let (setup, device_sks) = make_sample_setup_msg(3, 5);
        let signed = SignedDKGSetupMessage::sign(setup, 1, &device_sks[1]);
        assert!(signed.verify().is_ok());
    }

    #[test]
    pub fn test_sign_dkg_setup_msg_wrong_id() {
        let (setup, device_sks) = make_sample_setup_msg(3, 5);
        let signed = SignedDKGSetupMessage::sign(setup, 0, &device_sks[1]);
        assert!(signed.verify().is_err());
    }

    #[test]
    pub fn test_sign_dkg_setup_msg_invalid_id() {
        let (setup, device_sks) = make_sample_setup_msg(2, 3);
        let signed = SignedDKGSetupMessage::sign(setup, 3, &device_sks[0]);
        assert!(signed.verify().is_err());
    }

    /*****************************************************************************
     * Wait for Network State Tests.
     *****************************************************************************/

    #[test]
    fn test_wait_for_net_receive_valid_setup() {
        let (devices, device_sks) = make_sample_devices(3);
        let ctx = make_test_context(&device_sks[2]);

        let qr = QRData {
            instance: ctx.instance.clone(),
            threshold: 2,
            device_index: 0,
            vk: devices[0usize].vk.clone(),
        };
        let wait_state = DKGWaitForNetState::new(Arc::new(qr));

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_confirm(&ctx.instance, 2, &devices),
            1,
            &device_sks[1],
        );

        let (new_state, res) = wait_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Ok(true)));
        assert_eq!(new_state.get_state(), DKGState::WaitForSigs);
        assert!(matches!(new_state.my_device_index(), Ok(2)));
        expect_sent_msg(&new_state, &ctx, 2, &devices);

        let exp_devices = verify_devices(devices, &[0, 2]);
        let new_setup_devices = new_state.get_device_list().unwrap().0;
        assert_eq!(new_setup_devices.as_slice(), exp_devices.as_slice());
    }

    #[test]
    fn test_wait_for_net_receive_valid_setup_2_devices() {
        let (devices, device_sks) = make_sample_devices(2);
        let ctx = make_test_context(&device_sks[1]);

        let qr = QRData {
            instance: ctx.instance.clone(),
            threshold: 2,
            device_index: 0,
            vk: devices[0usize].vk.clone(),
        };
        let wait_state = DKGWaitForNetState::new(Arc::new(qr));

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_confirm(&ctx.instance, 2, &devices),
            0,
            &device_sks[0],
        );

        let (new_state, res) = wait_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Ok(true)));
        assert_eq!(new_state.get_state(), DKGState::Ready);
        assert!(matches!(new_state.my_device_index(), Ok(1)));
        expect_sent_msg(&new_state, &ctx, 1, &devices);

        let exp_devices = verify_devices(devices, &[0, 1]);
        let new_setup_devices = new_state.get_device_list().unwrap().0;
        assert_eq!(new_setup_devices.as_slice(), exp_devices.as_slice());
    }

    #[test]
    fn test_wait_for_net_receive_invalid_setup() {
        let (devices, device_sks) = make_sample_devices(3);
        let ctx = make_test_context(&device_sks[2]);

        let qr = QRData {
            instance: ctx.instance.clone(),
            threshold: 2,
            device_index: 0,
            vk: devices[0usize].vk.clone(),
        };
        let wait_state = DKGWaitForNetState::new(Arc::new(qr));

        let other_instance = InstanceId::from_entropy();
        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_confirm(&other_instance, 2, &devices),
            0,
            &device_sks[0],
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
        let (devices, device_sks) = make_sample_devices(3);
        let devices = verify_devices(devices, &[0, 1]);
        let ctx = make_test_context(&device_sks[1]);
        let wait_state: Box<dyn DKGInternalState> = DKGWaitForSigs::new(devices.clone(), 1, &ctx);
        assert_eq!(wait_state.get_state(), DKGState::WaitForSigs);
        assert_eq!(wait_state.get_device_list().unwrap(), (devices.clone(), 1));
        assert_eq!(wait_state.my_device_index().unwrap(), 1);
        expect_sent_msg(&wait_state, &ctx, 1, &devices);
    }

    #[test]
    fn test_wait_for_sigs_receive_invalid_device_list() {
        let (devices, device_sks) = make_sample_devices(3);
        let ctx = make_test_context(&device_sks[1]);
        let wait_state = DKGWaitForSigs::new(devices.clone(), 1, &ctx);

        let (bad_devices, _) = make_sample_devices(3); // Different devices
        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_confirm(&ctx.instance, 2, &bad_devices),
            0,
            &device_sks[0],
        );

        let (new_state, res) = wait_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Err(GeneralError::InvalidSetupMessage)));
        assert_eq!(new_state.get_state(), DKGState::WaitForSigs);
    }

    #[test]
    fn test_wait_for_sigs_receive_setup_ok() {
        let (devices, device_sks) = make_sample_devices(3);
        let ctx = make_test_context(&device_sks[1]);
        let verified_devices = verify_devices(devices.clone(), &[0, 1]);
        // This creates a state where we are the only ones to have signed.
        let wait_state = DKGWaitForSigs::new(verified_devices.clone(), 1, &ctx);

        // Receive device 2 signature.
        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_confirm(&ctx.instance, 2, &devices),
            2,
            &device_sks[2],
        );

        let (new_state, res) = wait_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Ok(false)));
        assert_eq!(new_state.get_state(), DKGState::WaitForSigs);

        // make sure verified devices are set correctly
        // make sure verified devices are set correctly
        let final_devices = new_state.get_device_list().unwrap().0;
        assert!(final_devices[0].verified);
        assert!(final_devices[1].verified);
        assert!(!final_devices[2].verified);

        // Receive device 0 signature.
        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_confirm(&ctx.instance, 2, &devices),
            0,
            &device_sks[0],
        );

        let (new_state, res) = new_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Ok(false)));
        assert_eq!(new_state.get_state(), DKGState::Ready);

        // make sure verified devices are set correctly
        let final_devices = new_state.get_device_list().unwrap().0;
        assert!(final_devices[0].verified);
        assert!(final_devices[1].verified);
        assert!(!final_devices[2].verified);
    }

    /*****************************************************************************
     * Ready State Tests.
     *****************************************************************************/

    #[test]
    fn test_ready_state_basics() {
        let (devices, device_sks) = make_sample_devices(3);
        let ctx = make_test_context(&device_sks[1]);
        let ready_state: Box<dyn DKGInternalState> = DKGReadyState::new(devices.clone(), 1, 2);
        assert_eq!(ready_state.get_state(), DKGState::Ready);
        assert_eq!(ready_state.get_device_list().unwrap(), (devices.clone(), 1));
        assert_eq!(ready_state.my_device_index().unwrap(), 1);
        expect_sent_msg(&ready_state, &ctx, 1, &devices);
    }

    #[test]
    fn test_ready_receive_setup_consistency_incompatible_device_list_shorter() {
        let instance = InstanceId::from_entropy();
        let (devices, device_sks) = make_sample_devices(3);
        let ready_state = DKGReadyState::new(devices.clone(), 1, 2);
        let ctx = make_test_context(&device_sks[1]);

        let mut short_devices = devices.clone();
        short_devices.pop();
        let bad_msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_confirm(&instance, 2, &short_devices),
            0,
            &device_sks[0],
        );
        let (new_state, res) = ready_state.receive_setup_msg(&ctx, bad_msg);
        assert!(matches!(res, Err(GeneralError::InvalidSetupMessage)));
        assert_eq!(new_state.get_state(), DKGState::Ready);
    }

    #[test]
    fn test_ready_receive_setup_consistency_incompatible_device_list_different() {
        let instance = InstanceId::from_entropy();
        let (devices, device_sks) = make_sample_devices(3);
        let ready_state = DKGReadyState::new(devices.clone(), 1, 2);
        let ctx = make_test_context(&device_sks[1]);

        let (different_devices, _) = make_sample_devices(3);
        let bad_msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_confirm(&instance, 2, &different_devices),
            0,
            &device_sks[0],
        );

        let (new_state, res) = ready_state.receive_setup_msg(&ctx, bad_msg);
        assert!(matches!(res, Err(GeneralError::InvalidSetupMessage)));
        assert_eq!(new_state.get_state(), DKGState::Ready);
    }

    #[test]
    fn test_ready_receive_setup_add_device() {
        let (devices, device_sks) = make_sample_devices(3);
        let ctx = make_test_context(&device_sks[0]);

        let devices = verify_devices(devices, &[0, 1]);
        let short_devices = devices[..devices.len() - 1].to_vec();
        let ready_state = DKGReadyState::new(short_devices, 0, 2);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_confirm(&ctx.instance, 2, &devices),
            1,
            &device_sks[1],
        );

        let (new_state, res) = ready_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Ok(true)));
        assert_eq!(new_state.get_state(), DKGState::WaitForSigs);

        let (new_setup_devices, new_id) = new_state.get_device_list().unwrap();
        assert_eq!(new_id, 0);
        assert_eq!(new_setup_devices, devices);

        expect_sent_msg(&new_state, &ctx, 0, &devices);
    }

    #[test]
    fn test_ready_receive_setup_join_many_devices() {
        let (devices, device_sks) = make_sample_devices(3);
        let ctx = make_test_context(&device_sks[0]);

        let devices = verify_devices(devices, &[0, 1]);
        let short_devices = devices[..devices.len() - 1].to_vec();
        let ready_state = DKGReadyState::new(short_devices, 0, 2);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_join(&ctx.instance, 2, &devices[2]),
            0,
            &device_sks[2],
        );

        let (new_state, res) = ready_state.receive_setup_msg(&ctx, msg);

        assert!(matches!(res, Ok(true)));
        assert_eq!(new_state.get_state(), DKGState::WaitForSigs);

        expect_sent_msg(&new_state, &ctx, 0, &devices);

        let (new_setup_devices, new_id) = new_state.get_device_list().unwrap();
        assert_eq!(new_id, 0);
        assert_eq!(new_setup_devices, devices);

        expect_sent_msg(&new_state, &ctx, 0, &devices);
    }

    #[test]
    fn test_ready_receive_setup_start_not_enough_devices() {
        let (devices, device_sks) = make_sample_devices(2);
        let mut ctx = make_test_context(&device_sks[1]);
        ctx.threshold = 3;
        let instance = &ctx.instance;
        let ready_state = DKGReadyState::new(devices.clone(), 1, 3);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_start(&instance, 3, &devices),
            0,
            &device_sks[0],
        );

        let (new_state, res) = ready_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));
        assert_eq!(new_state.get_state(), DKGState::WaitForDevices);
    }

    #[test]
    fn test_ready_receive_setup_start_success() {
        let (devices, device_sks) = make_sample_devices(2);
        let ctx = make_test_context(&device_sks[0]);
        let devices = verify_devices(devices, &[0, 1]);
        let ready_state = DKGReadyState::new(devices.clone(), 0, 2);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_start(&ctx.instance, 2, &devices),
            1,
            &device_sks[1],
        );

        let (new_state, res) = ready_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Ok(false)));
        assert_eq!(new_state.get_state(), DKGState::Running);
        let (new_setup_devices, new_id) = new_state.get_device_list().unwrap();
        assert_eq!(new_id, 0);
        assert_eq!(new_setup_devices, devices);
    }

    /*****************************************************************************
     * Running State Tests.
     *****************************************************************************/

    #[test]
    fn test_running_state_basics() {
        let (devices, device_sks) = make_sample_devices(3);
        let ctx = make_test_context(&device_sks[0]);
        let running_state = DKGRunningState::new(devices.clone(), 0);
        assert_eq!(running_state.get_state(), DKGState::Running);
        let (new_setup_devices, new_id) = running_state.get_device_list().unwrap();
        assert_eq!(new_id, 0);
        assert_eq!(new_setup_devices, devices);

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
        assert_eq!(sent_msg.device_index, 0, "Device Index mismatch");
        if sent_msg.setup.msg_type != DKGSetupMessageType::Start {
            panic!("Expected Start message");
        };
        assert!(
            list_matches(&devices, &sent_msg.setup.devices),
            "Device list mismatch"
        );
    }

    #[test]
    fn test_running_state_rejects_receive_setup() {
        // This should never happen, but good to make sure it doesn't crash or something.
        let (devices, device_sks) = make_sample_devices(3);
        let ctx = make_test_context(&device_sks[0]);
        let running_state = DKGRunningState::new(devices.clone(), 0);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_confirm(&ctx.instance, 2, &devices),
            1,
            &device_sks[1],
        );

        let (new_state, res) = running_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));
        assert_eq!(new_state.get_state(), DKGState::Running);
    }

    #[test]
    fn test_running_state_rejects_start_dkg() {
        let (devices, device_sks) = make_sample_devices(3);
        let ctx = make_test_context(&device_sks[0]);
        let running_state = DKGRunningState::new(devices.clone(), 0);
        let (new_state, res) = running_state.start_dkg(&ctx);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));
        assert_eq!(new_state.get_state(), DKGState::Running);
    }

    /*****************************************************************************
     * Finished State Tests.
     *****************************************************************************/

    #[test]
    fn test_finished_state_basics() {
        let (devices, _) = make_sample_devices(3);
        let finished_state =
            DKGFinishedState::new(devices.clone(), Err(GeneralError::Cancelled), 0);
        assert_eq!(finished_state.get_state(), DKGState::Finished);
        assert_eq!(
            finished_state.get_device_list().unwrap(),
            (devices.clone(), 0)
        );
        assert_eq!(finished_state.my_device_index().unwrap(), 0);
        assert!(matches!(
            finished_state.get_result(),
            Err(GeneralError::Cancelled)
        ));
    }

    #[test]
    fn test_finished_state_rejects_receive_setup() {
        // This should never happen, but good to make sure it doesn't crash or something.
        let (devices, device_sks) = make_sample_devices(3);
        let ctx = make_test_context(&device_sks[0]);
        let finished_state =
            DKGFinishedState::new(devices.clone(), Err(GeneralError::Cancelled), 0);

        let msg = SignedDKGSetupMessage::sign(
            DKGSetupMessage::make_confirm(&ctx.instance, 2, &devices),
            1,
            &device_sks[1],
        );

        let (new_state, res) = finished_state.receive_setup_msg(&ctx, msg);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));
        assert_eq!(new_state.get_state(), DKGState::Finished);
    }

    #[test]
    fn test_finished_state_rejects_start_dkg() {
        let (devices, device_sks) = make_sample_devices(3);
        let ctx = make_test_context(&device_sks[0]);
        let finished_state =
            DKGFinishedState::new(devices.clone(), Err(GeneralError::Cancelled), 0);
        let (new_state, res) = finished_state.start_dkg(&ctx);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));
        assert_eq!(new_state.get_state(), DKGState::Finished);
    }
}
