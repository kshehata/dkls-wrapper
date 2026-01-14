use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sl_dkls23::keygen::run as keygen_run;
use sl_dkls23::setup::keygen::SetupMessage as KeygenSetup;
use sl_dkls23::Relay as NetworkRelay;

use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use crate::error::GeneralError;
use crate::types::*;

#[cfg(test)]
use mockall::automock;

/*****************************************************************************
 * Messages
 *****************************************************************************/

// TODO: need signatures for this.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DKGSetupMessage {
    pub instance: InstanceId,
    pub threshold: u8,
    pub party_id: u8,
    pub parties: Vec<DeviceInfo>,
    pub start: bool,
}

// QR Code data for setting up DKG.
// TODO: hash of setup or signature ?
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QRData {
    // TODO: should make all of these read-only.
    pub instance: InstanceId,
    pub party_id: u8,
    pub vk: NodeVerifyingKey,
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

impl DKGSetupMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    fn verify_qr(&mut self, qr: &QRData) -> Result<&mut Self, GeneralError> {
        if self.instance != qr.instance
            || self.parties.len() <= self.party_id as usize
            || self.parties[self.party_id as usize].vk != qr.vk
        {
            return Err(GeneralError::InvalidInput(
                "Setup and QR mismatch".to_string(),
            ));
        }
        self.parties[qr.party_id as usize].verified = true;

        Ok(self)
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

#[derive(Debug, PartialEq)]
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

    fn get_setup(&self) -> Result<&DKGSetupMessage, GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot get setup in current state.".to_string(),
        ))
    }

    fn scan_qr(
        self: Box<Self>,
        context: &DKGContext,
        qr_data: QRData,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>);

    fn receive_setup_msg(
        self: Box<Self>,
        context: &DKGContext,
        setup_msg: DKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>);

    fn start_dkg(
        self: Box<Self>,
        context: &DKGContext,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>);

    fn finish_dkg(
        self: Box<Self>,
        context: &DKGContext,
        result: Result<Keyshare, GeneralError>,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>);

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

    fn scan_qr(
        self: Box<Self>,
        _: &DKGContext,
        _: QRData,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot scan QR in current state.".to_string(),
            )),
        )
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
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot start from current state.".to_string(),
            )),
        )
    }

    fn finish_dkg(
        self: Box<Self>,
        _context: &DKGContext,
        _result: Result<Keyshare, GeneralError>,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot finish from current state.".to_string(),
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
    setup: DKGSetupMessage,
}

impl DKGReadyState {
    fn new(setup: DKGSetupMessage) -> Box<Self> {
        Box::new(Self { setup })
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

    fn get_setup(&self) -> Result<&DKGSetupMessage, GeneralError> {
        Ok(&self.setup)
    }

    fn scan_qr(
        self: Box<Self>,
        _: &DKGContext,
        qr_data: QRData,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        let mut setup = self.setup;
        let res = setup.verify_qr(&qr_data).map(|_| ());

        (Self::new(setup), res)
    }

    fn receive_setup_msg(
        self: Box<Self>,
        _context: &DKGContext,
        mut setup_msg: DKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<bool, GeneralError>) {
        if let Err(e) = setup_msg.verify_existing(&self.setup) {
            return (self, Err(e));
        }

        // Check if we got the start flag, and if so
        // check that we have enough parties to start.
        if setup_msg.start {
            if setup_msg.parties.len() < setup_msg.threshold as usize {
                setup_msg.start = false;
                return (
                    Self::new(setup_msg),
                    Err(GeneralError::InvalidState(
                        "Not enough parties to start DKG.".to_string(),
                    )),
                );
            }
            (DKGRunningState::new(setup_msg), Ok(true))
        } else {
            (Self::new(setup_msg), Ok(false))
        }
    }

    fn start_dkg(
        self: Box<Self>,
        _context: &DKGContext,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        if self.setup.parties.len() < self.setup.threshold as usize {
            (
                self,
                Err(GeneralError::InvalidState(
                    "Not enough parties to start DKG.".to_string(),
                )),
            )
        } else {
            let mut setup = self.setup;
            setup.start = true;
            (DKGRunningState::new(setup), Ok(()))
        }
    }

    fn finish_dkg(
        self: Box<Self>,
        _context: &DKGContext,
        _result: Result<Keyshare, GeneralError>,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot finish from current state.".to_string(),
            )),
        )
    }
}

/*****************************************************************************
 * Running state.
 * DKG is running, can't get any intermediate results.
 *****************************************************************************/

struct DKGRunningState {
    setup: DKGSetupMessage,
}

impl DKGRunningState {
    fn new(setup: DKGSetupMessage) -> Box<Self> {
        Box::new(Self { setup })
    }
}

impl DKGInternalState for DKGRunningState {
    fn get_state(&self) -> DKGState {
        DKGState::Running
    }

    // This should only be used for testing!
    fn get_setup(&self) -> Result<&DKGSetupMessage, GeneralError> {
        Ok(&self.setup)
    }

    fn scan_qr(
        self: Box<Self>,
        _: &DKGContext,
        _: QRData,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot scan QR in current state.".to_string(),
            )),
        )
    }

    fn receive_setup_msg(
        self: Box<Self>,
        _context: &DKGContext,
        mut setup_msg: DKGSetupMessage,
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
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "DKG already started.".to_string(),
            )),
        )
    }

    fn finish_dkg(
        self: Box<Self>,
        _context: &DKGContext,
        result: Result<Keyshare, GeneralError>,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        (DKGFinishedState::new(self.setup, result), Ok(()))
    }
}

/*****************************************************************************
 * Finished state.
 * Really just provides access to the result and marks the DKG as finished.
 *****************************************************************************/

struct DKGFinishedState {
    setup: DKGSetupMessage,
    result: Result<Keyshare, GeneralError>,
}

impl DKGFinishedState {
    fn new(setup: DKGSetupMessage, result: Result<Keyshare, GeneralError>) -> Box<Self> {
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

    fn get_setup(&self) -> Result<&DKGSetupMessage, GeneralError> {
        Ok(&self.setup)
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

    fn scan_qr(
        self: Box<Self>,
        _: &DKGContext,
        _: QRData,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot scan QR in current state.".to_string(),
            )),
        )
    }

    fn start_dkg(
        self: Box<Self>,
        _: &DKGContext,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot start from current state.".to_string(),
            )),
        )
    }

    fn finish_dkg(
        self: Box<Self>,
        _context: &DKGContext,
        _result: Result<Keyshare, GeneralError>,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState("Already finished.".to_string())),
        )
    }

    fn get_result(&self) -> Result<Keyshare, GeneralError> {
        self.result.clone()
    }
}

/*****************************************************************************
 * Actual DKG Node.
 *****************************************************************************/

// #[derive(uniffi::Object)]
pub struct DKGNode {
    // Need interior mutability for state,
    // Option so that we can replace it dynamically.
    state: RwLock<Option<Box<dyn DKGInternalState>>>,
    context: DKGContext,
    setup_if: Arc<dyn NetworkInterface>,
    dkg_if: Arc<dyn NetworkInterface>,
}

impl DKGNode {
    pub fn new(
        name: &str,
        instance: InstanceId,
        threshold: u8,
        setup_if: Arc<dyn NetworkInterface>,
        dkg_if: Arc<dyn NetworkInterface>,
    ) -> Self {
        let context = DKGContext {
            friendly_name: name.to_string(),
            sk: NodeSecretKey::from_entropy(),
        };
        let setup = DKGSetupMessage {
            instance,
            threshold,
            party_id: 0,
            parties: vec![DeviceInfo::for_sk(name.to_string(), &context.sk)],
            start: false,
        };
        Self {
            state: RwLock::new(Some(DKGReadyState::new(setup))),
            context,
            setup_if,
            dkg_if,
        }
    }

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
            context,
            setup_if,
            dkg_if,
        }
    }

    pub fn get_state(&self) -> DKGState {
        self.state.read().unwrap().as_ref().unwrap().get_state()
    }

    pub fn get_qr(&self) -> Result<QRData, GeneralError> {
        self.state.read().unwrap().as_ref().unwrap().get_qr()
    }

    pub fn get_result(&self) -> Result<Keyshare, GeneralError> {
        self.state.read().unwrap().as_ref().unwrap().get_result()
    }

    pub fn receive_qr(&self, qr: QRData) -> Result<(), GeneralError> {
        let mut guard = self.state.write().unwrap();
        let current_state = guard.take().unwrap();
        let (new_state, res) = current_state.scan_qr(&self.context, qr);
        *guard = Some(new_state);
        res
    }

    // Shortcut to receive and parse a setup message.
    async fn get_next_setup_msg(&self) -> Result<DKGSetupMessage, GeneralError> {
        let data = self.setup_if.receive().await?;
        DKGSetupMessage::try_from(data.as_slice())
    }

    async fn process_next_setup_msg(&self) -> Result<(), GeneralError> {
        let setup_msg = self.get_next_setup_msg().await?;
        let bytes_to_send = self.receive_setup_msg_internal(setup_msg)?;
        if !bytes_to_send.is_empty() {
            self.setup_if.send(bytes_to_send).await?;
        }
        Ok(())
    }

    fn receive_setup_msg_internal(
        &self,
        setup_msg: DKGSetupMessage,
    ) -> Result<Vec<u8>, GeneralError> {
        let mut guard = self.state.write().unwrap();
        let current_state = guard.take().unwrap();
        let (new_state, res) = current_state.receive_setup_msg(&self.context, setup_msg);
        let bytes_to_send = if res? {
            new_state.get_setup().unwrap().to_bytes()
        } else {
            vec![]
        };
        *guard = Some(new_state);
        Ok(bytes_to_send)
    }

    pub async fn start_dkg(&self) -> Result<(), GeneralError> {
        let mut guard = self.state.write().unwrap();
        let current_state = guard.take().unwrap();
        let (new_state, res) = current_state.start_dkg(&self.context);
        if let Err(e) = res {
            *guard = Some(new_state);
            return Err(e);
        }
        // Have to send the start message out to the other nodes.
        if let Err(e) = self
            .dkg_if
            .send(new_state.get_setup().unwrap().to_bytes())
            .await
        {
            *guard = Some(new_state);
            return Err(e);
        }
        let (new_state, res) = self.do_dkg_internal(new_state).await;
        *guard = Some(new_state);
        res
    }

    async fn do_dkg_internal(
        &self,
        state: Box<dyn DKGInternalState>,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        if state.get_state() != DKGState::Running {
            return (
                state,
                Err(GeneralError::InvalidState(
                    "Cannot run DKG in other than running state.".to_string(),
                )),
            );
        }
        let setup = state.get_setup().unwrap();
        let result = do_keygen_relay(
            &setup,
            &self.context.sk,
            create_network_relay(self.dkg_if.clone()),
        )
        .await;
        let local_result = result.clone().map(|_| ());
        let (new_state, res) = state.finish_dkg(&self.context, result);
        // This should *always* be Ok(()), but better to be safe ?
        match res {
            Ok(_) => (new_state, local_result),
            Err(e) => (new_state, Err(e)),
        }
    }

    pub async fn message_loop(&self) -> Result<(), GeneralError> {
        // HACK: Need to send the initial setup message if we're the first one.
        if self.get_state() == DKGState::Ready {
            self.setup_if
                .send(
                    self.state
                        .read()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .get_setup()
                        .unwrap()
                        .to_bytes(),
                )
                .await?;
        }

        while self.get_state() != DKGState::Running {
            self.process_next_setup_msg().await?;
        }
        // Start the actual DKG
        let mut guard = self.state.write().unwrap();
        let current_state = guard.take().unwrap();
        let (new_state, res) = self.do_dkg_internal(current_state).await;
        *guard = Some(new_state);
        res
    }
}

/*****************************************************************************
 * Actually do the DKG.
 *****************************************************************************/

pub async fn do_keygen_relay<R: NetworkRelay>(
    setup: &DKGSetupMessage,
    sk: &NodeSecretKey,
    relay: R,
) -> Result<Keyshare, GeneralError> {
    let vkrefs: Vec<&NodeVerifyingKey> = setup.parties.iter().map(|dev| &dev.vk).collect();
    let ranks = vec![0u8; setup.parties.len()];
    let setup_msg = KeygenSetup::new(
        setup.instance.into(),
        sk,
        setup.party_id.into(),
        vkrefs,
        &ranks,
        setup.threshold.into(),
    );

    let mut rng = ChaCha20Rng::from_entropy();

    let result = keygen_run(setup_msg, rng.gen(), relay).await;

    result
        .map(|k| Keyshare(Arc::new(k)))
        .map_err(GeneralError::from)
}
