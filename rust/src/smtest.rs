use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sl_dkls23::keygen::run as keygen_run;
use sl_dkls23::setup::keygen::SetupMessage as KeygenSetup;
use sl_dkls23::Relay as NetworkRelay;

use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use tokio::sync::Notify;

use crate::error::GeneralError;
use crate::net::{create_network_relay, NetworkInterface};
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

    fn get_setup(&self) -> Result<Arc<DKGSetupMessage>, GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot get setup handle in current state.".to_string(),
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

    fn scan_qr(
        mut self: Box<Self>,
        _: &DKGContext,
        qr_data: QRData,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        let res = Arc::make_mut(&mut self.setup)
            .verify_qr(&qr_data)
            .map(|_| ());

        (self, res)
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
            let mut setup = Arc::unwrap_or_clone(self.setup);
            setup.start = true;
            (DKGRunningState::new(setup), Ok(()))
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
    fn new(setup: DKGSetupMessage) -> Box<Self> {
        Box::new(Self {
            setup: Arc::new(setup),
        })
    }
}

impl DKGInternalState for DKGRunningState {
    fn get_state(&self) -> DKGState {
        DKGState::Running
    }

    fn get_setup(&self) -> Result<Arc<DKGSetupMessage>, GeneralError> {
        Ok(self.setup.clone())
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
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
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
    await_msg_kick: Notify,
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
            await_msg_kick: Notify::new(),
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
            await_msg_kick: Notify::new(),
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
        println!("{:?} Waiting for setup message", self.context.friendly_name);
        let setup_msg = self.get_next_msg_interruptable().await?;
        println!("{:?} Received setup message", self.context.friendly_name);
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
        let bytes_to_send = new_state.get_setup().unwrap().to_bytes();
        *guard = Some(new_state);
        drop(guard);
        if !bytes_to_send.is_empty() {
            println!("{:?} Sending start message", self.context.friendly_name);
            self.dkg_if.send(bytes_to_send).await?;
        }
        println!("{:?} Notifying waiters", self.context.friendly_name);
        self.await_msg_kick.notify_waiters();
        Ok(())
        // let (new_state, res) = self.do_dkg_internal(new_state).await;
        // *guard = Some(new_state);
        // res
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

        println!("{:?} keygen_run", self.context.friendly_name);
        let result = keygen_run(
            setup_msg,
            rng.gen(),
            create_network_relay(self.dkg_if.clone()),
        )
        .await
        .map(|k| Keyshare(Arc::new(k)))
        .map_err(GeneralError::from);
        println!("{:?} keygen_run done", self.context.friendly_name);

        result
    }

    pub async fn message_loop(&self) -> Result<(), GeneralError> {
        // HACK: Need to send the initial setup message if we're the first one.

        println!(
            "{:?} Message loop start in state {:?}",
            self.context.friendly_name,
            self.get_state()
        );
        if self.get_state() == DKGState::WaitForParties {
            println!("{:?} Sending setup message", self.context.friendly_name);
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
                println!("{:?} Not Running!?!", self.context.friendly_name);
                return Err(GeneralError::InvalidState(
                    "Calculated state is running but stored state is not?".to_string(),
                ));
            }
            state.get_setup().unwrap()
        };

        println!("{:?} Starting DKG", self.context.friendly_name);
        let res = self.do_dkg_internal(setup.clone()).await;
        println!("{:?} DKG Complete?", self.context.friendly_name);

        let mut guard = self.state.write().unwrap();
        *guard = Some(DKGFinishedState::new(setup, res));
        Ok(())
    }
}

/*****************************************************************************
 * Actually do the DKG.
 *****************************************************************************/

pub async fn do_keygen_relay<R: NetworkRelay>(
    setup: Arc<DKGSetupMessage>,
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

/*****************************************************************************
 * Tests
 *****************************************************************************/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::InMemoryBridge;
    use k256::elliptic_curve::group::GroupEncoding;
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_from_setup_relay() {
        let instance = InstanceId::from_entropy();
        let sks = (0..3)
            .map(|_| NodeSecretKey::from_entropy())
            .collect::<Vec<_>>();
        let devs = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| DeviceInfo::for_sk(format!("Node{}", i), sk))
            .collect::<Vec<_>>();

        let setup_msgs = devs
            .iter()
            .enumerate()
            .map(|(i, _)| {
                Arc::new(DKGSetupMessage {
                    instance,
                    party_id: i as u8,
                    threshold: 2,
                    parties: devs.clone(),
                    start: true,
                })
            })
            .collect::<Vec<_>>();

        let mut parties = tokio::task::JoinSet::new();
        let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();

        for (sk, setup) in sks.into_iter().zip(setup_msgs.into_iter()) {
            let relay = coord.connect();
            parties.spawn(async move { do_keygen_relay(setup, &sk, relay).await });
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
                        shares.push(Arc::new(share))
                    }
                }
            }
        }

        for keyshare in shares.iter() {
            println!(
                "PK={} SK={}",
                hex::encode(keyshare.0.public_key().to_bytes()),
                hex::encode(keyshare.0.s_i().to_bytes())
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_from_setup_ni() {
        let instance = InstanceId::from_entropy();
        let sks = (0..3)
            .map(|_| NodeSecretKey::from_entropy())
            .collect::<Vec<_>>();
        let devs = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| DeviceInfo::for_sk(format!("Node{}", i), sk))
            .collect::<Vec<_>>();

        let setup_msgs = devs
            .iter()
            .enumerate()
            .map(|(i, _)| {
                Arc::new(DKGSetupMessage {
                    instance,
                    party_id: i as u8,
                    threshold: 2,
                    parties: devs.clone(),
                    start: true,
                })
            })
            .collect::<Vec<_>>();

        let mut parties = tokio::task::JoinSet::new();
        let coord = InMemoryBridge::new();
        let nis = setup_msgs
            .iter()
            .map(|_| coord.connect())
            .collect::<Vec<_>>();

        for ((sk, setup), ni) in sks
            .into_iter()
            .zip(setup_msgs.into_iter())
            .zip(nis.into_iter())
        {
            parties.spawn(timeout(Duration::from_secs(5), async move {
                do_keygen_relay(setup, &sk, create_network_relay(ni)).await
            }));
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
                        shares.push(Arc::new(share))
                    }
                }
            }
        }

        // for keyshare in shares.iter() {
        //     println!(
        //         "PK={} SK={}",
        //         hex::encode(keyshare.0.public_key().to_bytes()),
        //         hex::encode(keyshare.0.s_i().to_bytes())
        //     );
        // }
    }

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
            instance,
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

        println!("Got this far");

        // Wait for both nodes to become ready.
        assert!(wait_for_state(nodes[1].clone(), DKGState::Ready, 50).await);
        assert!(wait_for_state(nodes[0].clone(), DKGState::Ready, 50).await);

        println!("Starting DKG");
        assert!(nodes[0].start_dkg().await.is_ok());
        assert!(nodes[1].start_dkg().await.is_ok());

        // Wait for both nodes to finish DKG.
        assert!(wait_for_state(nodes[1].clone(), DKGState::Finished, 500).await);
        assert!(wait_for_state(nodes[0].clone(), DKGState::Finished, 500).await);
    }
}
