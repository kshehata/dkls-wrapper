use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sl_dkls23::keygen::run as keygen_run;
use sl_dkls23::setup::keygen::SetupMessage as KeygenSetup;
use sl_dkls23::Relay as NetworkRelay;

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

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

#[cfg_attr(test, automock)]
#[async_trait::async_trait]
pub trait DKGNetworkInterface: Send + Sync {
    async fn send(&self, data: Vec<u8>) -> Result<(), GeneralError>;
    async fn receive(&self) -> Result<Vec<u8>, GeneralError>;
}

#[async_trait::async_trait]
trait DKGContext: Send + Sync + 'static {
    fn friendly_name(&self) -> &str;
    fn sk(&self) -> &NodeSecretKey;
    async fn receive_setup(&self) -> Result<DKGSetupMessage, GeneralError>;
    async fn send_setup(&self, setup: &DKGSetupMessage) -> Result<(), GeneralError>;
    async fn do_dkg(&self, setup: &DKGSetupMessage) -> Result<Keyshare, GeneralError>;
}

#[async_trait::async_trait]
trait DKGInternalState<Context: DKGContext>: Send + Sync + 'static {
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
        context: &Context,
        qr_data: QRData,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>);

    async fn run(
        self: Box<Self>,
        context: &Context,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>);

    async fn start_dkg(
        self: Box<Self>,
        context: &Context,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>);

    fn get_result(&self) -> Result<Keyshare, GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot get result in current state.".to_string(),
        ))
    }
}

struct DKGContextForNetworkInterface {
    friendly_name: String,
    sk: NodeSecretKey,
    setup_if: Arc<dyn DKGNetworkInterface>,
    dkg_if: Arc<dyn NetworkInterface>,
}

#[async_trait::async_trait]
impl DKGContext for DKGContextForNetworkInterface {
    fn friendly_name(&self) -> &str {
        &self.friendly_name
    }

    fn sk(&self) -> &NodeSecretKey {
        &self.sk
    }

    // Shortcut to receive and parse a setup message.
    async fn receive_setup(&self) -> Result<DKGSetupMessage, GeneralError> {
        let data = self.setup_if.receive().await?;
        DKGSetupMessage::try_from(data.as_slice())
    }

    // Shortcut to send a setup message.
    async fn send_setup(&self, setup: &DKGSetupMessage) -> Result<(), GeneralError> {
        self.setup_if.send(setup.to_bytes()).await
    }

    async fn do_dkg(&self, setup: &DKGSetupMessage) -> Result<Keyshare, GeneralError> {
        do_keygen_relay(setup, &self.sk, create_network_relay(self.dkg_if.clone())).await
    }
}

struct DKGContextForSLRelay<R: NetworkRelay + Send + Sync + 'static> {
    friendly_name: String,
    sk: NodeSecretKey,
    setup_if: tokio::sync::Mutex<R>,
    dkg_if: Mutex<Option<R>>,
}

// Do we need this?
use futures::sink::SinkExt;
use futures::stream::StreamExt;

#[async_trait::async_trait]
impl<R: NetworkRelay + Send + Sync> DKGContext for DKGContextForSLRelay<R> {
    fn friendly_name(&self) -> &str {
        &self.friendly_name
    }

    fn sk(&self) -> &NodeSecretKey {
        &self.sk
    }

    // Shortcut to receive and parse a setup message.
    async fn receive_setup(&self) -> Result<DKGSetupMessage, GeneralError> {
        let data = match self.setup_if.lock().await.next().await {
            Some(data) => data,
            // TODO: make an error type for no more input?
            None => return Err(GeneralError::Generic),
        };
        DKGSetupMessage::try_from(data.as_slice())
    }

    // Shortcut to send a setup message.
    async fn send_setup(&self, setup: &DKGSetupMessage) -> Result<(), GeneralError> {
        match self.setup_if.lock().await.send(setup.to_bytes()).await {
            Ok(_) => Ok(()),
            Err(_) => Err(GeneralError::MessageSendError),
        }
    }

    async fn do_dkg(&self, setup: &DKGSetupMessage) -> Result<Keyshare, GeneralError> {
        let relay = self.dkg_if.lock().unwrap().take().unwrap();
        do_keygen_relay(setup, &self.sk, relay).await
    }
}

/*****************************************************************************
 * Waiting for Network State.
 * In this state, we've gotten an initial QR code and we're waiting for a
 * setup message from the network.
 *****************************************************************************/

struct DKGWaitForNetState<Context: DKGContext> {
    qr_data: QRData,
    _phantom: std::marker::PhantomData<Context>,
}

impl<Context: DKGContext> DKGWaitForNetState<Context> {
    fn new(qr_data: QRData) -> Box<Self> {
        Box::new(Self {
            qr_data,
            _phantom: std::marker::PhantomData,
        })
    }

    // Helper to receive a setup message and verify it against the QR data.
    async fn get_setup_maybe_update(
        &self,
        context: &Context,
    ) -> Result<DKGSetupMessage, GeneralError> {
        let mut setup = context.receive_setup().await?;
        setup.verify_qr(&self.qr_data)?;
        setup.add_ourself(context.friendly_name(), &context.sk());
        context.send_setup(&setup).await?;
        Ok(setup)
    }
}

#[async_trait::async_trait]
impl<Context: DKGContext> DKGInternalState<Context> for DKGWaitForNetState<Context> {
    fn get_state(&self) -> DKGState {
        DKGState::WaitForSetup
    }

    fn scan_qr(
        self: Box<Self>,
        _: &Context,
        _: QRData,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot scan QR in current state.".to_string(),
            )),
        )
    }

    async fn run(
        self: Box<Self>,
        context: &Context,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>) {
        println!("{:?} Waiting for setup message", context.friendly_name());
        let setup = match self.get_setup_maybe_update(context).await {
            Ok(s) => s,
            Err(e) => return (self, Err(e)),
        };
        println!("{:?} got setup message", context.friendly_name());
        println!("{:?}", setup);

        (DKGReadyState::new(setup), Ok(()))
    }

    async fn start_dkg(
        self: Box<Self>,
        _context: &Context,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>) {
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

struct DKGReadyState<Context: DKGContext> {
    setup: DKGSetupMessage,
    _phantom: std::marker::PhantomData<Context>,
}

impl<Context: DKGContext> DKGReadyState<Context> {
    fn new(setup: DKGSetupMessage) -> Box<Self> {
        Box::new(Self {
            setup,
            _phantom: std::marker::PhantomData,
        })
    }

    async fn receive_and_update_setup(
        &self,
        context: &Context,
    ) -> Result<DKGSetupMessage, GeneralError> {
        let mut setup = context.receive_setup().await?;
        setup.verify_existing(&self.setup)?;
        Ok(setup)
    }
}

#[async_trait::async_trait]
impl<Context: DKGContext> DKGInternalState<Context> for DKGReadyState<Context> {
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
        _: &Context,
        qr_data: QRData,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>) {
        let mut setup = self.setup;
        let res = setup.verify_qr(&qr_data).map(|_| ());

        (Self::new(setup), res)
    }

    async fn run(
        self: Box<Self>,
        context: &Context,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>) {
        // HACK: Send initial setup message if we're the first
        if self.setup.party_id == 0 && self.setup.parties.len() <= 1 {
            println!("{:?} Sending initial setup", context.friendly_name());
            if let Err(e) = context.send_setup(&self.setup).await {
                return (self, Err(e));
            }
        }

        println!("{:?} waiting for setup message", context.friendly_name());
        let setup = match self.receive_and_update_setup(context).await {
            Ok(setup) => setup,
            Err(e) => return (self, Err(e)),
        };
        println!("{:?} got setup message", context.friendly_name());
        println!("{:?}", setup);

        // Check if we got the start flag, and if so
        // check that we have enough parties to start.
        if setup.start {
            if setup.parties.len() < setup.threshold as usize {
                let mut setup = setup;
                setup.start = false;
                return (
                    Self::new(setup),
                    Err(GeneralError::InvalidState(
                        "Not enough parties to start DKG.".to_string(),
                    )),
                );
            }
            (DKGRunningState::new(setup), Ok(()))
        } else {
            (Self::new(setup), Ok(()))
        }
    }

    async fn start_dkg(
        self: Box<Self>,
        context: &Context,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>) {
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
            match context.send_setup(&setup).await {
                Ok(_) => (DKGRunningState::new(setup), Ok(())),
                Err(e) => {
                    setup.start = false;
                    (Self::new(setup), Err(e))
                }
            }
        }
    }
}

/*****************************************************************************
 * Running state.
 * DKG is running, can't get any intermediate results.
 *****************************************************************************/

struct DKGRunningState<Context: DKGContext> {
    setup: DKGSetupMessage,
    _phantom: std::marker::PhantomData<Context>,
}

impl<Context: DKGContext> DKGRunningState<Context> {
    fn new(setup: DKGSetupMessage) -> Box<Self> {
        Box::new(Self {
            setup,
            _phantom: std::marker::PhantomData,
        })
    }
}

#[async_trait::async_trait]
impl<Context: DKGContext> DKGInternalState<Context> for DKGRunningState<Context> {
    fn get_state(&self) -> DKGState {
        DKGState::Running
    }

    // This should only be used for testing!
    fn get_setup(&self) -> Result<&DKGSetupMessage, GeneralError> {
        Ok(&self.setup)
    }

    async fn run(
        self: Box<Self>,
        context: &Context,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>) {
        let result = context.do_dkg(&self.setup).await;

        let local_result = match &result {
            Ok(_) => Ok(()),
            Err(e) => Err(e.clone()),
        };
        (DKGFinishedState::new(self.setup, result), local_result)
    }

    fn scan_qr(
        self: Box<Self>,
        _: &Context,
        _: QRData,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot scan QR in current state.".to_string(),
            )),
        )
    }

    async fn start_dkg(
        self: Box<Self>,
        _: &Context,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>) {
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

struct DKGFinishedState<Context: DKGContext> {
    setup: DKGSetupMessage,
    result: Result<Keyshare, GeneralError>,
    _phantom: std::marker::PhantomData<Context>,
}

impl<Context: DKGContext> DKGFinishedState<Context> {
    fn new(setup: DKGSetupMessage, result: Result<Keyshare, GeneralError>) -> Box<Self> {
        Box::new(Self {
            setup,
            result,
            _phantom: std::marker::PhantomData,
        })
    }
}

#[async_trait::async_trait]
impl<Context: DKGContext> DKGInternalState<Context> for DKGFinishedState<Context> {
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

    async fn run(
        self: Box<Self>,
        _: &Context,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>) {
        (self, Ok(()))
    }

    fn scan_qr(
        self: Box<Self>,
        _: &Context,
        _: QRData,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot scan QR in current state.".to_string(),
            )),
        )
    }

    async fn start_dkg(
        self: Box<Self>,
        _: &Context,
    ) -> (Box<dyn DKGInternalState<Context>>, Result<(), GeneralError>) {
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
pub struct DKGNode<Context: DKGContext> {
    // Need interior mutability for state,
    // Option so that we can replace it dynamically.
    state: tokio::sync::Mutex<Option<Box<dyn DKGInternalState<Context>>>>,
    context: Context,
}

impl<Context: DKGContext> DKGNode<Context> {
    pub fn new(context: Context, instance: InstanceId, threshold: u8) -> Self {
        let setup = DKGSetupMessage {
            instance,
            threshold,
            party_id: 0,
            parties: vec![DeviceInfo::for_sk(
                context.friendly_name().to_string(),
                context.sk(),
            )],
            start: false,
        };
        Self {
            state: tokio::sync::Mutex::new(Some(DKGReadyState::new(setup))),
            context,
        }
    }

    pub fn from_qr_internal(context: Context, qr_data: QRData) -> Self {
        Self {
            state: tokio::sync::Mutex::new(Some(DKGWaitForNetState::new(qr_data))),
            context,
        }
    }

    pub async fn get_state(&self) -> DKGState {
        self.state.lock().await.as_ref().unwrap().get_state()
    }

    pub async fn get_qr(&self) -> Result<QRData, GeneralError> {
        self.state.lock().await.as_ref().unwrap().get_qr()
    }

    pub async fn receive_qr(&self, qr: QRData) -> Result<(), GeneralError> {
        let mut guard = self.state.lock().await;
        let current_state = guard.take().unwrap();
        let (new_state, res) = current_state.scan_qr(&self.context, qr);
        *guard = Some(new_state);
        res
    }

    pub async fn start(&self) -> Result<(), GeneralError> {
        let mut guard = self.state.lock().await;
        let current_state = guard.take().unwrap();
        let (new_state, res) = current_state.start_dkg(&self.context).await;
        *guard = Some(new_state);
        res
    }

    pub async fn run(&self) -> Result<(), GeneralError> {
        while self.get_state().await != DKGState::Finished {
            let mut guard = self.state.lock().await;
            let current_state = guard.take().unwrap();
            let (new_state, res) = current_state.run(&self.context).await;
            *guard = Some(new_state);
            res?;
        }
        Ok(())
    }
}

type DKGNodeForInterfaces = DKGNode<DKGContextForNetworkInterface>;

impl DKGNodeForInterfaces {
    pub fn starter(
        name: &str,
        instance: InstanceId,
        threshold: u8,
        setup_if: Arc<dyn DKGNetworkInterface>,
        dkg_if: Arc<dyn NetworkInterface>,
    ) -> Self {
        let context = DKGContextForNetworkInterface {
            friendly_name: name.to_string(),
            sk: NodeSecretKey::from_entropy(),
            setup_if,
            dkg_if,
        };
        Self::new(context, instance, threshold)
    }

    pub fn from_qr(
        name: &str,
        qr: QRData,
        setup_if: Arc<dyn DKGNetworkInterface>,
        dkg_if: Arc<dyn NetworkInterface>,
    ) -> Self {
        let context = DKGContextForNetworkInterface {
            friendly_name: name.to_string(),
            sk: NodeSecretKey::from_entropy(),
            setup_if,
            dkg_if,
        };
        Self::from_qr_internal(context, qr)
    }
}

type DKGNodeForRelay<R> = DKGNode<DKGContextForSLRelay<R>>;

impl<R: NetworkRelay + Send + Sync + 'static> DKGNodeForRelay<R> {
    pub fn starter(
        name: &str,
        instance: InstanceId,
        threshold: u8,
        setup_if: R,
        dkg_if: R,
    ) -> Self {
        let context = DKGContextForSLRelay {
            friendly_name: name.to_string(),
            sk: NodeSecretKey::from_entropy(),
            setup_if: tokio::sync::Mutex::new(setup_if),
            dkg_if: Mutex::new(Some(dkg_if)),
        };
        Self::new(context, instance, threshold)
    }

    pub fn from_qr(name: &str, qr: QRData, setup_if: R, dkg_if: R) -> Self {
        let context = DKGContextForSLRelay {
            friendly_name: name.to_string(),
            sk: NodeSecretKey::from_entropy(),
            setup_if: tokio::sync::Mutex::new(setup_if),
            dkg_if: Mutex::new(Some(dkg_if)),
        };
        Self::from_qr_internal(context, qr)
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

/*****************************************************************************
 * Tests
 *****************************************************************************/

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::group::GroupEncoding;
    use std::time::Duration;
    use tokio::sync::watch;
    use tokio::time::{sleep, timeout};

    fn spawn_node<U: DKGContext>(
        js: &mut tokio::task::JoinSet<()>,
        node: Arc<DKGNode<U>>,
    ) -> tokio::task::AbortHandle {
        js.spawn(async move {
            node.run().await;
        })
    }

    // #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_node() {
        println!("Starting DKG Node via Relays Test");
        let instance = InstanceId::from_entropy();

        let setup_coord = sl_mpc_mate::coord::SimpleMessageRelay::new();
        let dkg_coord = sl_mpc_mate::coord::SimpleMessageRelay::new();

        let mut nodes = vec![Arc::new(DKGNodeForRelay::starter(
            "Node1",
            instance,
            2,
            setup_coord.connect(),
            dkg_coord.connect(),
        ))];

        assert_eq!(nodes[0].get_state().await, DKGState::WaitForParties);

        let qr = nodes[0].get_qr().await.unwrap();
        assert_eq!(qr.instance, instance);
        assert_eq!(qr.party_id, 0);
        // TODO: check vk

        nodes.push(Arc::new(DKGNodeForRelay::from_qr(
            "Node2",
            qr.clone(),
            setup_coord.connect(),
            dkg_coord.connect(),
        )));
        assert_eq!(nodes[1].get_state().await, DKGState::WaitForSetup);

        let mut parties = tokio::task::JoinSet::new();
        spawn_node(&mut parties, nodes[1].clone());
        spawn_node(&mut parties, nodes[0].clone());

        println!("Got this far");

        // Wait for node 2 to become ready.
        let n = nodes[1].clone();
        let r1 = timeout(Duration::from_millis(500), async move {
            loop {
                let state = n.get_state().await;
                println!("Current state: {:?}", state);
                if state == DKGState::Ready {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        // assert!(r1.is_ok());
        assert!(nodes[0].start().await.is_ok());
    }

    // #[tokio::test(flavor = "multi_thread")]
    async fn test_relay() {
        let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();
        let mut parties = tokio::task::JoinSet::new();
        let mut relay = coord.connect();
        parties.spawn(async move {
            let Some(bytes) = relay.next().await else {
                println!("Got nothin.");
                return;
            };
            let Ok(msg) = str::from_utf8(&bytes) else {
                println!("Invalid message.");
                return;
            };
            println!("Got message: {:?}", msg);
        });

        let mut relay2 = coord.connect();
        relay2
            .send("Hello, world!".as_bytes().to_vec())
            .await
            .unwrap();
        parties.join_all().await;
    }
}
