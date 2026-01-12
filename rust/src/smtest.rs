use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use crate::error::GeneralError;
use crate::types::*;

#[cfg(test)]
use mockall::automock;

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

// QR Code data for setting up DKG.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QRData {
    // TODO: should make all of these read-only.
    pub instance: InstanceId,
    pub threshold: u8,
    pub party_id: u8,
    pub dev_info: DeviceInfo,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DKGSetupMessage {
    pub instance: InstanceId,
    pub threshold: u8,
    pub parties: Vec<DeviceInfo>,
    pub start: bool,
}

struct DKGContext {
    friendly_name: String,
    sk: NodeSecretKey,
    setup_if: Arc<dyn DKGNetworkInterface>,
}

trait DKGInternalState {
    fn scan_qr(
        self: Box<Self>,
        context: &DKGContext,
        qr_data: QRData,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>);

    fn receive_setup(
        self: Box<Self>,
        context: &DKGContext,
        setup: DKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>);

    fn start(
        self: Box<Self>,
        context: &DKGContext,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>);

    fn get_setup_message(&self) -> Result<&DKGSetupMessage, GeneralError> {
        Err(GeneralError::InvalidState(
            "Cannot get setup message in current state.".to_string(),
        ))
    }

    fn get_state(&self) -> DKGState;
}

/*****************************************************************************
 * Waiting for Network State.
 * In this state, we've gotten an initial QR code and we're waiting for a
 * setup message from the network.
 *****************************************************************************/

struct DKGWaitForNetState {
    qr_data: QRData,
}

impl DKGInternalState for DKGWaitForNetState {
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

    fn receive_setup(
        self: Box<Self>,
        context: &DKGContext,
        mut setup: DKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        if self.qr_data.instance != setup.instance
            || self.qr_data.threshold != setup.threshold
            || setup.parties.len() <= self.qr_data.party_id as usize
            || setup.parties[self.qr_data.party_id as usize] != self.qr_data.dev_info
        {
            return (self, Err(GeneralError::InvalidSetupMessage));
        }
        setup.parties[self.qr_data.party_id as usize].verified = true;

        // add ourselves to the list of parties.
        setup.parties.push(DeviceInfo::for_sk(
            context.friendly_name.clone(),
            &context.sk,
        ));
        // send the updated setup message to the network.
        (Box::new(DKGReadyState { setup }), Ok(()))
    }

    fn start(
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

    fn get_state(&self) -> DKGState {
        DKGState::WaitForSetup
    }
}

#[cfg(test)]
mod dkg_wait_state_tests {
    use super::*;

    fn gen_sample_context() -> DKGContext {
        let sk = NodeSecretKey::from_entropy();
        let mut mock_if = MockDKGNetworkInterface::new();
        DKGContext {
            friendly_name: "ourselves".to_string(),
            sk,
            setup_if: Arc::new(mock_if),
        }
    }

    fn gen_sample_wait_state() -> Box<DKGWaitForNetState> {
        let sk = NodeSecretKey::from_entropy();
        let qr = QRData {
            instance: InstanceId::from_bytes(vec![0x01; 32]).unwrap(),
            threshold: 2,
            party_id: 0,
            dev_info: DeviceInfo::for_sk("node0".to_string(), &sk),
        };
        Box::new(DKGWaitForNetState {
            qr_data: qr.clone(),
        })
    }

    #[test]
    fn test_wait_recv_qr_err() {
        let sk = NodeSecretKey::from_entropy();
        let qr = QRData {
            instance: InstanceId::from_bytes(vec![0x01; 32]).unwrap(),
            threshold: 2,
            party_id: 1,
            dev_info: DeviceInfo::for_sk("node1".to_string(), &sk),
        };
        let context = gen_sample_context();
        let state = gen_sample_wait_state();
        assert_eq!(state.get_state(), DKGState::WaitForSetup);
        let (new_state, res) = state.scan_qr(&context, qr.clone());
        assert_eq!(new_state.get_state(), DKGState::WaitForSetup);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))))
    }

    #[test]
    fn test_wait_start_err() {
        let context = gen_sample_context();
        let state = gen_sample_wait_state();
        let (new_state, res) = state.start(&context);
        assert_eq!(new_state.get_state(), DKGState::WaitForSetup);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))))
    }

    #[test]
    fn test_wait_recv_setup_ok() {
        let context = gen_sample_context();
        let instance = InstanceId::from_bytes(vec![0x01; 32]).unwrap();

        let secret_keys = vec![NodeSecretKey::from_entropy(), NodeSecretKey::from_entropy()];

        let parties: Vec<DeviceInfo> = secret_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| DeviceInfo::for_sk(format!("node{}", i), sk))
            .collect();
        let mut exp_parties = parties.clone();
        exp_parties[1].verified = true;
        exp_parties.push(DeviceInfo::for_sk("ourselves".to_string(), &context.sk));

        let qr = QRData {
            instance: instance,
            threshold: 2,
            party_id: 1,
            dev_info: parties[1].clone(),
        };
        let setup_msg = DKGSetupMessage {
            instance,
            threshold: 2,
            parties: parties.clone(),
            start: false,
        };

        let state = Box::new(DKGWaitForNetState {
            qr_data: qr.clone(),
        });
        let (res_state, res) = state.receive_setup(&context, setup_msg);
        res.unwrap();
        assert_eq!(res_state.get_state(), DKGState::Ready);
        let new_setup = res_state.get_setup_message().unwrap();
        assert_eq!(new_setup.instance, instance);
        assert_eq!(new_setup.threshold, 2);
        assert_eq!(new_setup.parties, exp_parties);
        // TODO: check that sends new setup message to announce ourselves.
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

impl DKGInternalState for DKGReadyState {
    fn get_state(&self) -> DKGState {
        if self.setup.parties.len() < self.setup.threshold as usize {
            DKGState::WaitForParties
        } else {
            DKGState::Ready
        }
    }

    fn get_setup_message(&self) -> Result<&DKGSetupMessage, GeneralError> {
        Ok(&self.setup)
    }

    fn scan_qr(
        self: Box<Self>,
        _: &DKGContext,
        qr_data: QRData,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        if qr_data.instance != self.setup.instance || qr_data.threshold != self.setup.threshold {
            return (
                self,
                Err(GeneralError::InvalidInput(
                    "QR data does not match setup data.".to_string(),
                )),
            );
        }

        if qr_data.party_id as usize >= self.setup.parties.len() {
            return (
                self,
                Err(GeneralError::InvalidInput("Unknown party ID.".to_string())),
            );
        }
        if qr_data.dev_info != self.setup.parties[qr_data.party_id as usize] {
            return (
                self,
                Err(GeneralError::InvalidInput(
                    "QR device info does not match setup device info.".to_string(),
                )),
            );
        }
        let mut setup = self.setup;
        setup.parties[qr_data.party_id as usize].verified = true;
        (Box::new(DKGReadyState { setup }), Ok(()))
    }

    fn receive_setup(
        self: Box<Self>,
        _context: &DKGContext,
        mut setup: DKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        if setup.instance != self.setup.instance || setup.threshold != self.setup.threshold {
            return (
                self,
                Err(GeneralError::InvalidInput(
                    "Received setup message does not match instance or threshold.".to_string(),
                )),
            );
        }

        if setup.parties.len() < self.setup.parties.len() {
            return (
                self,
                Err(GeneralError::InvalidInput(
                    "Received setup message has fewer parties than expected.".to_string(),
                )),
            );
        }

        // copy over the verified field
        for i in 0..self.setup.parties.len() {
            setup.parties[i].verified = self.setup.parties[i].verified;
        }

        if setup.parties[0..self.setup.parties.len()] != self.setup.parties {
            return (
                self,
                Err(GeneralError::InvalidInput(
                    "Received setup message has different parties than expected.".to_string(),
                )),
            );
        }

        // check that we have enough parties to start.
        if setup.start && setup.parties.len() < setup.threshold as usize {
            return (
                self,
                Err(GeneralError::InvalidInput(
                    "Not enough parties to start DKG.".to_string(),
                )),
            );
        }

        if setup.start {
            (Box::new(DKGRunningState { setup }), Ok(()))
        } else {
            (Box::new(DKGReadyState { setup }), Ok(()))
        }
    }

    fn start(
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
            // TODO: should send the start message to peers.
            (Box::new(DKGRunningState { setup: self.setup }), Ok(()))
        }
    }
}

#[cfg(test)]
mod dkg_ready_state_tests {
    use super::*;

    fn gen_sample_context() -> DKGContext {
        let sk = NodeSecretKey::from_entropy();
        let mut mock_if = MockDKGNetworkInterface::new();
        DKGContext {
            friendly_name: "ourselves".to_string(),
            sk,
            setup_if: Arc::new(mock_if),
        }
    }

    fn make_sample_setup(
        instance: InstanceId,
        context: &DKGContext,
        threshold: u8,
        n: u8,
    ) -> DKGSetupMessage {
        let mut parties: Vec<DeviceInfo> = (0..n - 1)
            .map(|i| DeviceInfo::for_sk(format!("node{}", i), &NodeSecretKey::from_entropy()))
            .collect();
        parties.push(DeviceInfo::for_sk(
            context.friendly_name.clone(),
            &context.sk,
        ));
        DKGSetupMessage {
            instance,
            threshold,
            parties,
            start: false,
        }
    }

    fn make_sample_data(n: u8) -> (InstanceId, DKGContext, DKGSetupMessage, Box<DKGReadyState>) {
        let instance = InstanceId::from_bytes(vec![0x01; 32]).unwrap();
        let context = gen_sample_context();
        let setup = make_sample_setup(instance, &context, 2, n);
        let state = Box::new(DKGReadyState {
            setup: setup.clone(),
        });
        (instance, context, setup, state)
    }

    fn make_qr(instance: InstanceId, threshold: u8, party_id: u8, dev_info: &DeviceInfo) -> QRData {
        QRData {
            instance,
            threshold,
            party_id,
            dev_info: dev_info.clone(),
        }
    }

    #[test]
    fn test_wait_for_parties() {
        let (instance, context, setup, state) = make_sample_data(1);
        assert_eq!(state.get_state(), DKGState::WaitForParties);
    }

    #[test]
    fn test_ready_receive_qr_ok() {
        let (instance, context, setup, state) = make_sample_data(3);
        let qr = make_qr(instance, 2, 0, &setup.parties[0]);
        let (new_state, res) = state.scan_qr(&context, qr);
        assert!(res.is_ok());
        assert_eq!(new_state.get_state(), DKGState::Ready);
        let new_setup = new_state.get_setup_message().unwrap();
        assert!(new_setup.parties[0].verified);
    }

    #[test]
    fn test_ready_receive_qr_wrong_instance() {
        let (instance, context, setup, state) = make_sample_data(3);
        let qr = make_qr(
            InstanceId::from_bytes(vec![0x02; 32]).unwrap(),
            2,
            0,
            &setup.parties[0],
        );
        let (new_state, res) = state.scan_qr(&context, qr);
        assert_eq!(new_state.get_state(), DKGState::Ready);
        assert!(matches!(res, Err(GeneralError::InvalidInput(_))));
    }

    #[test]
    fn test_ready_receive_qr_wrong_threshold() {
        let (instance, context, setup, state) = make_sample_data(3);
        let qr = make_qr(instance, 3, 0, &setup.parties[0]);
        let (new_state, res) = state.scan_qr(&context, qr);
        assert_eq!(new_state.get_state(), DKGState::Ready);
        assert!(matches!(res, Err(GeneralError::InvalidInput(_))));
    }

    #[test]
    fn test_ready_receive_qr_invalid_party_id() {
        let (instance, context, setup, state) = make_sample_data(3);
        let qr = make_qr(instance, 2, 3, &setup.parties[0]);
        let (new_state, res) = state.scan_qr(&context, qr);
        assert_eq!(new_state.get_state(), DKGState::Ready);
        assert!(matches!(res, Err(GeneralError::InvalidInput(_))));
    }

    #[test]
    fn test_ready_receive_qr_invalid_dev_info() {
        let (instance, context, setup, state) = make_sample_data(3);
        let qr = make_qr(instance, 2, 0, &setup.parties[1]);
        let (new_state, res) = state.scan_qr(&context, qr);
        assert_eq!(new_state.get_state(), DKGState::Ready);
        assert!(matches!(res, Err(GeneralError::InvalidInput(_))));
    }

    #[test]
    fn test_ready_receive_setup_ok() {
        let (instance, context, mut new_setup, state) = make_sample_data(3);
        new_setup.parties.push(DeviceInfo::for_sk(
            "new_node".to_string(),
            &NodeSecretKey::from_entropy(),
        ));
        let (state, res) = state.receive_setup(&context, new_setup.clone());
        res.unwrap();
        assert_eq!(state.get_state(), DKGState::Ready);
        let res_setup = state.get_setup_message().unwrap();
        assert_eq!(&new_setup, res_setup);
    }

    #[test]
    fn test_ready_receive_setup_ok_with_verified() {
        let (instance, context, mut new_setup, mut state) = make_sample_data(3);
        state.setup.parties[0].verified = true;
        new_setup.parties.push(DeviceInfo::for_sk(
            "new_node".to_string(),
            &NodeSecretKey::from_entropy(),
        ));
        let (state, res) = state.receive_setup(&context, new_setup.clone());
        res.unwrap();
        assert_eq!(state.get_state(), DKGState::Ready);
        new_setup.parties[0].verified = true;
        let res_setup = state.get_setup_message().unwrap();
        assert_eq!(&new_setup, res_setup);
    }

    #[test]
    fn test_ready_receive_setup_invalid_instance() {
        let (instance, context, mut new_setup, state) = make_sample_data(3);
        new_setup.instance = InstanceId::from_bytes(vec![0x02; 32]).unwrap();
        let (state, res) = state.receive_setup(&context, new_setup.clone());
        assert_eq!(state.get_state(), DKGState::Ready);
        assert!(matches!(res, Err(GeneralError::InvalidInput(_))));
    }

    #[test]
    fn test_ready_receive_setup_invalid_threshold() {
        let (instance, context, mut new_setup, state) = make_sample_data(3);
        new_setup.threshold = 3;
        let (state, res) = state.receive_setup(&context, new_setup.clone());
        assert_eq!(state.get_state(), DKGState::Ready);
        assert!(matches!(res, Err(GeneralError::InvalidInput(_))));
    }

    #[test]
    fn test_ready_receive_setup_too_few_parties() {
        let (instance, context, mut new_setup, state) = make_sample_data(3);
        new_setup.parties.pop();
        let (state, res) = state.receive_setup(&context, new_setup.clone());
        assert_eq!(state.get_state(), DKGState::Ready);
        assert!(matches!(res, Err(GeneralError::InvalidInput(_))));
    }

    #[test]
    fn test_ready_receive_setup_wrong_party_info() {
        let (instance, context, mut new_setup, state) = make_sample_data(3);
        new_setup.parties.pop();
        new_setup.parties.push(DeviceInfo::for_sk(
            "ourselves".to_string(),
            &NodeSecretKey::from_entropy(),
        ));
        let (state, res) = state.receive_setup(&context, new_setup.clone());
        assert_eq!(state.get_state(), DKGState::Ready);
        assert!(matches!(res, Err(GeneralError::InvalidInput(_))));
    }

    #[test]
    fn test_ready_receive_start_too_few_parties() {
        let (instance, context, mut new_setup, state) = make_sample_data(1);
        new_setup.start = true;
        let (state, res) = state.receive_setup(&context, new_setup.clone());
        assert_eq!(state.get_state(), DKGState::WaitForParties);
        assert!(matches!(res, Err(GeneralError::InvalidInput(_))));
    }

    #[test]
    fn test_ready_receive_start() {
        let (instance, context, mut new_setup, state) = make_sample_data(3);
        new_setup.start = true;
        let (state, res) = state.receive_setup(&context, new_setup.clone());
        res.unwrap();
        assert_eq!(state.get_state(), DKGState::Running);
    }

    #[test]
    fn test_ready_start_too_few_parties() {
        let (instance, context, mut new_setup, state) = make_sample_data(1);
        let (state, res) = state.start(&context);
        assert_eq!(state.get_state(), DKGState::WaitForParties);
        assert!(matches!(res, Err(GeneralError::InvalidState(_))));
    }

    #[test]
    fn test_ready_start() {
        let (instance, context, mut new_setup, state) = make_sample_data(3);
        let (state, res) = state.start(&context);
        res.unwrap();
        assert_eq!(state.get_state(), DKGState::Running);
    }
}

/*****************************************************************************
 * Running state.
 * DKG is running, can't get any intermediate results.
 *****************************************************************************/

struct DKGRunningState {
    setup: DKGSetupMessage,
}

impl DKGInternalState for DKGRunningState {
    fn get_state(&self) -> DKGState {
        DKGState::Running
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

    fn receive_setup(
        self: Box<Self>,
        _: &DKGContext,
        _: DKGSetupMessage,
    ) -> (Box<dyn DKGInternalState>, Result<(), GeneralError>) {
        (
            self,
            Err(GeneralError::InvalidState(
                "Cannot receive setup in current state.".to_string(),
            )),
        )
    }

    fn start(
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
}

// #[derive(uniffi::Object)]
pub struct DKGNode {
    // Need interior mutability for state,
    // Option so that we can replace it dynamically.
    state: Mutex<Option<Box<dyn DKGInternalState>>>,
    context: DKGContext,
    dkg_if: Arc<dyn DKGNetworkInterface>,
}

impl DKGNode {
    pub fn new(
        name: &str,
        instance: InstanceId,
        threshold: u8,
        setup_if: Arc<dyn DKGNetworkInterface>,
        dkg_if: Arc<dyn DKGNetworkInterface>,
    ) -> Self {
        let context = DKGContext {
            friendly_name: name.to_string(),
            sk: NodeSecretKey::from_entropy(),
            setup_if,
        };
        let setup = DKGSetupMessage {
            instance,
            threshold,
            parties: vec![DeviceInfo::for_sk(name.to_string(), &context.sk)],
            start: false,
        };
        Self {
            state: Mutex::new(Some(Box::new(DKGReadyState { setup }))),
            context,
            dkg_if,
        }
    }

    pub fn get_state(&self) -> DKGState {
        self.state.lock().unwrap().as_ref().unwrap().get_state()
    }

    pub fn receive_qr(&mut self, qr: QRData) -> Result<(), GeneralError> {
        let mut guard = self.state.lock().unwrap();
        let current_state = guard.take().unwrap();
        let (new_state, res) = current_state.scan_qr(&self.context, qr);
        *guard = Some(new_state);
        res
    }

    pub fn receive_setup(&mut self, setup: DKGSetupMessage) -> Result<(), GeneralError> {
        let mut guard = self.state.lock().unwrap();
        let current_state = guard.take().unwrap();
        let (new_state, res) = current_state.receive_setup(&self.context, setup);
        *guard = Some(new_state);
        res
    }

    pub fn start(&mut self) -> Result<(), GeneralError> {
        let mut guard = self.state.lock().unwrap();
        let current_state = guard.take().unwrap();
        let (new_state, res) = current_state.start(&self.context);
        *guard = Some(new_state);
        res
    }
}
