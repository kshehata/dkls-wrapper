use sl_dkls23::keygen::KeygenError as DklsKeygenError;
use sl_dkls23::sign::SignError as DklsSignError;
use uniffi::Error;

#[derive(Debug, Clone, Error, thiserror::Error)]
pub enum GeneralError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Invalid signature: {0}")]
    SignatureError(String),
    #[error("Invalid setup message")]
    InvalidSetupMessage,
    #[error("Message sending error")]
    MessageSendError,
    #[error("Keygen Error: {0}")]
    KeygenError(String),
    #[error("Abort protocol by party {0}")]
    AbortProtocol(u32),
    #[error("Abort protocol and ban party {0}")]
    AbortProtocolAndBanParty(u8),
    #[error("Signing Error: {0}")]
    SigningError(String),
    #[error("Invalid context")]
    InvalidContext,
    #[error("Internal failure")]
    Generic,
}

impl From<DklsKeygenError> for GeneralError {
    fn from(error: DklsKeygenError) -> Self {
        match error {
            DklsKeygenError::SendMessage => Self::MessageSendError,
            DklsKeygenError::AbortProtocol(p) => Self::AbortProtocol(p as u32),
            _ => Self::KeygenError(error.to_string()),
        }
    }
}

impl From<sl_dkls23::MessageSendError> for GeneralError {
    fn from(_: sl_dkls23::MessageSendError) -> Self {
        Self::MessageSendError
    }
}

impl From<DklsSignError> for GeneralError {
    fn from(error: DklsSignError) -> Self {
        match error {
            DklsSignError::SendMessage => Self::MessageSendError,
            DklsSignError::AbortProtocol(p) => Self::AbortProtocol(p as u32),
            DklsSignError::AbortProtocolAndBanParty(p) => Self::AbortProtocolAndBanParty(p as u8),
            _ => Self::SigningError(error.to_string()),
        }
    }
}
