use uniffi::Error;
use sl_dkls23::keygen::types::KeygenError as DklsKeygenError;

#[derive(Debug, Error, thiserror::Error)]
#[uniffi(flat_error)]
pub enum GeneralError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Invalid signature: {0}")]
    SignatureError(String),
    #[error("Internal failure")]
    Generic,
}

#[derive(Debug, Error, thiserror::Error)]
pub enum KeygenError {
    /// Error while serializing or deserializing message data, or invalid message length
    #[error(
        "Error while deserializing message or invalid message data length"
    )]
    InvalidMessage,

    /// The commitment hash provided does not match the expected value
    #[error("Invalid commitment hash")]
    InvalidCommitmentHash,

    /// The discrete logarithm proof provided is invalid
    #[error("Invalid DLog proof")]
    InvalidDLogProof,

    /// The polynomial point provided is invalid
    #[error("Invalid Polynomial Point")]
    InvalidPolynomialPoint,

    /// The key refresh operation failed
    #[error("Invalid key refresh")]
    InvalidKeyRefresh,

    /// The quorum change operation failed
    #[error("Invalid Quorum Change")]
    InvalidQuorumChange,

    /// The x_i values provided are not unique
    #[error("Not unique x_i values")]
    NotUniqueXiValues,

    /// The Big F vector does not match the expected value
    #[error("Big F vec mismatch")]
    BigFVecMismatch,

    /// The Feldman verification failed
    #[error("Failed feldman verify")]
    FailedFelmanVerify,

    /// The public key in the message does not match the party's public key
    #[error("Public key mismatch between the message and the party")]
    PublicKeyMismatch,

    /// The Big S value does not match the expected value
    #[error("Big S value mismatch")]
    BigSMismatch,

    /// An error occurred in the PPRF (Pseudorandom Function) operation
    #[error("PPRF error")]
    PPRFError(String),

    /// A required message is missing
    #[error("Missing message")]
    MissingMessage,

    /// Failed to send a message
    #[error("Send message")]
    SendMessage,

    /// A party has decided to abort the protocol
    #[error("Abort protocol by party {0}")]
    AbortProtocol(u32),

    // Invalid Context
    #[error("Invalid runtime context")]
    InvalidContext,
}

impl From<DklsKeygenError> for KeygenError {
    fn from(error: DklsKeygenError) -> Self {
        match error {
            DklsKeygenError::InvalidMessage => Self::InvalidMessage,
            DklsKeygenError::InvalidCommitmentHash => Self::InvalidCommitmentHash,
            DklsKeygenError::InvalidDLogProof => Self::InvalidDLogProof,
            DklsKeygenError::InvalidPolynomialPoint => Self::InvalidPolynomialPoint,
            DklsKeygenError::InvalidKeyRefresh => Self::InvalidKeyRefresh,
            DklsKeygenError::InvalidQuorumChange => Self::InvalidQuorumChange,
            DklsKeygenError::NotUniqueXiValues => Self::NotUniqueXiValues,
            DklsKeygenError::BigFVecMismatch => Self::BigFVecMismatch,
            DklsKeygenError::FailedFelmanVerify => Self::FailedFelmanVerify,
            DklsKeygenError::PublicKeyMismatch => Self::PublicKeyMismatch,
            DklsKeygenError::BigSMismatch => Self::BigSMismatch,
            DklsKeygenError::PPRFError(error) => Self::PPRFError(error.to_string()),
            DklsKeygenError::MissingMessage => Self::MissingMessage,
            DklsKeygenError::SendMessage => Self::SendMessage,
            DklsKeygenError::AbortProtocol(p) => Self::AbortProtocol(p as u32),
        }
    }
}


#[derive(Debug, Error, thiserror::Error)]
pub enum NetworkError {
    #[error("Message sending error")]
    MessageSendError,
}

impl From<sl_dkls23::MessageSendError> for NetworkError {
    fn from(_: sl_dkls23::MessageSendError) -> Self {
        Self::MessageSendError
    }
}

impl Into<sl_dkls23::MessageSendError> for NetworkError {
    fn into(self) -> sl_dkls23::MessageSendError {
        sl_dkls23::MessageSendError
    }
}
