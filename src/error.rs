use thiserror::Error;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Ok = 0,
    InvalidArgument = 1,
    ParseFailed = 2,
    NetworkFailed = 3,
    Unauthorized = 4,
    ChallengeRequired = 5,
    InvalidState = 6,
    CryptoFailed = 7,
    NotFound = 8,
    Unsupported = 9,
    Internal = 255,
}

#[derive(Debug, Clone, Error)]
pub enum AtrError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("parse failed: {0}")]
    ParseFailed(String),
    #[error("network failed: {0}")]
    NetworkFailed(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("challenge required: {0}")]
    ChallengeRequired(String),
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("crypto failed: {0}")]
    CryptoFailed(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type AtrResult<T> = Result<T, AtrError>;

impl AtrError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
            Self::ParseFailed(_) => ErrorCode::ParseFailed,
            Self::NetworkFailed(_) => ErrorCode::NetworkFailed,
            Self::Unauthorized(_) => ErrorCode::Unauthorized,
            Self::ChallengeRequired(_) => ErrorCode::ChallengeRequired,
            Self::InvalidState(_) => ErrorCode::InvalidState,
            Self::CryptoFailed(_) => ErrorCode::CryptoFailed,
            Self::NotFound(_) => ErrorCode::NotFound,
            Self::Unsupported(_) => ErrorCode::Unsupported,
            Self::Internal(_) => ErrorCode::Internal,
        }
    }
}

impl From<reqwest::Error> for AtrError {
    fn from(err: reqwest::Error) -> Self {
        Self::NetworkFailed(err.to_string())
    }
}

impl From<serde_json::Error> for AtrError {
    fn from(err: serde_json::Error) -> Self {
        Self::ParseFailed(err.to_string())
    }
}

impl From<url::ParseError> for AtrError {
    fn from(err: url::ParseError) -> Self {
        Self::ParseFailed(err.to_string())
    }
}

impl From<rsa::errors::Error> for AtrError {
    fn from(err: rsa::errors::Error) -> Self {
        Self::CryptoFailed(err.to_string())
    }
}

impl From<std::io::Error> for AtrError {
    fn from(err: std::io::Error) -> Self {
        Self::NetworkFailed(err.to_string())
    }
}
