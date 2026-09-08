//! Protocol v1 primitives. This crate does not activate production interfaces.
pub mod api;
pub mod crypto;
pub mod engine;
pub mod protocol;
pub mod state;
#[cfg(unix)]
pub mod store;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid protocol input")]
    Invalid,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("randomness unavailable")]
    Random,
    #[error("invalid state transition")]
    Conflict,
    #[error("installer operation failed")]
    Installer,
}
pub type Result<T> = std::result::Result<T, Error>;
