//! Protocol v1 primitives. This crate does not activate production interfaces.
pub mod crypto;
pub mod protocol;

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
}
pub type Result<T> = std::result::Result<T, Error>;
