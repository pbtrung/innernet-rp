use std::convert::TryFrom;

use crate::body::Body;
use hyper::{http, Response, StatusCode};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("unauthorized access")]
    Unauthorized,

    #[error("object not found")]
    NotFound,

    #[error("invalid query")]
    InvalidQuery,

    #[error("endpoint gone")]
    Gone,

    #[error("conflicting durable state")]
    Conflict,
    #[error("request exceeds the body limit")]
    PayloadTooLarge,
    #[error("unsupported content encoding or type")]
    UnsupportedMedia,
    #[error("PQ resource budget exhausted")]
    RateLimited,
    #[error("PQ service is not ready")]
    Unavailable,
    #[error("invalid PQ message")]
    Pq(#[from] innernet_pq::Error),

    #[error("internal database error")]
    Database(#[from] rusqlite::Error),

    #[error("internal WireGuard error")]
    WireGuard,

    #[error("internal I/O error")]
    Io(#[from] std::io::Error),

    #[error("JSON parsing/serialization error")]
    Json(#[from] serde_json::Error),

    #[error("Generic HTTP error")]
    Http(#[from] http::Error),

    #[error("Generic Hyper error")]
    Hyper(#[from] hyper::Error),
}

impl From<&ServerError> for StatusCode {
    fn from(error: &ServerError) -> StatusCode {
        use ServerError::*;
        match error {
            Unauthorized => StatusCode::UNAUTHORIZED,
            NotFound => StatusCode::NOT_FOUND,
            Gone => StatusCode::GONE,
            Conflict | Pq(innernet_pq::Error::Conflict) => StatusCode::CONFLICT,
            PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            UnsupportedMedia => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Unavailable | Pq(innernet_pq::Error::Random) => StatusCode::SERVICE_UNAVAILABLE,
            Pq(_) => StatusCode::BAD_REQUEST,
            InvalidQuery | Json(_) => StatusCode::BAD_REQUEST,
            Database(rusqlite::Error::SqliteFailure(
                libsqlite3_sys::Error {
                    code:
                        libsqlite3_sys::ErrorCode::DatabaseBusy
                        | libsqlite3_sys::ErrorCode::DatabaseLocked
                        | libsqlite3_sys::ErrorCode::DiskFull,
                    ..
                },
                ..,
            )) => StatusCode::SERVICE_UNAVAILABLE,
            // Special-case the constraint violation situation.
            Database(rusqlite::Error::SqliteFailure(libsqlite3_sys::Error { code, .. }, ..))
                if *code == libsqlite3_sys::ErrorCode::ConstraintViolation =>
            {
                StatusCode::BAD_REQUEST
            },
            Database(rusqlite::Error::QueryReturnedNoRows) => StatusCode::NOT_FOUND,
            WireGuard | Io(_) | Database(_) | Http(_) | Hyper(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            },
        }
    }
}

impl TryFrom<ServerError> for Response<Body> {
    type Error = http::Error;

    fn try_from(e: ServerError) -> Result<Self, Self::Error> {
        let mut response = Response::builder().status(StatusCode::from(&e));
        if matches!(
            StatusCode::from(&e),
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
        ) {
            response = response.header("Retry-After", "1");
        }
        response.body(crate::body::empty())
    }
}
