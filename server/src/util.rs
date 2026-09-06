use bytes::Buf;
use hyper::{header, Body, Request, Response, StatusCode};
use serde::{de::DeserializeOwned, Serialize};

use crate::ServerError;

pub async fn form_body<F: DeserializeOwned>(req: Request<Body>) -> Result<F, ServerError> {
    form_body_with_limit(req, 16 * 1024).await
}

/// Like [`form_body`], but with a caller-specified max body size instead of the default 16 KiB.
///
/// Used by endpoints whose legitimate payload is much larger than a typical form body (e.g. a
/// Rosenpass public key, a ~512 KiB Classic McEliece key rather than a compact WireGuard key) —
/// still a firm, bounded ceiling, just a larger one, checked against `Content-Length` before the
/// body is ever read into memory.
pub async fn form_body_with_limit<F: DeserializeOwned>(
    req: Request<Body>,
    max_content_len: usize,
) -> Result<F, ServerError> {
    let content_len: usize = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.parse().ok())
        .ok_or(ServerError::InvalidQuery)?;

    if content_len > max_content_len {
        return Err(ServerError::InvalidQuery);
    }

    let whole_body = hyper::body::aggregate(req).await?;

    serde_json::from_reader(whole_body.reader()).map_err(Into::into)
}

pub fn json_response<F: Serialize>(form: F) -> Result<Response<Body>, ServerError> {
    let json = serde_json::to_string(&form)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json))?)
}

pub fn json_status_response<F: Serialize>(
    form: F,
    status: StatusCode,
) -> Result<Response<Body>, ServerError> {
    let json = serde_json::to_string(&form)?;
    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json))?)
}

pub fn status_response(status: StatusCode) -> Result<Response<Body>, ServerError> {
    Ok(Response::builder().status(status).body(Body::empty())?)
}
