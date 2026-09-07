use crate::body::Body;
use http_body_util::{BodyExt, Limited};
use hyper::{header, Request, Response, StatusCode};
use serde::{de::DeserializeOwned, Serialize};

use crate::ServerError;

pub async fn form_body<F: DeserializeOwned>(req: Request<Body>) -> Result<F, ServerError> {
    let content_len: usize = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.parse().ok())
        .ok_or(ServerError::InvalidQuery)?;

    if content_len > 16 * 1024 {
        return Err(ServerError::InvalidQuery);
    }

    let whole_body = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Limited::new(req.into_body(), 16 * 1024).collect(),
    )
    .await
    .map_err(|_| ServerError::InvalidQuery)?
    .map_err(|_| ServerError::InvalidQuery)?
    .to_bytes();
    serde_json::from_slice(&whole_body).map_err(Into::into)
}

pub fn json_response<F: Serialize>(form: F) -> Result<Response<Body>, ServerError> {
    let json = serde_json::to_string(&form)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(crate::body::full(json))?)
}

pub fn json_status_response<F: Serialize>(
    form: F,
    status: StatusCode,
) -> Result<Response<Body>, ServerError> {
    let json = serde_json::to_string(&form)?;
    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(crate::body::full(json))?)
}

pub fn status_response(status: StatusCode) -> Result<Response<Body>, ServerError> {
    Ok(Response::builder()
        .status(status)
        .body(crate::body::empty())?)
}
