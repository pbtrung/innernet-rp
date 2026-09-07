use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};

pub type Body = BoxBody<Bytes, hyper::Error>;

pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

pub fn empty() -> Body {
    full(Bytes::new())
}

#[cfg(test)]
pub async fn aggregate(response: hyper::Response<Body>) -> Result<Bytes, hyper::Error> {
    Ok(response.into_body().collect().await?.to_bytes())
}
