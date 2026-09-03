//! The shared golden vector for the forum wallet-login wire,
//! `vectors/forum_login_v1.json` from the warren-vectors submodule: the exact
//! signed request bytes a client builds and the exact answer this provider
//! gives per outcome. The login and report suites replay different subsets
//! of it, so not every helper is used by both crates.
#![allow(dead_code)]

use std::collections::BTreeMap;

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt as _;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use warren_connect::nonces::NonceStore;
use warren_connect::verify::{SignedHeaders, VerifiedIdentity, verify_signed_request};
use warren_contract::auth::{canonical_message, sign_request};

/// The vector file, relative to the crate root (the submodule checkout).
const VECTOR_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/forum_login_v1.json");

#[derive(Deserialize)]
pub struct Vector {
    pub version: u32,
    pub signer: Signer,
    pub requests: Vec<SignedRequest>,
    pub responses: Responses,
    pub provider: Provider,
}

#[derive(Deserialize)]
pub struct Signer {
    pub signing_key_hex: String,
    pub pubkey_hex: String,
    pub pubkey_ss58: String,
    pub timestamp: u64,
    pub connect_host: String,
}

#[derive(Deserialize)]
pub struct SignedRequest {
    pub name: String,
    pub method: String,
    pub path: String,
    pub url: String,
    pub nonce_hex: String,
    pub sid: Option<String>,
    pub fields: Option<serde_json::Value>,
    pub log_utf8: Option<String>,
    pub log_gz_hex: Option<String>,
    pub body_utf8: String,
    pub body_sha256_hex: String,
    pub canonical_message: String,
    pub headers: BTreeMap<String, String>,
}

#[derive(Deserialize)]
pub struct Responses {
    pub login: Group,
    pub session_status: Group,
    pub report: Group,
}

/// One outcome group; the `_endpoint` and `_comment` entries ride along as
/// prose, so the answers are decoded on demand by name.
#[derive(Deserialize)]
pub struct Group(BTreeMap<String, serde_json::Value>);

/// Status, Content-Type and exact body bytes of one provider answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Answer {
    pub status: u16,
    pub content_type: String,
    pub body_utf8: String,
}

#[derive(Deserialize)]
pub struct Provider {
    pub handle_secret_utf8: String,
    pub handle: String,
    pub external_id: String,
    pub notify_slot: i32,
    pub topic_id: u64,
    pub forum_public_url: String,
}

pub fn load() -> Vector {
    let raw = std::fs::read_to_string(VECTOR_PATH).unwrap_or_else(|err| {
        panic!("read {VECTOR_PATH}: {err} (run `git submodule update --init`)")
    });
    let vector: Vector = serde_json::from_str(&raw).expect("forum_login_v1.json parses");
    assert_eq!(vector.version, 1, "this suite replays forum_login v1");
    vector
}

/// The request named `name`; an unknown name is a vector this suite has not
/// been taught to replay, which must fail rather than pass by omission.
pub fn request<'a>(vector: &'a Vector, name: &str) -> &'a SignedRequest {
    vector
        .requests
        .iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("unknown forum_login_v1 request name {name}"))
}

impl Signer {
    pub fn signing_key(&self) -> ed25519_dalek::SigningKey {
        let bytes: [u8; 32] = hex::decode(&self.signing_key_hex)
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        ed25519_dalek::SigningKey::from_bytes(&bytes)
    }
}

impl SignedRequest {
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .unwrap_or_else(|| panic!("vector request {} carries no {name}", self.name))
    }

    pub fn nonce(&self) -> [u8; 16] {
        hex::decode(&self.nonce_hex)
            .expect("hex")
            .try_into()
            .expect("16 bytes")
    }

    /// The four `X-Warren-*` values exactly as the vector pins them.
    pub fn signed_headers(&self) -> SignedHeaders {
        SignedHeaders {
            pubkey_ss58: self.header("X-Warren-PubKey").to_owned(),
            signature_hex: self.header("X-Warren-Sig").to_owned(),
            timestamp: self
                .header("X-Warren-Timestamp")
                .parse()
                .expect("timestamp header is an integer"),
            nonce_hex: self.header("X-Warren-Nonce").to_owned(),
        }
    }

    /// The pinned bytes as an HTTP request against this router: every
    /// header verbatim, the body verbatim.
    pub fn as_http(&self) -> Request<Body> {
        let mut builder = Request::builder()
            .method(self.method.as_str())
            .uri(&self.path);
        for (name, value) in &self.headers {
            builder = builder.header(name, value);
        }
        builder
            .body(Body::from(self.body_utf8.clone()))
            .expect("request")
    }

    /// The pinned body signed again at `timestamp` with a fresh nonce: the
    /// same bytes a client sends, stamped inside the provider's clock window.
    pub fn resigned_at(
        &self,
        key: &ed25519_dalek::SigningKey,
        timestamp: u64,
        nonce: [u8; 16],
    ) -> Request<Body> {
        let s = sign_request(
            key,
            &self.method,
            &self.path,
            self.body_utf8.as_bytes(),
            timestamp,
            nonce,
        );
        Request::builder()
            .method(self.method.as_str())
            .uri(&self.path)
            .header("Content-Type", "application/json")
            .header("X-Warren-PubKey", s.pubkey_ss58)
            .header("X-Warren-Sig", s.signature_hex)
            .header("X-Warren-Timestamp", s.timestamp.to_string())
            .header("X-Warren-Nonce", s.nonce_hex)
            .body(Body::from(self.body_utf8.clone()))
            .expect("request")
    }
}

/// The contract's own signer, fed the vector inputs, reproduces the pinned
/// hash, canonical message and headers byte for byte.
pub fn assert_signed_by_the_contract(vector: &Vector, req: &SignedRequest) {
    let body_sha256_hex = hex::encode(Sha256::digest(req.body_utf8.as_bytes()));
    assert_eq!(
        body_sha256_hex, req.body_sha256_hex,
        "{}: body hash",
        req.name
    );
    assert_eq!(
        canonical_message(
            &req.method,
            &req.path,
            vector.signer.timestamp,
            &req.nonce_hex,
            &body_sha256_hex
        ),
        req.canonical_message,
        "{}: canonical message",
        req.name
    );
    let s = sign_request(
        &vector.signer.signing_key(),
        &req.method,
        &req.path,
        req.body_utf8.as_bytes(),
        vector.signer.timestamp,
        req.nonce(),
    );
    assert_eq!(s.pubkey_ss58, req.header("X-Warren-PubKey"), "{}", req.name);
    assert_eq!(s.signature_hex, req.header("X-Warren-Sig"), "{}", req.name);
    assert_eq!(
        s.timestamp.to_string(),
        req.header("X-Warren-Timestamp"),
        "{}",
        req.name
    );
    assert_eq!(s.nonce_hex, req.header("X-Warren-Nonce"), "{}", req.name);
    assert_eq!(
        req.header("Content-Type"),
        "application/json",
        "{}",
        req.name
    );
    assert_eq!(
        req.url,
        format!("https://{}{}", vector.signer.connect_host, req.path),
        "{}: url",
        req.name
    );
}

/// The verifier accepts the pinned headers over the pinned body with its
/// clock set to the vector timestamp, and proves the vector key.
pub fn verify_at_vector_clock(vector: &Vector, req: &SignedRequest) -> VerifiedIdentity {
    let identity = verify_signed_request(
        &req.signed_headers(),
        &req.method,
        &req.path,
        req.body_utf8.as_bytes(),
        vector.signer.timestamp,
        &NonceStore::default(),
    )
    .unwrap_or_else(|err| panic!("{}: the pinned request must verify: {err}", req.name));
    assert_eq!(
        identity.pubkey_ss58, vector.signer.pubkey_ss58,
        "{}",
        req.name
    );
    assert_eq!(
        hex::encode(identity.pubkey),
        vector.signer.pubkey_hex,
        "{}",
        req.name
    );
    identity
}

impl Group {
    /// The answer pinned under `name`; the names this suite replays are the
    /// whole group, checked by [`Group::names`].
    pub fn get(&self, name: &str) -> Answer {
        let value = self
            .0
            .get(name)
            .unwrap_or_else(|| panic!("unknown forum_login_v1 answer name {name}"));
        serde_json::from_value(value.clone()).unwrap_or_else(|err| {
            panic!("answer {name} has the status/content_type/body shape: {err}")
        })
    }

    /// Every outcome name in the group, prose entries excluded.
    pub fn names(&self) -> Vec<&str> {
        self.0
            .keys()
            .filter(|k| !k.starts_with('_'))
            .map(String::as_str)
            .collect()
    }
}

impl Answer {
    /// The same answer with the vector's synthetic forum origin replaced by
    /// this deployment's: the one field a provider fills from its own
    /// configuration.
    pub fn at_forum_origin(&self, vector_origin: &str, origin: &str) -> Answer {
        Answer {
            status: self.status,
            content_type: self.content_type.clone(),
            body_utf8: self.body_utf8.replace(vector_origin, origin),
        }
    }
}

/// Status, Content-Type and body bytes of a router answer.
pub async fn observe(response: axum::response::Response) -> Answer {
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    Answer {
        status,
        content_type,
        body_utf8: String::from_utf8(bytes.to_vec()).expect("utf8 body"),
    }
}

/// Byte-exact on purpose: the clients match tokens as substrings of these
/// bodies, so a re-serialisation with a space or a wrapper object would drop
/// them onto the generic path with every parsed-value assertion still green.
pub fn assert_answer(actual: &Answer, expected: &Answer, what: &str) {
    assert_eq!(actual.status, expected.status, "{what}: status");
    assert_eq!(
        actual.content_type, expected.content_type,
        "{what}: content type"
    );
    assert_eq!(actual.body_utf8, expected.body_utf8, "{what}: body bytes");
}
