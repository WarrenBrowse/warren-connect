//! The shared golden vector for the bound forum login,
//! `vectors/forum_login_v2.json` from the warren-vectors submodule: the
//! signed approval request a client builds, the completion object it gets
//! back, and the provider's answer per outcome on the browser half (cookie,
//! state poll, confirm, completion, handoff).

use std::collections::BTreeMap;

use axum::body::Body;
use axum::http::Request;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use warren_connect::nonces::NonceStore;
use warren_connect::verify::{SignedHeaders, VerifiedIdentity, verify_signed_request};
use warren_contract::auth::{canonical_message, sign_request};

use crate::forum_vector::Answer;

const VECTOR_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/forum_login_v2.json");

#[derive(Deserialize)]
pub struct Vector {
    pub version: u32,
    pub signer: Signer,
    pub requests: Vec<SignedRequest>,
    pub cookie: Cookie,
    pub handoff: Handoff,
    pub states: States,
    pub responses: BTreeMap<String, serde_json::Value>,
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
    pub sid: String,
    pub body_utf8: String,
    pub body_sha256_hex: String,
    pub canonical_message: String,
    pub headers: BTreeMap<String, String>,
}

#[derive(Deserialize)]
pub struct Cookie {
    pub name: String,
    pub example_value: String,
    pub example_set_cookie: String,
}

#[derive(Deserialize)]
pub struct Handoff {
    pub path: String,
    pub example: String,
}

#[derive(Deserialize)]
pub struct States {
    pub status: Vec<String>,
    pub cancel_reasons: Vec<String>,
}

#[derive(Deserialize)]
pub struct Provider {
    pub handle_secret_utf8: String,
    pub handle: String,
    pub external_id: String,
    pub notify_slot: i32,
    pub completion_code: String,
    pub qr_sid: String,
    pub forum_public_url: String,
}

pub fn load() -> Vector {
    let raw = std::fs::read_to_string(VECTOR_PATH).unwrap_or_else(|err| {
        panic!("read {VECTOR_PATH}: {err} (run `git submodule update --init`)")
    });
    let vector: Vector = serde_json::from_str(&raw).expect("forum_login_v2.json parses");
    assert_eq!(vector.version, 2, "this suite replays forum_login v2");
    vector
}

impl Vector {
    /// The request named `name`; an unknown name has no replay here, which
    /// must fail rather than pass by omission.
    pub fn request(&self, name: &str) -> &SignedRequest {
        self.requests
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("unknown forum_login_v2 request name {name}"))
    }

    fn group(&self, group: &str) -> &serde_json::Map<String, serde_json::Value> {
        self.responses
            .get(group)
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| panic!("unknown forum_login_v2 answer group {group}"))
    }

    /// The raw pinned entry, for the redirect fields an [`Answer`] leaves out.
    pub fn entry(&self, group: &str, name: &str) -> &serde_json::Value {
        self.group(group)
            .get(name)
            .unwrap_or_else(|| panic!("unknown forum_login_v2 answer {group}.{name}"))
    }

    pub fn answer(&self, group: &str, name: &str) -> Answer {
        serde_json::from_value(self.entry(group, name).clone())
            .unwrap_or_else(|err| panic!("{group}.{name} has the answer shape: {err}"))
    }

    /// Every answer group and its outcome names, prose entries excluded.
    pub fn names(&self) -> BTreeMap<&str, Vec<&str>> {
        self.responses
            .iter()
            .filter(|(group, _)| !group.starts_with('_'))
            .map(|(group, entries)| {
                let names = entries
                    .as_object()
                    .map(|o| {
                        o.keys()
                            .filter(|k| !k.starts_with('_'))
                            .map(String::as_str)
                            .collect()
                    })
                    .unwrap_or_default();
                (group.as_str(), names)
            })
            .collect()
    }
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

    /// The pinned bytes verbatim against this router.
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

    /// `body` signed at `timestamp` with a fresh nonce, as a client sends it.
    pub fn signed_body(
        &self,
        key: &ed25519_dalek::SigningKey,
        body: &str,
        timestamp: u64,
        nonce: [u8; 16],
    ) -> Request<Body> {
        let s = sign_request(
            key,
            &self.method,
            &self.path,
            body.as_bytes(),
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
            .body(Body::from(body.to_owned()))
            .expect("request")
    }
}

/// The contract's own signer reproduces the pinned hash, canonical message
/// and headers, and this verifier accepts them at the vector clock.
pub fn assert_signed_and_verified(vector: &Vector, req: &SignedRequest) -> VerifiedIdentity {
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
    let nonce: [u8; 16] = hex::decode(&req.nonce_hex)
        .expect("hex")
        .try_into()
        .expect("16 bytes");
    let s = sign_request(
        &vector.signer.signing_key(),
        &req.method,
        &req.path,
        req.body_utf8.as_bytes(),
        vector.signer.timestamp,
        nonce,
    );
    assert_eq!(s.pubkey_ss58, req.header("X-Warren-PubKey"), "{}", req.name);
    assert_eq!(s.signature_hex, req.header("X-Warren-Sig"), "{}", req.name);
    assert_eq!(s.nonce_hex, req.header("X-Warren-Nonce"), "{}", req.name);
    assert_eq!(
        req.header("X-Warren-Timestamp"),
        vector.signer.timestamp.to_string()
    );
    assert_eq!(req.header("Content-Type"), "application/json");
    assert_eq!(
        req.url,
        format!("https://{}{}", vector.signer.connect_host, req.path)
    );
    let identity = verify_signed_request(
        &SignedHeaders {
            pubkey_ss58: req.header("X-Warren-PubKey").to_owned(),
            signature_hex: req.header("X-Warren-Sig").to_owned(),
            timestamp: vector.signer.timestamp,
            nonce_hex: req.nonce_hex.clone(),
        },
        &req.method,
        &req.path,
        req.body_utf8.as_bytes(),
        vector.signer.timestamp,
        &NonceStore::default(),
    )
    .unwrap_or_else(|err| panic!("{}: the pinned request must verify: {err}", req.name));
    assert_eq!(identity.pubkey_ss58, vector.signer.pubkey_ss58);
    assert_eq!(hex::encode(identity.pubkey), vector.signer.pubkey_hex);
    identity
}
