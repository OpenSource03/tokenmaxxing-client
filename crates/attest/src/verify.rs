//! Verifier: runs on our infrastructure. Pure math, no network.
//!
//! Checks, in order:
//! 1. the attestation is signed by a trusted notary key;
//! 2. the attestation itself verifies (signature, commitments);
//! 3. the server identity proof verifies against Mozilla roots and equals the expected name;
//! 4. the transcript proof verifies (revealed bytes match commitments);
//! 5. the redaction policy: every unauthenticated byte lies inside an allow-listed secret.

use rangeset::{
    iter::{FromRangeIterator, RangeIterator},
    ops::Set,
    set::RangeSet,
};
use serde::{Deserialize, Serialize};

use tlsn::{
    attestation::{
        CryptoProvider,
        presentation::{Presentation, PresentationOutput},
    },
    connection::TlsVersion,
    transcript::Transcript,
};
use tlsn_formats::http::{BodyContent, HttpTranscript};

use crate::{keys::normalise_key_hex, spec::ResponseRedaction};

/// Byte used to fill unauthenticated (hidden) transcript positions.
pub const REDACTED_BYTE: u8 = b'X';

/// What the verifier is asked to check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyInput {
    /// bincode-serialised presentation.
    #[serde(with = "base64_bytes")]
    pub presentation: Vec<u8>,
    /// DNS name the session must have been with.
    pub expected_server_name: String,
    /// Hex-encoded notary verifying keys we trust.
    pub trusted_notary_keys: Vec<String>,
    /// Request header names whose values may be hidden.
    #[serde(default)]
    pub secret_request_headers: Vec<String>,
    /// Response header names whose values may be hidden.
    #[serde(default)]
    pub secret_response_headers: Vec<String>,
    /// Response-body JSON paths whose values may be hidden.
    #[serde(default)]
    pub redactions: Vec<ResponseRedaction>,
}

/// A header as seen by the verifier. `value` is `None` when it was (legitimately) hidden.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedHeader {
    /// Header name.
    pub name: String,
    /// Header value, `None` if redacted.
    pub value: Option<String>,
}

/// Authenticated request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedRequest {
    /// HTTP method.
    pub method: String,
    /// Request target (path + query).
    pub target: String,
    /// Headers in wire order.
    pub headers: Vec<VerifiedHeader>,
    /// Body, if any (always fully authenticated).
    pub body: Option<String>,
}

/// Authenticated response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedResponse {
    /// HTTP status code.
    pub status: u16,
    /// Headers in wire order.
    pub headers: Vec<VerifiedHeader>,
    /// Body content (de-chunked). Hidden values appear as runs of `X`.
    pub body: String,
    /// Parsed JSON body, if parseable.
    pub body_json: Option<serde_json::Value>,
    /// JSON paths that were hidden.
    pub redacted_paths: Vec<String>,
}

/// Result of a successful verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedSession {
    /// Hex of the notary verifying key that signed the attestation.
    pub notary_key: String,
    /// Authenticated server DNS name.
    pub server_name: String,
    /// Unix time (seconds) the TLS connection started, recorded by the notary.
    pub time: u64,
    /// TLS version.
    pub tls_version: String,
    /// Bytes sent / received in the session.
    pub sent_len: usize,
    /// Bytes received.
    pub recv_len: usize,
    /// Requests, in order.
    pub requests: Vec<VerifiedRequest>,
    /// Responses, in order.
    pub responses: Vec<VerifiedResponse>,
}

/// Verification failure. Every variant is a hard reject.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Presentation bytes could not be decoded.
    #[error("malformed presentation: {0}")]
    Malformed(String),
    /// Notary key not in the trusted set.
    #[error("untrusted notary key {0}")]
    UntrustedNotary(String),
    /// Cryptographic verification failed.
    #[error("presentation verification failed: {0}")]
    Crypto(String),
    /// Server identity missing or mismatched.
    #[error("server name mismatch: expected {expected}, got {actual}")]
    ServerName {
        /// Expected DNS name.
        expected: String,
        /// Actual DNS name.
        actual: String,
    },
    /// Transcript missing from presentation.
    #[error("presentation contains no transcript proof")]
    NoTranscript,
    /// HTTP transcript could not be parsed.
    #[error("cannot parse HTTP transcript: {0}")]
    Http(String),
    /// Redaction policy violated.
    #[error("redaction policy violated: {0}")]
    Policy(String),
}

/// Verifies a presentation and enforces the redaction policy.
pub fn verify(input: &VerifyInput) -> Result<VerifiedSession, VerifyError> {
    let presentation: Presentation = bincode::deserialize(&input.presentation)
        .map_err(|e| VerifyError::Malformed(e.to_string()))?;

    // 1. Notary trust.
    let key = presentation.verifying_key();
    let notary_key = hex::encode(&key.data);
    let trusted = input
        .trusted_notary_keys
        .iter()
        .any(|k| normalise_key_hex(k) == notary_key);
    if !trusted {
        return Err(VerifyError::UntrustedNotary(notary_key));
    }

    // 2–4. Cryptographic verification (attestation signature, identity, transcript).
    let provider = CryptoProvider::default();
    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = presentation
        .verify(&provider)
        .map_err(|e| VerifyError::Crypto(e.to_string()))?;

    let actual_server = server_name
        .map(|s| s.to_string())
        .unwrap_or_else(|| "<none>".to_string());
    if !actual_server.eq_ignore_ascii_case(&input.expected_server_name) {
        return Err(VerifyError::ServerName {
            expected: input.expected_server_name.clone(),
            actual: actual_server,
        });
    }

    let mut partial = transcript.ok_or(VerifyError::NoTranscript)?;
    let sent_authed = partial.sent_authed().clone();
    let recv_authed = partial.received_authed().clone();
    let sent_unauthed = partial.sent_unauthed();
    let recv_unauthed = partial.received_unauthed();
    partial.set_unauthed(REDACTED_BYTE);

    let sent = partial.sent_unsafe().to_vec();
    let recv = partial.received_unsafe().to_vec();
    let http = HttpTranscript::parse(&Transcript::new(sent.clone(), recv.clone()))
        .map_err(|e| VerifyError::Http(e.to_string()))?;

    // 5. Redaction policy.
    let secret_req: Vec<String> = lower(&input.secret_request_headers);
    let secret_resp: Vec<String> = lower(&input.secret_response_headers);

    let mut allowed_sent: RangeSet<usize> = RangeSet::default();
    let mut requests = Vec::with_capacity(http.requests.len());
    for request in &http.requests {
        let mut headers = Vec::with_capacity(request.headers.len());
        for header in &request.headers {
            let name = header.name.as_str().to_string();
            let hidden = secret_req.contains(&name.to_ascii_lowercase());
            let value_authed = sent_authed.is_superset(header.value.indices());
            if hidden {
                allowed_sent.union_mut(header.value.indices());
            }
            headers.push(VerifiedHeader {
                name,
                value: if value_authed {
                    Some(String::from_utf8_lossy(&header.value.as_bytes()).into_owned())
                } else {
                    None
                },
            });
        }
        requests.push(VerifiedRequest {
            method: request.request.method.as_str().to_string(),
            target: request.request.target.as_str().to_string(),
            headers,
            body: request
                .body
                .as_ref()
                .map(|b| String::from_utf8_lossy(&b.content_data()).into_owned()),
        });
    }
    if !sent_unauthed.is_subset(&allowed_sent) {
        return Err(VerifyError::Policy(format!(
            "{} sent bytes hidden outside allowed secret headers",
            sent_unauthed.difference(&allowed_sent).into_set().len()
        )));
    }

    let mut allowed_recv: RangeSet<usize> = RangeSet::default();
    let mut responses = Vec::with_capacity(http.responses.len());
    for (i, response) in http.responses.iter().enumerate() {
        let mut headers = Vec::with_capacity(response.headers.len());
        for header in &response.headers {
            let name = header.name.as_str().to_string();
            let hidden = secret_resp.contains(&name.to_ascii_lowercase());
            let value_authed = recv_authed.is_superset(header.value.indices());
            if hidden {
                allowed_recv.union_mut(header.value.indices());
            }
            headers.push(VerifiedHeader {
                name,
                value: if value_authed {
                    Some(String::from_utf8_lossy(&header.value.as_bytes()).into_owned())
                } else {
                    None
                },
            });
        }

        let mut redacted_paths = Vec::new();
        let body_text = match &response.body {
            Some(body) => {
                if let BodyContent::Json(doc) = &body.content {
                    for redaction in input.redactions.iter().filter(|r| r.response == i) {
                        for path in &redaction.json_paths {
                            if let Some(value) = doc.get(path) {
                                let idx = RangeSet::from_range_iter(value.clone());
                                if !recv_authed.is_superset(&idx) {
                                    redacted_paths.push(path.clone());
                                }
                                allowed_recv.union_mut(idx);
                            }
                        }
                    }
                }
                String::from_utf8_lossy(&body.content_data()).into_owned()
            }
            None => String::new(),
        };
        let status = response
            .status
            .code
            .as_str()
            .parse::<u16>()
            .map_err(|e| VerifyError::Http(format!("bad status code: {e}")))?;
        let body_json = serde_json::from_str::<serde_json::Value>(&body_text).ok();
        responses.push(VerifiedResponse {
            status,
            headers,
            body: body_text,
            body_json,
            redacted_paths,
        });
    }
    if !recv_unauthed.is_subset(&allowed_recv) {
        return Err(VerifyError::Policy(format!(
            "{} received bytes hidden outside allowed redactions",
            recv_unauthed.difference(&allowed_recv).into_set().len()
        )));
    }

    Ok(VerifiedSession {
        notary_key,
        server_name: actual_server,
        time: connection_info.time,
        tls_version: match connection_info.version {
            TlsVersion::V1_2 => "1.2".to_string(),
            TlsVersion::V1_3 => "1.3".to_string(),
        },
        sent_len: sent.len(),
        recv_len: recv.len(),
        requests,
        responses,
    })
}

fn lower(v: &[String]) -> Vec<String> {
    v.iter().map(|s| s.to_ascii_lowercase()).collect()
}

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}
