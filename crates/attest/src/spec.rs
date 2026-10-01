//! Proof specification: what to fetch, what to hide.

use serde::{Deserialize, Serialize};

/// Placeholder a server-issued spec uses for the locally held credential. The client substitutes
/// it only inside headers listed in `secret_headers`.
pub const CREDENTIAL_PLACEHOLDER: &str = "{{credential}}";

/// One HTTP request inside an attested TLS session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSpec {
    /// HTTP method, e.g. `GET`.
    #[serde(default = "default_method")]
    pub method: String,
    /// Request target, e.g. `/api/oauth/usage`.
    pub path: String,
    /// Headers to send. Values of headers listed in `secret_headers` are never revealed.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Header names (case-insensitive) whose values are redacted from the proof.
    #[serde(default)]
    pub secret_headers: Vec<String>,
    /// Optional request body (sent as-is, revealed in full).
    #[serde(default)]
    pub body: Option<String>,
}

fn default_method() -> String {
    "GET".to_string()
}

/// JSON paths (spansy dot syntax, e.g. `account.email`) redacted from a response body.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseRedaction {
    /// Index of the response within the session (0-based).
    pub response: usize,
    /// Paths whose values are hidden. Structure and all other values stay revealed.
    pub json_paths: Vec<String>,
}

/// Full specification of an attested session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSpec {
    /// DNS name of the TLS server (also used for SNI and `Host`).
    pub server_name: String,
    /// TCP port, default 443.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Requests sent sequentially over one keep-alive connection.
    pub requests: Vec<RequestSpec>,
    /// Response-body redactions.
    #[serde(default)]
    pub redactions: Vec<ResponseRedaction>,
    /// Response header names (case-insensitive) whose values are redacted (e.g. `set-cookie`).
    #[serde(default = "default_secret_response_headers")]
    pub secret_response_headers: Vec<String>,
    /// Upper bound on bytes sent (MPC preprocessing size).
    #[serde(default = "default_max_sent")]
    pub max_sent_data: usize,
    /// Upper bound on bytes received.
    #[serde(default = "default_max_recv")]
    pub max_recv_data: usize,
    /// Bytes the prover may decrypt *online* (while the TLS connection is live).
    ///
    /// Sequential requests over one connection need the response plaintext before the next
    /// request can be sent, so they require online decryption. `None` selects deferred
    /// decryption (cheaper MPC), which is only valid for single-request sessions.
    #[serde(default)]
    pub max_recv_data_online: Option<usize>,
}

fn default_port() -> u16 {
    443
}
fn default_secret_response_headers() -> Vec<String> {
    vec!["set-cookie".to_string()]
}
fn default_max_sent() -> usize {
    1 << 13
}
fn default_max_recv() -> usize {
    1 << 14
}

impl ProofSpec {
    /// Validates structural constraints before any network activity.
    pub fn validate(&self) -> Result<(), String> {
        if self.server_name.is_empty() {
            return Err("server_name is required".into());
        }
        if self.requests.is_empty() {
            return Err("at least one request is required".into());
        }
        if self.requests.len() > 1 && self.max_recv_data_online.is_none() {
            return Err(
                "sequential requests require max_recv_data_online (online decryption)".into(),
            );
        }
        if let Some(online) = self.max_recv_data_online
            && online > self.max_recv_data
        {
            return Err("max_recv_data_online cannot exceed max_recv_data".into());
        }
        for (i, r) in self.requests.iter().enumerate() {
            if !r.path.starts_with('/') {
                return Err(format!("request {i}: path must start with '/'"));
            }
            for (name, _) in &r.headers {
                let lower = name.to_ascii_lowercase();
                if lower == "host" || lower == "connection" || lower == "accept-encoding" {
                    return Err(format!(
                        "request {i}: header '{name}' is managed by the prover"
                    ));
                }
            }
        }
        for red in &self.redactions {
            if red.response >= self.requests.len() {
                return Err(format!(
                    "redaction references response {} which does not exist",
                    red.response
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_managed_headers() {
        let spec = ProofSpec {
            server_name: "example.com".into(),
            port: 443,
            requests: vec![RequestSpec {
                method: "GET".into(),
                path: "/".into(),
                headers: vec![("Host".into(), "x".into())],
                secret_headers: vec![],
                body: None,
            }],
            redactions: vec![],
            secret_response_headers: vec![],
            max_sent_data: 1024,
            max_recv_data: 1024,
            max_recv_data_online: None,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn sequential_requests_need_online_decryption() {
        let req = RequestSpec {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![],
            secret_headers: vec![],
            body: None,
        };
        let mut spec = ProofSpec {
            server_name: "example.com".into(),
            port: 443,
            requests: vec![req.clone(), req],
            redactions: vec![],
            secret_response_headers: vec![],
            max_sent_data: 1024,
            max_recv_data: 1024,
            max_recv_data_online: None,
        };
        assert!(spec.validate().is_err());
        spec.max_recv_data_online = Some(1024);
        assert!(spec.validate().is_ok());
        spec.max_recv_data_online = Some(2048);
        assert!(spec.validate().is_err());
    }
}
