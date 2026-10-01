//! Tokenmaxxing attestation layer, built on TLSNotary.
//!
//! Three roles share this crate:
//!
//! * **Prover** ([`prove`]) — runs on the user's machine. Fetches provider usage endpoints over
//!   MPC-TLS together with our notary, then builds a *presentation* that reveals everything except
//!   credentials (and configured PII paths).
//! * **Notary** ([`notary`]) — runs on our infrastructure. Co-signs the TLS session without ever
//!   seeing plaintext and issues a signed attestation.
//! * **Verifier** ([`verify`]) — runs on our infrastructure. Checks the notary signature, the
//!   server certificate chain, the server name, transcript integrity, and enforces the redaction
//!   policy: nothing may be hidden except the allow-listed secrets.
//!
//! The client is assumed hostile. Every guarantee is enforced by [`verify`], never by the prover.

pub mod admission;
pub mod keys;
pub mod notary;
pub mod prove;
pub mod spec;
pub mod verify;
pub mod ws;

pub use spec::{ProofSpec, RequestSpec, ResponseRedaction};

/// Upper bound on concurrent multiplexed streams per session.
///
/// MPC-TLS preprocessing forks one stream per sub-task; on many-core hosts that fan-out
/// exceeds tlsn-mux's default of 512 within milliseconds. 4096 keeps the connection window
/// at the multiplexer's default 1 GiB (256 KiB credit per stream).
pub const MAX_MUX_STREAMS: usize = 4096;

/// Default cap on MPC executor threads. Proofs are bursty; capping keeps a background
/// client from saturating every core while costing little wall-clock time.
pub const DEFAULT_MPC_THREADS: usize = 8;

/// Session tuning shared by prover and notary. `TMX_MPC_THREADS` overrides the thread cap.
pub fn session_config() -> tlsn::SessionConfig {
    let available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(DEFAULT_MPC_THREADS);
    let threads = std::env::var("TMX_MPC_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or_else(|| available.min(DEFAULT_MPC_THREADS));
    tlsn::SessionConfig {
        max_num_streams: MAX_MUX_STREAMS,
        num_threads: Some(threads),
    }
}
