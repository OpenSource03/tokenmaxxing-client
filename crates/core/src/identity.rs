//! Device identity: an Ed25519 key registered with the API at pairing time.

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::paths::{Paths, write_private};

#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub server_url: String,
    /// base64 raw 32-byte public key (what the API stores).
    pub public_key: String,
    secret_key_hex: String,
    pub user_id: String,
    pub username: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub paired_at: DateTime<Utc>,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id)
            .field("server_url", &self.server_url)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    pub fn new(
        key: &DeviceKey,
        device_id: String,
        server_url: String,
        user_id: String,
        username: String,
        display_name: Option<String>,
    ) -> Self {
        Self {
            device_id,
            server_url,
            public_key: key.public_key_base64(),
            secret_key_hex: key.secret_hex(),
            user_id,
            username,
            display_name,
            paired_at: Utc::now(),
        }
    }

    pub fn load(paths: &Paths) -> Result<Option<Self>> {
        let path = paths.device_file();
        if !path.exists() {
            return Ok(None);
        }
        let raw =
            std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        Ok(Some(
            serde_json::from_slice(&raw).context("device.json is corrupt")?,
        ))
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        write_private(&paths.device_file(), &serde_json::to_vec_pretty(self)?)
    }

    pub fn forget(paths: &Paths) -> Result<()> {
        match std::fs::remove_file(paths.device_file()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.signing_key()?.sign(message).to_bytes().to_vec())
    }

    fn signing_key(&self) -> Result<SigningKey> {
        let bytes = hex::decode(&self.secret_key_hex).context("device secret key is not hex")?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("device secret key has the wrong length"))?;
        Ok(SigningKey::from_bytes(&arr))
    }
}

/// A freshly generated Ed25519 key, used once at pairing.
pub struct DeviceKey {
    signing: SigningKey,
}

impl DeviceKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self {
            signing: SigningKey::from_bytes(&bytes),
        }
    }
    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.signing.verifying_key().to_bytes())
    }
    pub fn secret_hex(&self) -> String {
        hex::encode(self.signing.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    #[test]
    fn identity_roundtrips_and_signs_verifiably() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().to_path_buf()).unwrap();
        assert!(DeviceIdentity::load(&paths).unwrap().is_none());
        let key = DeviceKey::generate();
        let identity = DeviceIdentity::new(
            &key,
            "dev_1".into(),
            "http://localhost:8787".into(),
            "user_1".into(),
            "alice".into(),
            None,
        );
        identity.save(&paths).unwrap();
        let loaded = DeviceIdentity::load(&paths).unwrap().unwrap();
        assert_eq!(loaded.device_id, "dev_1");
        let sig = loaded.sign(b"hello").unwrap();
        let pub_bytes: [u8; 32] = STANDARD
            .decode(&loaded.public_key)
            .unwrap()
            .try_into()
            .unwrap();
        let verifying = VerifyingKey::from_bytes(&pub_bytes).unwrap();
        assert!(
            verifying
                .verify(
                    b"hello",
                    &ed25519_dalek::Signature::from_slice(&sig).unwrap()
                )
                .is_ok()
        );
        assert!(!format!("{loaded:?}").contains(&key.secret_hex()));
        DeviceIdentity::forget(&paths).unwrap();
        assert!(DeviceIdentity::load(&paths).unwrap().is_none());
    }
}
