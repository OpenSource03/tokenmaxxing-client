//! Notary signing-key helpers (secp256k1).

use std::{io::Write, path::Path};

use anyhow::{Context, Result, bail};
use k256::ecdsa::SigningKey;
use rand::RngCore;

/// Generates a fresh secp256k1 signing key.
pub fn generate_signing_key() -> [u8; 32] {
    loop {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        if SigningKey::from_slice(&key).is_ok() {
            return key;
        }
    }
}

/// Hex of the compressed SEC1 verifying key, the exact bytes TLSNotary embeds in attestations.
pub fn verifying_key_hex(key: &[u8]) -> Result<String> {
    let sk = SigningKey::from_slice(key).context("invalid secp256k1 signing key")?;
    Ok(hex::encode(sk.verifying_key().to_sec1_bytes()))
}

/// Canonical form for comparing hex keys.
pub fn normalise_key_hex(key: &str) -> String {
    key.trim().trim_start_matches("0x").to_ascii_lowercase()
}

/// Writes a signing key as hex, refusing to overwrite and with owner-only permissions.
pub fn write_signing_key(path: &Path, key: &[u8; 32]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(hex::encode(key).as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

/// Loads a hex signing key written by [`write_signing_key`].
pub fn load_signing_key(path: &Path) -> Result<[u8; 32]> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read notary key {}", path.display()))?;
    let bytes = hex::decode(normalise_key_hex(&raw)).context("notary key is not hex")?;
    if bytes.len() != 32 {
        bail!("notary key must be 32 bytes, got {}", bytes.len());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    SigningKey::from_slice(&key).context("notary key is not a valid secp256k1 scalar")?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_key_file() {
        let dir = std::env::temp_dir().join(format!("tmx-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notary.key");
        let key = generate_signing_key();
        write_signing_key(&path, &key).unwrap();
        assert!(
            write_signing_key(&path, &key).is_err(),
            "must not overwrite"
        );
        let loaded = load_signing_key(&path).unwrap();
        assert_eq!(key, loaded);
        assert_eq!(verifying_key_hex(&key).unwrap().len(), 66);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn normalises_hex() {
        assert_eq!(normalise_key_hex(" 0xABcd\n"), "abcd");
    }
}
