//! Local data directory and private-file helpers.

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};

#[derive(Debug, Clone)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    /// `$TMX_HOME` if set, else the platform application-data directory.
    pub fn discover() -> Result<Self> {
        if let Ok(dir) = std::env::var("TMX_HOME") {
            return Self::at(PathBuf::from(dir));
        }
        let dirs = directories::ProjectDirs::from("com", "tokenmaxxing", "Tokenmaxxing")
            .ok_or_else(|| anyhow!("cannot determine an application data directory"))?;
        Self::at(dirs.data_dir().to_path_buf())
    }

    pub fn at(root: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&root)
            .with_context(|| format!("cannot create {}", root.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn device_file(&self) -> PathBuf {
        self.root.join("device.json")
    }
    pub fn providers_file(&self) -> PathBuf {
        self.root.join("providers.json")
    }
    pub fn state_file(&self) -> PathBuf {
        self.root.join("state.json")
    }
    pub fn log_file(&self) -> PathBuf {
        self.root.join("tokenmaxxing.log")
    }
}

pub fn home_dir() -> Result<PathBuf> {
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return Ok(PathBuf::from(home));
    }
    directories::BaseDirs::new()
        .map(|d| d.home_dir().to_path_buf())
        .ok_or_else(|| anyhow!("cannot determine the home directory"))
}

/// Writes `bytes` atomically with owner-only permissions.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .with_context(|| format!("cannot write {}", tmp.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("cannot move {} into place", tmp.display()))?;
    Ok(())
}
