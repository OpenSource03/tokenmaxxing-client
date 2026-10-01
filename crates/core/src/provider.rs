use std::fmt;

use serde::{Deserialize, Serialize};

/// Supported providers. Serialised ids match the API's `Provider` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Provider {
    Claude,
    Codex,
    Cursor,
    Zai,
    Openrouter,
}

impl Provider {
    pub const ALL: [Provider; 5] = [
        Provider::Claude,
        Provider::Codex,
        Provider::Cursor,
        Provider::Zai,
        Provider::Openrouter,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Provider::Claude => "CLAUDE",
            Provider::Codex => "CODEX",
            Provider::Cursor => "CURSOR",
            Provider::Zai => "ZAI",
            Provider::Openrouter => "OPENROUTER",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Provider::Claude => "Claude Code",
            Provider::Codex => "Codex",
            Provider::Cursor => "Cursor",
            Provider::Zai => "Z.ai",
            Provider::Openrouter => "OpenRouter",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|p| p.id().eq_ignore_ascii_case(id))
    }

    /// Providers without a desktop login: the user pastes an API key into the app.
    pub fn takes_api_key(self) -> bool {
        matches!(self, Provider::Zai | Provider::Openrouter)
    }

    /// Providers whose exact per-request tokens come from local session logs (BOUNDED tier).
    pub fn has_local_logs(self) -> bool {
        matches!(self, Provider::Claude | Provider::Codex)
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_roundtrip_through_serde_and_from_id() {
        for p in Provider::ALL {
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(json, format!("\"{}\"", p.id()));
            assert_eq!(serde_json::from_str::<Provider>(&json).unwrap(), p);
            assert_eq!(Provider::from_id(p.id()), Some(p));
        }
        assert_eq!(Provider::from_id("nope"), None);
    }
}
