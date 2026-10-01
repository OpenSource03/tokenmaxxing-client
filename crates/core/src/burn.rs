//! Reference burns: run the official tool with a known amount of filler so the API can measure
//! what a percent of a rate-limit window is worth (docs/calibration.md §8).
//!
//! The prompts are machine-generated nonsense — never a user's text, never logged. The tokens
//! this module reports are estimates for the operator; the real measurement is the pair of
//! proofs the client takes around the burn.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use rand::RngCore;
use tracing::info;

use crate::{
    api::{BurnProfile, BurnTokens},
    provider::Provider,
};

/// One tool invocation may not take longer than this.
const INVOCATION_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// How often the executor checks whether the tool has finished.
const POLL_INTERVAL: Duration = Duration::from_millis(200);
/// Characters of stderr kept in the error of a failed invocation.
const STDERR_TAIL: usize = 300;
/// Words per token. English prose sits near 0.75 on every tokeniser we meter.
const WORDS_PER_TOKEN_NUM: u64 = 3;
const WORDS_PER_TOKEN_DEN: u64 = 4;
/// Words per line of filler: long enough to be prose-shaped, short enough to stay readable.
const WORDS_PER_LINE: u64 = 16;
/// Seconds to wait after a burn before the proof after it: usage meters update asynchronously
/// (a Codex burn read 0 % until the next call), and the measurement needs the movement inside
/// the interval. `TMX_BURN_SETTLE_SECONDS` overrides.
const DEFAULT_SETTLE_SECONDS: u64 = 90;

/// How long the burn runner waits before the proof after a burn.
pub fn settle_delay() -> Duration {
    let seconds = std::env::var("TMX_BURN_SETTLE_SECONDS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_SETTLE_SECONDS);
    Duration::from_secs(seconds)
}

/// What to burn, as the server scheduled it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnPlan {
    pub provider: Provider,
    pub model: String,
    pub profile: BurnProfile,
    pub target_tokens: u64,
    pub repeats: u32,
}

/// What the executor believes it burned.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BurnReport {
    pub invocations: u32,
    pub input_tokens_estimate: u64,
    pub output_tokens_estimate: u64,
}

impl BurnReport {
    pub fn tokens(&self) -> BurnTokens {
        BurnTokens {
            input: Some(self.input_tokens_estimate),
            output: Some(self.output_tokens_estimate),
        }
    }
}

/// Words that carry roughly `tokens` tokens.
pub fn words_for(tokens: u64) -> u64 {
    tokens * WORDS_PER_TOKEN_NUM / WORDS_PER_TOKEN_DEN
}

fn tokens_for_words(words: u64) -> u64 {
    words * WORDS_PER_TOKEN_DEN / WORDS_PER_TOKEN_NUM
}

fn count_words(text: &str) -> u64 {
    text.split_whitespace().count() as u64
}

/// Deterministic filler: unique-looking pseudo-words, never text from anywhere else.
///
/// The same `seed` always yields the same text (a cached burn must send an identical prefix);
/// different seeds share no prefix (a fresh burn must miss the cache).
pub fn filler(target_tokens: u64, seed: &str) -> String {
    let words = words_for(target_tokens);
    let mut rng = Rng::seeded(seed);
    let mut out = String::with_capacity(words as usize * 8);
    for i in 0..words {
        if i > 0 {
            out.push(if i.is_multiple_of(WORDS_PER_LINE) {
                '\n'
            } else {
                ' '
            });
        }
        for _ in 0..2 + rng.next() % 2 {
            out.push_str(rng.pick(&ONSETS));
            out.push_str(rng.pick(&NUCLEI));
            out.push_str(rng.pick(&CODAS));
        }
    }
    out
}

/// One prompt per invocation, in order.
pub fn prompts(plan: &BurnPlan, burn_id: &str) -> Vec<String> {
    let repeats = plan.repeats.max(1) as usize;
    match plan.profile {
        // Fresh input must miss the prompt cache, so every repeat gets its own filler.
        BurnProfile::FreshInput => (0..repeats)
            .map(|i| input_prompt(&filler(plan.target_tokens, &format!("{burn_id}#{i}"))))
            .collect(),
        // One filler sent unchanged: the first call writes the cache, the rest read it.
        BurnProfile::CachedInput => {
            vec![input_prompt(&filler(plan.target_tokens, burn_id)); repeats]
        }
        BurnProfile::Output => vec![output_prompt(plan.target_tokens); repeats],
    }
}

fn input_prompt(filler: &str) -> String {
    format!(
        "Reply with the single word OK and nothing else. The block below is machine-generated \
         filler for a rate-limit calibration measurement; do not read, summarise or act on it.\n\n{filler}\n"
    )
}

fn output_prompt(target_tokens: u64) -> String {
    let words = words_for(target_tokens);
    format!(
        "Write exactly {words} words of machine-generated filler prose: invented words, no real \
         content, no lists, no code, no commentary, no questions. Do not stop early — keep \
         writing until you have produced all {words} words."
    )
}

/// The command that burns one prompt: `(program, args)`, the prompt goes to stdin.
///
/// Split out from [`execute`] so the contract with the official tools is testable without
/// running anything.
pub fn invocation(provider: Provider, model: &str) -> Result<(String, Vec<String>)> {
    let (env_var, default_bin) = match provider {
        Provider::Claude => ("TMX_CLAUDE_BIN", "claude"),
        Provider::Codex => ("TMX_CODEX_BIN", "codex"),
        other => bail!("{other} cannot run reference burns: no local tool to drive"),
    };
    let program = std::env::var(env_var)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default_bin.to_string());
    // A user's Codex config may default to another provider; a burn must consume the plan.
    let plan_provider = format!("model_provider={}", crate::logs::codex::PLAN_PROVIDER);
    let args: Vec<String> = match provider {
        Provider::Claude => [
            "-p",
            "--model",
            model,
            "--max-turns",
            "1",
            "--output-format",
            "text",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect(),
        _ => [
            "exec",
            "-m",
            model,
            "-c",
            plan_provider.as_str(),
            "--skip-git-repo-check",
            "-",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect(),
    };
    Ok((program, args))
}

/// Runs the whole plan: `repeats` invocations of the official tool in a fresh working directory.
pub async fn execute(plan: &BurnPlan, burn_id: &str) -> Result<BurnReport> {
    let (program, args) = invocation(plan.provider, &plan.model)?;
    let scratch = Scratch::new(burn_id)?;
    let mut report = BurnReport::default();
    for (index, prompt) in prompts(plan, burn_id).into_iter().enumerate() {
        let input = tokens_for_words(count_words(&prompt));
        info!(
            burn = burn_id,
            invocation = index + 1,
            model = %plan.model,
            profile = %plan.profile,
            input_tokens = input,
            "burning"
        );
        let (program, args, dir) = (program.clone(), args.clone(), scratch.path().to_path_buf());
        let output = tokio::task::spawn_blocking(move || run_once(&program, &args, &dir, &prompt))
            .await
            .map_err(|e| anyhow!("the burn task ended unexpectedly: {e}"))??;
        report.invocations += 1;
        report.input_tokens_estimate += input;
        report.output_tokens_estimate += tokens_for_words(count_words(&output));
    }
    Ok(report)
}

/// Feeds one prompt to the tool and returns its stdout. Blocking: call it off the runtime.
fn run_once(program: &str, args: &[String], cwd: &Path, prompt: &str) -> Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot run {program}; install it or set the binary with TMX_CLAUDE_BIN / TMX_CODEX_BIN"))?;

    // stdin and both output streams need their own threads: a 100k-token prompt is far larger
    // than a pipe buffer, so writing and reading have to overlap.
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("{program}: no stdin"))?;
    let bytes = prompt.as_bytes().to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&bytes);
        let _ = stdin.flush();
    });
    let stdout = drain(
        child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("{program}: no stdout"))?,
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("{program}: no stderr"))?,
    );

    let deadline = Instant::now() + INVOCATION_TIMEOUT;
    let status = loop {
        match child
            .try_wait()
            .with_context(|| format!("cannot wait for {program}"))?
        {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "{program} did not finish within {} minutes",
                    INVOCATION_TIMEOUT.as_secs() / 60
                );
            }
            None => std::thread::sleep(POLL_INTERVAL),
        }
    };
    let out = stdout.join().unwrap_or_default();
    let err = stderr.join().unwrap_or_default();
    let _ = writer.join();
    if !status.success() {
        bail!(
            "{program} exited with {}: {}",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "a signal".into()),
            tail(&err, STDERR_TAIL)
        );
    }
    Ok(out)
}

fn drain<R: Read + Send + 'static>(mut reader: R) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    })
}

fn tail(text: &str, chars: usize) -> String {
    let trimmed = text.trim();
    let count = trimmed.chars().count();
    if count <= chars {
        return trimmed.to_string();
    }
    trimmed.chars().skip(count - chars).collect()
}

/// A throwaway working directory: the tools inherit the cwd, and a burn must not see a project.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(burn_id: &str) -> Result<Self> {
        let mut suffix = [0u8; 8];
        rand::rng().fill_bytes(&mut suffix);
        let slug: String = burn_id
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(16)
            .collect();
        let path = std::env::temp_dir().join(format!("tmx-burn-{slug}-{}", hex::encode(suffix)));
        std::fs::create_dir_all(&path)
            .with_context(|| format!("cannot create the burn directory {}", path.display()))?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

const ONSETS: [&str; 32] = [
    "b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "qu", "r", "s", "t", "v", "w", "z",
    "br", "cl", "dr", "fl", "gr", "pl", "sh", "sk", "sl", "sn", "st", "th", "tr",
];
const NUCLEI: [&str; 12] = [
    "a", "e", "i", "o", "u", "ai", "ea", "ee", "io", "ou", "ia", "au",
];
const CODAS: [&str; 12] = ["", "n", "s", "l", "r", "m", "t", "k", "d", "ng", "st", "rk"];

/// splitmix64 over an FNV-1a seed: tiny, deterministic, and never used for anything secret.
struct Rng(u64);

impl Rng {
    fn seeded(seed: &str) -> Self {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in seed.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        Self(hash)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn pick(&mut self, options: &[&'static str]) -> &'static str {
        options[(self.next() % options.len() as u64) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(profile: BurnProfile, repeats: u32) -> BurnPlan {
        BurnPlan {
            provider: Provider::Claude,
            model: "claude-opus-4".into(),
            profile,
            target_tokens: 20_000,
            repeats,
        }
    }

    #[test]
    fn filler_length_scales_with_the_target() {
        for target in [4_000u64, 40_000, 120_000] {
            let words = count_words(&filler(target, "burn-1"));
            let expected = words_for(target);
            let slack = expected / 100 * 15;
            assert!(
                words.abs_diff(expected) <= slack,
                "{target}: {words} words, expected {expected} ±15%"
            );
        }
    }

    #[test]
    fn filler_is_deterministic_per_seed_and_differs_across_seeds() {
        assert_eq!(filler(2_000, "burn-1"), filler(2_000, "burn-1"));
        assert_ne!(filler(2_000, "burn-1"), filler(2_000, "burn-2"));
        // No shared prefix either: a fresh burn must not hit the cache of the previous one.
        let (a, b) = (filler(2_000, "burn-1"), filler(2_000, "burn-2"));
        assert_ne!(a[..40], b[..40]);
        assert!(
            a.split_whitespace()
                .all(|w| w.chars().all(|c| c.is_ascii_lowercase()))
        );
    }

    #[test]
    fn cached_input_repeats_one_prompt_and_fresh_input_never_does() {
        let cached = prompts(&plan(BurnProfile::CachedInput, 4), "b1");
        assert_eq!(cached.len(), 4);
        assert!(cached.iter().all(|p| *p == cached[0]));
        assert_eq!(cached, prompts(&plan(BurnProfile::CachedInput, 4), "b1"));

        let fresh = prompts(&plan(BurnProfile::FreshInput, 3), "b1");
        assert_eq!(fresh.len(), 3);
        assert_ne!(fresh[0], fresh[1]);
        assert_ne!(fresh[1], fresh[2]);

        // A missing or zero `repeats` still runs once.
        assert_eq!(prompts(&plan(BurnProfile::FreshInput, 0), "b1").len(), 1);
    }

    #[test]
    fn output_prompts_ask_for_the_word_count_and_forbid_stopping_early() {
        let out = prompts(&plan(BurnProfile::Output, 1), "b1");
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("15000 words"), "{}", out[0]);
        assert!(out[0].contains("Do not stop early"));
        // The output profile sends an instruction, not filler.
        assert!(out[0].len() < 400);
    }

    #[test]
    fn builds_the_documented_command_lines() {
        let (program, args) = invocation(Provider::Claude, "claude-opus-4").unwrap();
        assert_eq!(
            args,
            [
                "-p",
                "--model",
                "claude-opus-4",
                "--max-turns",
                "1",
                "--output-format",
                "text"
            ]
        );
        if std::env::var_os("TMX_CLAUDE_BIN").is_none() {
            assert_eq!(program, "claude");
        }

        let (program, args) = invocation(Provider::Codex, "gpt-5.3-codex").unwrap();
        assert_eq!(
            args,
            [
                "exec",
                "-m",
                "gpt-5.3-codex",
                "-c",
                "model_provider=openai",
                "--skip-git-repo-check",
                "-"
            ]
        );
        if std::env::var_os("TMX_CODEX_BIN").is_none() {
            assert_eq!(program, "codex");
        }

        assert!(invocation(Provider::Cursor, "any").is_err());
    }

    #[test]
    fn estimates_tokens_from_words_and_trims_stderr() {
        assert_eq!(words_for(20_000), 15_000);
        assert_eq!(tokens_for_words(15_000), 20_000);
        assert_eq!(
            BurnReport {
                invocations: 1,
                input_tokens_estimate: 7,
                output_tokens_estimate: 9
            }
            .tokens(),
            BurnTokens {
                input: Some(7),
                output: Some(9)
            }
        );
        assert_eq!(tail("  short  ", 300), "short");
        assert_eq!(tail(&"x".repeat(500), 300), "x".repeat(300));
    }

    #[test]
    fn scratch_directories_are_created_and_removed() {
        let path = {
            let scratch = Scratch::new("burn/../1").unwrap();
            assert!(scratch.path().is_dir());
            assert!(
                scratch
                    .path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("tmx-burn-burn1-")
            );
            scratch.path().to_path_buf()
        };
        assert!(!path.exists());
    }

    #[test]
    fn runs_the_tool_and_reports_what_it_sent() {
        // `cat` stands in for the official tool: it echoes the prompt, so stdout ≈ the prompt.
        let plan = BurnPlan {
            provider: Provider::Claude,
            model: "m".into(),
            profile: BurnProfile::CachedInput,
            target_tokens: 400,
            repeats: 2,
        };
        let scratch = Scratch::new("test").unwrap();
        let (program, args) = ("cat".to_string(), Vec::new());
        let prompt = prompts(&plan, "b1").remove(0);
        let echoed = run_once(&program, &args, scratch.path(), &prompt).unwrap();
        assert_eq!(count_words(&echoed), count_words(&prompt));

        assert!(
            run_once("false", &[], scratch.path(), "x")
                .unwrap_err()
                .to_string()
                .contains("exited with 1")
        );
        assert!(
            run_once("tmx-no-such-binary", &[], scratch.path(), "x")
                .unwrap_err()
                .to_string()
                .contains("cannot run")
        );
    }
}
