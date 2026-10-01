# Tokenmaxxing client

Open-source desktop app and `tmx` command-line client for proving AI usage from your own machine.
The client includes the TLSNotary prover, provider integrations, log scanners and device signing.
Provider credentials stay on your machine. Claude Code and Codex usage is bounded, not exact.

## Install

Download a matching macOS or Windows bundle from [Releases](https://github.com/OpenSource03/tokenmaxxing-client/releases).
Preview bundles are unsigned and not notarised; operating systems may warn or block them.
A working Tokenmaxxing server and a dashboard pairing code are required. Set the server URL when pairing.

## Build

Requires Rust stable, Node 24, pnpm 10 and the [Tauri platform prerequisites](https://v2.tauri.app/start/prerequisites/).

```sh
git clone https://github.com/OpenSource03/tokenmaxxing-client
cd tokenmaxxing-client
pnpm install --frozen-lockfile
pnpm build:app
cargo build --release -p tmx-cli
./target/release/tmx pair TMX-XXXX-XXXX --server https://YOUR_API_HOST
./target/release/tmx daemon --interval 600
```

`tmx daemon` only proves existing usage. Scheduled reference burns require the explicit
`--run-reference-burns` flag and a server-registered reference account.

## Validation and security

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Never commit keys, device state, provider transcripts or credential files. The public notary
requires a short-lived admission ticket from a paired device; the service also bounds active
sessions and connection setup. The server remains the authority for scores.

Source is exported from the main Tokenmaxxing repository; `SOURCE_COMMIT` identifies its revision.
The pinned TLSNotary fork is public and retains its upstream licensing. This client is MIT licensed.
