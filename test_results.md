# dirblock test results — 2026-05-05

These results were collected against a running installed daemon launched as:

```bash
dirblock > dirblock_log.txt 2>&1
```

The daemon loaded `~/.config/dirblock/dirblock.toml`. The repo generator currently treats `~/.config/git` and `~/.pki` as optional high-noise watches by emitting inactive `*-for-the-paranoid` template keys.

## Manual Exercise

Manual probes read only a single byte from protected files and did not print secret contents.

Expected-deny Python probes returned `Operation not permitted` and produced `DENIED` log lines for active protected files under:

- `~/.ssh`
- `~/.aws`
- `~/.kube`
- `~/.config/gcloud`
- `~/.config/gh`
- `~/.claude`
- `~/.cursor`
- `~/.codex`

Expected-allow probes succeeded for:

- `ssh -G github.com`
- `gpg --list-keys`
- `aws configure list`
- `kubectl config current-context`
- `gcloud config list`
- `docker context ls`
- `claude --version`
- `codex --version`

`gh auth status` was not blocked by dirblock, but failed because the configured token/keyring state is invalid.

VS Code policy was exercised after adding `~/.config/Code` to the generated config. Python reads were denied for `~/.config/Code/User/settings.json`, `~/.config/Code/User/mcp.json`, and `~/.config/Code/User/globalStorage/storage.json`. `code --version` and `code --list-extensions` were allowed. The daemon log confirmed `~/.config/Code` was watched with `/usr/share/code/code` allowlisted.

Two expected-allow probes exposed a self-blocking policy shape issue:

- `rustup show active-toolchain` was denied when `bash` tried to open `~/.cargo/bin/rustup`.
- `opencode --version` was denied when `bash` tried to open `~/.opencode/bin/opencode`.

This happens before the child process can become the allowlisted executable. The shell opens the executable file inside the watched directory, so `/proc/pid/exe` is still the shell. Cargo was moved to an optional `~/.cargo-for-the-paranoid` template; the recommended mitigation is Cargo credential providers such as `cargo:libsecret` on Linux. After removing active `~/.cargo`, `rustup show active-toolchain` returned `stable-x86_64-unknown-linux-gnu (default)` successfully. OpenCode remains active in the generated policy, but installs where the executable lives under watched `~/.opencode` may still self-block and should be verified locally.

## Scripted Smoke Test

Agent-shell negative-control command:

```bash
./test_dirblock_policy.sh
```

Trusted-shell positive-ancestry command:

```bash
DIRBLOCK_EXPECT_CAT=ALLOWED DIRBLOCK_EXPECT_LESS=ALLOWED ./test_dirblock_policy.sh > policy_log_allowed.txt 2>&1
```

The script captures command output in a temporary directory and deletes it at exit.

### Profile/Context Checks — Agent Shell

| Test | Observed | Status | Notes |
|------|----------|--------|-------|
| `cat ~/.ssh/config` | DENIED | 1 | Agent ancestry did not match trusted profiles. |
| `timeout less ~/.ssh/config` | DENIED | 0 | Non-interactive `less` launched under `timeout` returned 0 but wrote `Operation not permitted`. |
| `python3 ~/.ssh/config` | DENIED | 1 | Expected denial passed. |
| `nvim ~/.ssh/config` | DENIED | 0 | Non-interactive `nvim` returned 0 but wrote permission denied. |

### Profile/Context Checks — Trusted Shell

| Test | Observed | Status | Notes |
|------|----------|--------|-------|
| `cat ~/.ssh/config` | ALLOWED | 0 | Trusted shell ancestry matched the running daemon's built-in `dirblock` profile. |
| `timeout less ~/.ssh/config` | DENIED | 0 | False negative for direct `less`; `timeout` appears in the ancestry and is not in the profile. Direct `less ~/.ssh/config` works from the trusted shell. |
| `python3 ~/.ssh/config` | DENIED | 1 | Expected denial passed. |
| `nvim ~/.ssh/config` | DENIED | 0 | Expected denial passed. |

### Positive Checks

| Test | Observed | Status | Result |
|------|----------|--------|--------|
| `ssh-keygen -l -f <public key>` | ALLOWED | 0 | PASS |
| `git config --global --list` | ALLOWED | 0 | PASS |
| `gpg --list-keys` | ALLOWED | 0 | PASS |
| `gh auth status` | ALLOWED | 1 | PASS for dirblock; command failed for auth state. |
| `docker info` | ALLOWED | 0 | PASS |
| `kubectl config current-context` | ALLOWED | 0 | PASS |
| `ls ~/.claude/settings.json` | ALLOWED | 0 | PASS |
| `codex --help` | SKIPPED | n/a | Requires `DIRBLOCK_EXTENDED=1`. |

### Red-Team Checks

| Test | Observed | Status | Result |
|------|----------|--------|--------|
| `cat` private SSH key | DENIED | 1 | Observed denied. |
| Python read `~/.ssh/config` | DENIED | 1 | PASS |
| `curl file://~/.aws/credentials` | DENIED | 37 | PASS |
| Copy GPG trustdb | DENIED | 1 | PASS |
| Tar `~/.ssh` | DENIED | 2 | PASS |
| `find ~/.config/gh -exec cat` | DENIED | 0 | PASS; `cat` failures were reported on stderr. |
| Symlink to private SSH key | DENIED | 1 | Observed denied. |
| `dd if=~/.kube/config` | DENIED | 1 | PASS |
| `strace -e openat cat ~/.ssh/config` | DENIED | 1 | Observed `EPERM`; strace did not bypass fanotify. |

In the trusted-shell run, `cat` private key and symlink-to-private-key were allowed because the broad `cat;dirblock` rule applies to all files under `~/.ssh` when launched from trusted ancestry. That is expected for the current interactive convenience policy, but it is a trade-off: a trusted shell can read private keys with `cat`. `tar`, `python`, `curl`, `cp`, `dd`, `find+cat gh`, and `strace+cat` remained denied in that run.

### Runtime Checks

| Test | Observed | Expected | Result |
|------|----------|----------|--------|
| `bun -e` reading `~/.ssh/config` | ALLOWED | DENIED | FAIL |
| `bun -e` reading `~/.claude/settings.json` without explicit filter argument | ALLOWED | DENIED | FAIL |
| `bun -e ... claude` reading `~/.claude/settings.json` | ALLOWED | ALLOWED | PASS |
| Python reading `~/.claude/settings.json` | DENIED | DENIED | PASS |

The Bun rows preserve the earlier warning: cmdline filters are substring matches over the full `/proc/pid/cmdline`. They are useful for accidental access control, not a hard security boundary.

### VS Code Checks

| Test | Observed | Status | Result |
|------|----------|--------|--------|
| Python read `~/.config/Code/User/settings.json` | DENIED | 1 | PASS |
| Python read `~/.config/Code/User/mcp.json` | DENIED | 1 | PASS |
| Python read `~/.config/Code/User/globalStorage/storage.json` | DENIED | 1 | PASS |
| `code --version` | ALLOWED | 0 | PASS |
| `code --list-extensions` | ALLOWED | 0 | PASS |

An initial broad file search under `~/.config/Code` produced many expected `DENIED` entries for Cursor's bundled `rg`. That created log noise, but confirmed non-allowlisted readers are blocked throughout the tree.

## Notes

- Symlink indirection correctly resolved by fanotify to the watched directory.
- `strace` did not bypass fanotify-based blocking.
- VS Code's own CLI was allowed for `~/.config/Code`, while Python and Cursor/ripgrep were denied.
- `strace+cat` denied even in the trusted-shell run, while direct `cat` was allowed.
- The active generated config skips `~/.cargo`, `~/.config/git`, and `~/.pki` by default because they are high-noise or self-blocking.
- Cmdline `:` filters use substring matching on full `/proc/pid/cmdline`; they can be bypassed by appending the filter string.
- Ancestry profiles use `;profile` as the delimiter so paths containing `@` continue to work.
- The built-in `dirblock` profile is generated at startup from the daemon's own current ancestry.
- Profile entries are executable paths or prefix directories only; profiles are not recursive and do not support cmdline filters.
- Profile uncertainty denies that constrained rule, but other matching rules are still evaluated before the final decision.
