# dirblock

A Linux daemon that protects sensitive directories by intercepting file opens and checking the accessing process against a per-directory allowlist. Unauthorized opens are denied and can trigger a desktop notification.

dirblock is built on the kernel's [fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html) API (`FAN_OPEN_PERM`). It watches mount points at the VFS layer, so symlinks and alternate path spellings still resolve to the opened file.

## Why

Supply chain attacks can steal SSH keys, cloud credentials, and API tokens from your home directory during ordinary developer workflows. dirblock is a narrow, directory-first guard: define the secret directory, list the few binaries that should access it, and deny everything else.

Linux already has mature MAC systems such as SELinux and AppArmor. Those solve broader system and application policy problems. dirblock is intentionally smaller and more surgical.

For implementation details and architecture, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Quick Start

Requirements:
- Linux with fanotify permission events
- `g++` with C++17 support
- `make`
- Python 3.11+ for the config generator

### Build the binary:

```bash
git clone <repo-url>
cd dirblock
make
```

### Generate `config/dirblock.toml`

#### Python Script

The deterministic generator checks known sensitive directories and resolves allowlisted executables using standard paths first, warning when a command is found only through a non-standard `PATH` entry. It writes a host-specific `config/dirblock.toml` and comments out missing exact paths.

```bash
python3 generate_config.py
```

This writes `config/dirblock.toml`. When replacing a different existing config, the generator first preserves it as `config/dirblock_orig.toml`, `config/dirblock_orig_1.toml`, and so on.

The broad reference catalog is `config/dirblock_default.toml`; it is generated only by:

```bash
python3 generate_config.py --default
```

Do not hand-maintain the default file. Some high-noise or self-blocking watches, such as `~/.pki`, `~/.config/git`, and `~/.cargo`, are intentionally emitted as opt-in `-for-the-paranoid` entries.

#### AI Assisted

For a guided local update after an unwanted `DENIED` or `DRY-RUN DENY` line, point an AI coding assistant at [update_config.md](update_config.md):

```text
read update_config.md and update config/dirblock.toml
```

The assistant playbook is for the smallest local `config/dirblock.toml` exception that explains legitimate access. It does not generate `config/dirblock_default.toml` and it does not deploy the config; `make install` does that.

### Install the binary and config:

```bash
make install
```

`make install` copies the binary to `~/.local/bin/dirblock`, copies `config/dirblock.toml` to `~/.config/dirblock/dirblock.toml`, and prints the capability command to run. Grant the installed binary those capabilities:

```bash
sudo setcap cap_sys_admin,cap_sys_ptrace+ep ~/.local/bin/dirblock
```

`CAP_SYS_ADMIN` is required for fanotify. `CAP_SYS_PTRACE` lets dirblock inspect `/proc/<pid>/exe` for processes owned by other users, such as `sshd` children.

### Test the policy in dry-run mode first:

```bash
tmux new -s dirblock-test 'dirblock --dry-run'
```

While dry-run is running, use the tools that should legitimately access protected files. dirblock logs what it would deny, but still allows the open. Paste a prompt like this into your coding assistant:

```text
I got this dirblock deny in dry-run mode. I want to allow this legitimate access.
Please update config/dirblock.toml using the smallest appropriate allow rule.

dirblock: DRY-RUN DENY: pid=2000866 exe=gh-copilot (/home/user/.local/share/gh/extensions/gh-copilot/gh-copilot) [gh-copilot suggest] -> /home/user/.config/gh/config.yml
```

Then run `make install` again to deploy the updated config.

### Finally, Run dirblock in a persistent tmux pane and watch the startup output:

```bash
tmux new -s dirblock dirblock
```

At startup, dirblock prints the generated built-in `dirblock` ancestry profile for this launch. Keep the pane open while you exercise normal workflows and inspect any `DENIED` lines.

## Configuration

The runtime config is installed to:

```text
~/.config/dirblock/dirblock.toml
```

The generated repository config lives at:

```text
config/dirblock.toml
```

Basic example:

```toml
[general]
notify = true

[profiles]
"terminal" = [
    "/usr/bin/bash",
    "/usr/bin/tmux",
    "/usr/sbin/sshd",
    "/usr/lib/systemd/systemd",
    "/usr/libexec/gnome-terminal-server",
    "/usr/bin/kitty",
]

[watched]
"~/.ssh" = [
    "/usr/bin/ssh",
    "/usr/bin/ssh-agent",
    "/usr/bin/git",
    "/usr/bin/cat;dirblock",
    "/usr/bin/cat;terminal",
]
```

Allowlist entries support:
- Exact paths: `"/usr/bin/ssh"`
- Prefix paths: `"~/.local/share/claude/versions/"`
- Cmdline filters: `"filter:path"`
- Ancestry profiles: `"path;profile"`
- `~` expansion using the real user's home directory

The built-in `dirblock` profile is generated at startup from the daemon's own current ancestry. If dirblock is launched from tmux, `"/usr/bin/cat;dirblock"` allows `cat` only from that trusted tmux ancestry. For assistant-driven config updates, see [update_config.md](update_config.md).

## Cargo and Rust Users

The generated configs do not actively watch `~/.cargo` by default. Instead, the policy is emitted as `~/.cargo-for-the-paranoid`, so users must explicitly rename the watched key to `~/.cargo` before enabling it.

This is intentional. Cargo can store registry tokens in `$CARGO_HOME/credentials.toml`, but standard Rust installs also put launchers such as `cargo` and `rustup` under `~/.cargo/bin`. If dirblock watches `~/.cargo`, a shell can be blocked while opening `~/.cargo/bin/cargo` or `~/.cargo/bin/rustup` before `execve` changes `/proc/<pid>/exe` to the target program. In that case, allowlisting the target binary itself may not be enough.

Recommended mitigations before enabling the watch:
- Prefer Cargo credential providers so registry tokens live in a keyring or external secret store instead of plaintext `credentials.toml`.
- On Linux desktops, consider `cargo:libsecret` for keyring-backed token storage.
- If you still enable the watch, test common commands such as `cargo metadata`, `cargo publish --dry-run`, and `rustup show active-toolchain` with dirblock running before relying on the policy.
- Avoid broad shell allows such as `"/usr/bin/bash;dirblock"` for `~/.cargo` unless you understand the trade-off: it can fix self-blocking, but it also trusts that shell ancestry to read files under the watched directory.

References:
- [Cargo registry authentication](https://doc.rust-lang.org/cargo/reference/registry-authentication.html)
- [Cargo credential provider protocol](https://doc.rust-lang.org/cargo/reference/credential-provider-protocol.html)

## Safety Notes

dirblock is designed to fail open at the daemon level:
- If the daemon exits or crashes, the kernel removes fanotify marks and normal access resumes.
- If event processing throws, dirblock responds with `FAN_ALLOW` to avoid hanging the caller.
- Profile uncertainty denies only that constrained rule; other matching rules are still evaluated.

Limitations:
- Cmdline filters are useful but not a hard security boundary.
- Ancestry profiles check current ancestry at access time, not historical launch provenance.
- The daemon sees all opens on marked mounts and then filters by watched directory path.

See [CONTRIBUTING.md](CONTRIBUTING.md) for architecture, function responsibilities, and development workflow.

## License

Apache-2.0. See [LICENSE](LICENSE).
