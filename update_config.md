# dirblock config agent playbook

This document is for coding assistants updating `config/dirblock.toml` after a user reports unwanted DENY messages. Treat it like an operational playbook: make the smallest safe config change, prefer least privilege, and preserve the user's existing policy.

## Non-negotiable rules

- Always read the existing `config/dirblock.toml` before editing.
- Never create duplicate `[watched]` keys. Update the existing array for a watched directory.
- Keep one executable entry per line.
- Use `which <binary>` to check whether a common executable exists.
- If `which` finds a binary, use `readlink -f "$(which <binary>)"` and add the resolved real executable path, not the symlink.
- If a common executable is not found with `which`, leave it commented out with a short `# not found` note.
- Do not add unprofiled general-purpose readers/editors/interpreters (`cat`, `less`, `vim`, `nvim`, `python`, `node`, `bun`) to sensitive directories.
- For general-purpose tools, use `;dirblock`, `;terminal`, another explicit ancestry profile, or a narrow cmdline filter where appropriate.
- Missing project-specific exact paths should be removed unless the user explicitly wants to keep a commented example.

## Config file location

The config file is TOML format. Locations searched (in order):
1. `--config` CLI argument
2. `<binary_dir>/../config/dirblock.toml`
3. `~/.config/dirblock/dirblock.toml`
4. `/etc/dirblock/dirblock.toml`

## Config workflow

This playbook is for local `config/dirblock.toml` updates, usually after the user sees DENY messages for legitimate tools. It is not the source of truth for `config/dirblock_default.toml`; the default file is generated only by `generate_config.py`.

Do not edit or copy files under `~/.config/dirblock/`; deployment is handled by `make install`.

Workflow:

```bash
# 1. Edit config/dirblock.toml in this repo

# 2. Validate the build/config parse if requested by the user
make
./dirblock --dry-run --config config/dirblock.toml
```

If the user wants the updated config installed, they should run `make install`. That command copies `config/dirblock.toml` into `~/.config/dirblock/dirblock.toml` and preserves capabilities on the installed binary when appropriate.

If the user needs a broad default-policy change, update `generate_config.py` instead. Do not try to recreate default generation logic in this markdown file.

### Recommended runtime: tmux

Prefer starting `dirblock` from a dedicated `tmux` window or pane. This keeps the daemon running when the user disconnects and gives the generated built-in `dirblock` ancestry profile a stable, useful shape:

```text
dirblock: generated built-in ancestry profile for this dirblock launch:
dirblock: [profiles]
dirblock: "dirblock" = [
dirblock:     "/usr/bin/bash",
dirblock:     "/usr/bin/tmux",
dirblock: ]
```

Rules like `"/usr/bin/cat;dirblock"` then allow `cat` only when it is launched from the same trusted tmux/shell ancestry, not when launched by unrelated tools.

## Step 1: Identify sensitive directories

Scan the user's home directory for directories and files that contain secrets, credentials, or private keys:

```bash
# List all dot-directories and dot-files in home
ls -d ~/.[!.]* | sort
```

### Well-known sensitive paths

Check each of these and add active watches when appropriate. Entries ending in `-for-the-paranoid` are disabled templates; keep that name unless the user explicitly opts in.

| Path | Contains | Check |
|------|----------|-------|
| `~/.ssh/` | SSH private keys, known_hosts, config | Almost always exists |
| `~/.gnupg/` | GPG private keys, trustdb | `ls ~/.gnupg/ 2>/dev/null` |
| `~/.aws/` | AWS credentials, config | `ls ~/.aws/credentials 2>/dev/null` |
| `~/.kube/` | Kubernetes config with cluster tokens | `ls ~/.kube/config 2>/dev/null` |
| `~/.config/gcloud/` | GCP credentials | `ls ~/.config/gcloud/ 2>/dev/null` |
| `~/.docker/` | Docker/Podman auth tokens | `ls ~/.docker/config.json 2>/dev/null` |
| `~/.config/gh/` | GitHub CLI auth token | `ls ~/.config/gh/hosts.yml 2>/dev/null` |
| `~/.config/git-for-the-paranoid/` | Optional high-noise Git credential storage policy | Rename to `~/.config/git` only if explicitly enabled |
| `~/.claude/` | Claude Code config, API keys | `ls ~/.claude/ 2>/dev/null` |
| `~/.cursor/` | Cursor editor auth/config | `ls ~/.cursor/ 2>/dev/null` |
| `~/.config/Code/` | VS Code user data, auth/config | `ls ~/.config/Code/ 2>/dev/null` |
| `~/.config/Code - Insiders/` | VS Code Insiders user data, auth/config | `ls ~/.config/Code\ -\ Insiders/ 2>/dev/null` |
| `~/.config/Code - OSS/` | Code OSS user data, auth/config | `ls ~/.config/Code\ -\ OSS/ 2>/dev/null` |
| `~/.config/VSCodium/` | VSCodium user data, auth/config | `ls ~/.config/VSCodium/ 2>/dev/null` |
| `~/.gemini/` | Gemini CLI credentials | `ls ~/.gemini/ 2>/dev/null` |
| `~/.pki-for-the-paranoid/` | Optional high-noise TLS client certificate policy | Rename to `~/.pki` only if explicitly enabled |
| `~/.password-store/` | pass/gopass encrypted store | `ls ~/.password-store/ 2>/dev/null` |
| `~/.cargo-for-the-paranoid/` | Optional high-noise/self-blocking Cargo policy | Rename to `~/.cargo` only if explicitly enabled |
| `~/.npmrc` | npm auth token (file, not dir) | `ls ~/.npmrc 2>/dev/null` |
| `~/.netrc` | FTP/HTTP credentials (file, not dir) | `ls ~/.netrc 2>/dev/null` |
| `~/.pypirc` | PyPI upload credentials (file, not dir) | `ls ~/.pypirc 2>/dev/null` |
| `~/.lmstudio/` | LM Studio API keys (OpenAI, Anthropic, etc.) | `ls ~/.lmstudio/credentials 2>/dev/null` |
| `~/.opencode/` | OpenCode config, auth tokens, and possibly the OpenCode binary | `ls ~/.opencode/ 2>/dev/null` |
| `~/.codex/` | OpenAI Codex CLI config | `ls ~/.codex/ 2>/dev/null` |

Note: dirblock only watches directories. Non-directory paths are rejected at startup with a warning. Individual files like `~/.bash_history` cannot be watched directly — to protect shell history, watch the parent directory (`~/`) but be aware that is very broad.

`~/.pki`, `~/.config/git`, and `~/.cargo` may appear as disabled `-for-the-paranoid` watch names. They are real secret-bearing locations, but they are noisy enough, or self-blocking enough, that users must opt in by renaming the watched key.

## Step 2: Resolve executable paths

For each directory you want to protect, you need to identify which programs legitimately access it. The allowlist uses **full binary paths** as resolved by `/proc/<pid>/exe`.

**Paths vary significantly between distributions.** The common allowlist examples in Step 3 are starting points — always resolve actual paths on the target system before writing them to the config.

### Resolving paths on the target system

Run this for each binary you intend to allowlist. `which` decides whether the executable exists in the user's PATH; `readlink -f` traverses symbolic links until it reaches the actual executable that `/proc/<pid>/exe` will report:

```bash
if which ssh >/dev/null 2>&1; then
    readlink -f "$(which ssh)"
else
    echo "ssh not found"
fi
```

For groups of common tools, use this pattern and then copy the resolved paths into TOML:

```bash
for bin in ssh ssh-agent ssh-add ssh-keygen git scp rsync sftp mosh cat less vim nvim; do
    if which "$bin" >/dev/null 2>&1; then
        printf '%-12s %s\n' "$bin" "$(readlink -f "$(which "$bin")")"
    else
        printf '%-12s not found\n' "$bin"
    fi
done
```

TOML output rule:

```toml
"/usr/bin/ssh",
# "/usr/bin/mosh",  # not found
```

Do not guess unresolved paths for common commands. If `which` cannot find it, comment it out.

Common distro variations:

| Binary | Arch/Debian | Fedora/RHEL | Notes |
|--------|-------------|-------------|-------|
| `sshd` | `/usr/bin/sshd` (Arch merges `/usr/sbin`→`/usr/bin`) | `/usr/sbin/sshd` | May be `/usr/lib/openssh/sshd` on some |
| `git-remote-*` | `/usr/lib/git-core/git-remote-http` | `/usr/libexec/git-core/git-remote-http` | Check with `ls $(git --exec-path)/git-remote-*` |
| `gpg-agent` | `/usr/bin/gpg-agent` | `/usr/bin/gpg-agent` | May be in `/usr/lib/gnupg/` |
| `keyboxd` | `/usr/lib/gnupg/keyboxd` | `/usr/libexec/gnupg/keyboxd` | Use prefix match for `/usr/lib/gnupg/` |
| `electron` | `/usr/bin/electron39` (versioned package name) | `/usr/bin/electron` | On Arch, electron is a versioned package (`electron39`, `electron32`, etc.) — `readlink -f $(which electron)` gives the real name |

For git helpers specifically, use `git --exec-path` to find the right directory rather than guessing:

```bash
ls $(git --exec-path)/git-remote-*
```

For helpers discovered this way, add found paths. If an expected helper is absent, comment it out with `# not found`.

### Checking if a binary is a symlink

```bash
ls -la $(which gpg)
readlink -f $(which gpg)   # follow all symlinks to real binary
```

### Identifying the /proc/pid/exe for runtime-based tools

Some tools run via an interpreter or runtime. `/proc/pid/exe` shows the runtime binary, not the script:

| Tool type | /proc/pid/exe shows | How to identify |
|-----------|-------------------|-----------------|
| Native binary | The binary itself | `readlink -f $(which ssh)` |
| Python script | `/usr/bin/python3` | All Python scripts look the same |
| Bun script | `~/.bun/bin/bun` | All bun scripts look the same |
| Node.js script | `/usr/bin/node` | All node scripts look the same |
| Electron app | `/usr/bin/electron` or embedded | Depends on packaging |
| AppImage | The AppImage file path | `readlink -f $(which cursor)` |
| Versioned install | Path includes version number | `readlink -f $(which claude)` |

#### Runtime-based tools: using cmdline filtering

For runtime-based tools (Python, Bun, Node), you can now distinguish between different scripts by filtering on `/proc/pid/cmdline`. Use the `filter:path` syntax:

```toml
# Without filter (allows ANY bun script):
"~/.gemini" = ["~/.bun/bin/bun"]

# With filter (allows bun ONLY if cmdline contains "gemini-cli"):
"~/.gemini" = ["gemini-cli:~/.bun/bin/bun"]
```

When you invoke `gemini-cli`, its cmdline will be something like `/home/user/.bun/bin/bun /usr/local/bin/gemini-cli ...`, which contains the string `"gemini-cli"`. A random bun script like `bun -e "malicious code"` will not contain that string and will be denied.

**Note:** Cmdline filters are not a hard security boundary. Anyone who knows the filter string can bypass it by appending it to their own invocation of the same binary (e.g. `bun -e "<code>" gemini-cli`). They can stop processes that are unaware of dirblock, but prefer native binaries or Python venv `console_scripts` for stronger isolation.

This is the recommended approach for multi-tool runtimes.

## Step 2b: Configure ancestry profiles

Ancestry profiles let a config allow a general-purpose binary only from a trusted parent process tree. Use them for interactive tools such as `cat`, `less`, `vim`, and `nvim` when protecting directories like `~/.ssh`.

### Syntax

```toml
[profiles]
"terminal" = [
    "/usr/bin/bash",
    "/usr/sbin/sshd",
    "/usr/lib/systemd/systemd",
    "/usr/libexec/gnome-terminal-server",
]

[watched]
"~/.ssh" = [
    "/usr/bin/cat;terminal",
]
```

Profile entries are executable paths or prefix directories only:
- Do not put cmdline filters inside `[profiles]`.
- Do not reference profiles from other profiles.
- Use one executable path per line.
- A profile-constrained rule denies if any ancestor cannot be read or validated.

### Built-in `dirblock` profile

`dirblock` generates a built-in profile named `dirblock` at startup from its own current ancestry. Users do not need to define it in TOML. Prefer starting `dirblock` from `tmux`; then `;dirblock` typically means "tools launched from my trusted tmux shell".

Use this built-in profile for local interactive readers/editors:

```toml
"~/.ssh" = [
    "/usr/bin/cat;dirblock",
    "/usr/bin/less;dirblock",
    "/usr/bin/vim;dirblock",
    "/usr/bin/nvim;dirblock",
]
```

Only add entries for tools that are installed and that the user explicitly wants to use for that directory.

### Updating the `terminal` profile

The `terminal` profile is for interactive terminal ancestries that the user trusts to run profiled readers/editors such as `cat`, `less`, `vim`, and `nvim`. It may include SSH login parents, tmux, and local terminal emulators such as GNOME Terminal or kitty. The safest source is dirblock's ancestry diagnostics: first try a profiled command from the terminal, read the `observed ancestry for candidate profile` log, and add only the trusted ancestors to `terminal`.

Typical terminal profile:

```toml
[profiles]
"terminal" = [
    "/usr/bin/bash",
    "/usr/bin/tmux",
    "/usr/sbin/sshd",
    "/usr/lib/systemd/systemd",
    "/usr/libexec/gnome-terminal-server",
    "/usr/bin/kitty",
]
```

Resolve paths on the target system:

```bash
readlink -f "$(which bash)"
readlink -f "$(command -v sshd || printf '%s\n' /usr/sbin/sshd)"
readlink -f "$(test -e /usr/lib/systemd/systemd && printf '%s\n' /usr/lib/systemd/systemd || printf '%s\n' /lib/systemd/systemd)"
readlink -f "$(command -v gnome-terminal-server || printf '%s\n' /usr/libexec/gnome-terminal-server)"
```

If the user's shell is not bash, use the actual login shell path:

```bash
readlink -f "$SHELL"
```

Then add parallel rules for the protected directory:

```toml
"~/.ssh" = [
    "/usr/bin/cat;dirblock",
    "/usr/bin/cat;terminal",
    "/usr/bin/less;dirblock",
    "/usr/bin/less;terminal",
]
```

Keep `terminal` limited to interactive terminal ancestors. If a separate trust domain appears, such as CI, build services, or container entrypoints, create a separate named profile instead of broadening `terminal`.

### Discovering custom installation paths

Different systems and users install tools differently. The starting config only lists common package-manager paths. To configure tools you've installed custom ways (symlinks, AppImages, development builds), discover their real paths:

**Method 1: Resolve symlinks and wrapper scripts**

```bash
# Find where a tool is installed, follow symlinks
readlink -f $(which cursor)
readlink -f $(which code)
readlink -f $(which lmstudio)
```

Examples of different install methods:
```
# Package manager (most common)
readlink -f $(which cursor)  → /usr/bin/cursor

# Symlink to custom location
readlink -f $(which code)    → /home/user/VSCode-linux-x64/code

# Versioned directory
readlink -f $(which claude)  → /home/user/.local/share/claude/versions/2.1.85

# AppImage (special case)
readlink -f $(which lmstudio) → /tmp/.mount_lmstud.../... (ephemeral, don't use)
```

**For AppImages specifically:** The exe path is the mounted `/tmp` path, which changes every run. Don't add it to the config. Instead:
1. Find the AppImage file itself: `ls ~/.local/bin/appimages/`
2. Check if it's worth protecting (contains credentials)
3. If yes, use `--dry-run` mode to discover what cmdline filter would distinguish it from other tools sharing that directory

**Method 2: Use dry-run to discover actual accesses**

This is the most reliable way to build an allowlist:

```bash
# Run dirblock in dry-run, verbose mode
dirblock --dry-run -v --config config/dirblock.toml

# In another terminal, use the tool(s) that should access the protected directory
# Then review the DRY-RUN DENIED and ALLOWED logs
```

Look for lines like:
```
DRY-RUN ALLOWED: pid=12345 exe=/usr/bin/cursor (cursor) [/usr/bin/cursor --user-data-dir=...] -> ~/.cursor/...
DENIED: pid=54321 exe=/home/user/.local/bin/random-app (random-app) [random-app --flag] -> ~/.cursor/...
```

The `exe=` field shows the exact binary path as dirblock sees it. Use that in your config.

**Method 3: Check /proc directly while the tool is running**

If you're unsure, run the tool and check in another terminal:
```bash
# While tool is running, find its PID and check its real exe
ps aux | grep cursor
readlink /proc/<PID>/exe
```

### Examples of custom install configurations

#### Cursor (package manager + AppImage)
```toml
"~/.cursor" = [
    "/usr/bin/cursor",  # Debian/Ubuntu/Fedora standard path
    # For AppImage: discover the /tmp mount path with --dry-run, 
    # add the result here. Note it will change on each run.
]
```

#### VS Code (many install methods)
```toml
"~/.config/Code" = [
    "/usr/bin/code",                    # Standard package manager
    "~/.local/bin/code",                # Symlink to custom location
    "~/.vscode-oss/bin/code",           # OSS build
    # Add your specific path after discovering with readlink -f
]
```

#### Development/custom builds
```toml
"~/.myapp" = [
    "~/proj/myapp/build/myapp",  # Development build
    # Use readlink -f to resolve the real path if it's a symlink
]
```

### Using prefix matching for versioned installs

If a binary path includes a version number that changes on update, use prefix matching (trailing `/`):

```toml
# Claude Code: binary at ~/.local/share/claude/versions/2.1.85
# Changes on every update, so use prefix:
"~/.claude" = ["~/.local/share/claude/versions/"]

# Cursor AppImage: ~/.local/bin/appimages/Cursor-2.6.19-x86_64.AppImage
# Version in filename, so use prefix:
"~/.cursor" = ["~/.local/bin/appimages/"]
```

### Using cmdline filtering for runtime interpreters

When a runtime interpreter (bun, node, python) is used by multiple tools, use cmdline filtering to distinguish them:

Syntax: `string:/path/to/exe` or `string:/path/with/prefix/`

The filter checks if `/proc/pid/cmdline` contains the given string (case-sensitive, substring match).

**Example:**

```toml
# ~/.gemini should only be accessed by gemini-cli (a bun-based tool)
"~/.gemini" = [
    "gemini-cli:~/.bun/bin/bun",
]
```

When gemini-cli is invoked as `/home/user/.bun/bin/bun /usr/local/bin/gemini-cli ...`, the cmdline contains `"gemini-cli"` and access is allowed. A random bun script without this string will be denied.

Works with both exact paths and prefix matches (trailing `/`).

### Discovery via dry-run

The most reliable way to build an allowlist is to run dirblock in dry-run mode and observe what accesses your watched directories:

```bash
dirblock --dry-run -v --config config/dirblock.toml
```

Then trigger the tools that should access each directory:
- `ssh user@host` to exercise SSH
- `git push` to exercise git with SSH
- `gpg --list-keys` to exercise GPG

Review the DRY-RUN DENY and ALLOWED log lines to see the exact `/proc/pid/exe` paths.

## Step 3: Write the config

Update `config/dirblock.toml` only for the local policy change the user requested, typically adding a legitimate executable that appeared in a DENY log. Use the TOML snippets in this section as examples for local edits only. Do not use this markdown to generate or maintain `config/dirblock_default.toml`.

### Template for a new watched directory entry

```toml
# --- Description of what this protects ---
"~/<path>" = [
    "/usr/bin/<binary>",
    # "/usr/bin/<binary2>",  # add if installed
]
```

**Formatting rule:** one executable per line. Never pack multiple paths on one line.

### Common allowlists by directory

These are starting points based on common distro layouts. **Do not copy these paths verbatim**. For each common executable, run `which`, then `readlink -f` on the `which` result. Add found real paths. Leave not-found common executables commented out with `# not found`.

#### ~/.ssh
```toml
[profiles]
"terminal" = [
    "/usr/bin/bash",
    "/usr/bin/tmux",
    "/usr/sbin/sshd",
    "/usr/lib/systemd/systemd",
    "/usr/libexec/gnome-terminal-server",
    "/usr/bin/kitty",
]

"~/.ssh" = [
    "/usr/bin/ssh",
    "/usr/bin/ssh-agent",
    "/usr/bin/ssh-add",
    "/usr/bin/ssh-keygen",
    "/usr/bin/git",
    "/usr/lib/git-core/git-remote-http",
    "/usr/lib/git-core/git-remote-https",
    "/usr/bin/scp",
    "/usr/bin/rsync",
    "/usr/bin/sftp",
    "/usr/sbin/sshd",  # required if this machine accepts incoming SSH (reads authorized_keys)
    # "/usr/bin/mosh",  # not found
    "/usr/bin/cat;dirblock",
    "/usr/bin/cat;terminal",
    "/usr/bin/less;dirblock",
    "/usr/bin/less;terminal",
    # "/usr/bin/vim;dirblock",       # not found or not requested
    # "/usr/bin/vim;terminal",       # not found or not requested
    # "/usr/bin/nvim;dirblock",      # not found or not requested
    # "/usr/bin/nvim;terminal",      # not found or not requested
]
```

Note: `sshd` children that read `authorized_keys` run as root (UID 0). dirblock must have `CAP_SYS_PTRACE` (in addition to `CAP_SYS_ADMIN`) to resolve their exe path via `/proc/<pid>/exe`. Without it, sshd shows as an empty exe name and is denied. See README — the required setcap command is `cap_sys_admin,cap_sys_ptrace+ep`.

Do not add unprofiled `cat`, `less`, `vim`, or `nvim` to `~/.ssh`. These are general-purpose exfiltration tools; constrain them with `;dirblock`, `;terminal`, or another explicit profile.

#### ~/.gnupg
```toml
"~/.gnupg" = [
    "/usr/bin/gpg",
    "/usr/bin/gpg-agent",
    "/usr/bin/gpg2",
    "/usr/bin/gpgconf",
    "/usr/bin/gpgsm",
    # "/usr/bin/pass",   # add if pass is installed
    # "/usr/bin/gopass",  # add if gopass is installed
]
```

#### ~/.aws
```toml
"~/.aws" = [
    "/usr/bin/aws",
    # "/usr/local/bin/aws",      # if installed via pip
    # "/usr/local/aws-cli/",     # prefix: if installed as versioned bundle under /usr/local/aws-cli/v2/
]
```

#### ~/.kube
```toml
"~/.kube" = [
    "/usr/bin/kubectl",
    "/usr/bin/helm",
    # "/usr/bin/k9s",
]
```

#### ~/.docker
```toml
"~/.docker" = [
    "/usr/bin/docker",
    "/usr/bin/podman",
    "/usr/bin/podman-remote",
]
```

#### ~/.config/gh
```toml
"~/.config/gh" = [
    "/usr/bin/gh",
    "~/.local/share/gh/extensions/",  # prefix: gh extensions (gh-copilot, etc.)
]
```

#### Common AI assistants

**Claude Code:**
```bash
readlink -f $(which claude)  # Usually ~/.local/share/claude/versions/<version>
```
```toml
"~/.claude" = [
    "claude:~/.local/share/claude/versions/",  # prefix + cmdline filter
    "/usr/bin/bash",  # bash tool integration
]
```

**Cursor editor:**
```bash
readlink -f $(which cursor)  # /usr/bin/cursor (package), or /tmp/.mount_... (AppImage)
```
```toml
"~/.cursor" = [
    "/usr/bin/cursor",  # Standard package manager path
    # For AppImage: use --dry-run to discover /tmp mount path (ephemeral)
]
```

**VS Code / Code OSS:**
```bash
readlink -f $(which code)  # /usr/bin/code, ~/VSCode-linux-x64/code, ~/.vscode-oss/bin/code, etc.
```
```toml
"~/.config/Code" = [
    "/usr/bin/code",                    # Standard package manager
    "~/.local/bin/code",                # Custom symlink
    "~/.vscode-oss/bin/code",           # OSS build
]

"~/.config/Code - Insiders" = [
    "/usr/bin/code-insiders",
    "~/.local/bin/code-insiders",
]

"~/.config/Code - OSS" = [
    "/usr/bin/code-oss",
    "~/.vscode-oss/bin/code",
]

"~/.config/VSCodium" = [
    "/usr/bin/codium",
    "~/.local/bin/codium",
]
```

**Gemini CLI:**
```bash
readlink -f $(which gemini)  # Usually ~/.bun/bin/bun or ~/.nvm/versions/node/...
```
```toml
"~/.gemini" = [
    "gemini-cli:~/.bun/bin/bun",        # If installed as bun script, use cmdline filter
    # "gemini-cli:~/.nvm/versions/node/",  # If installed as node script
]
```

**LM Studio:**
```bash
# AppImage: readlink -f $(which lmstudio) → /tmp/.mount_lmstud... (ephemeral)
# Use --dry-run to observe accesses, note that /tmp path changes each run
```
```toml
# Not recommended as a stable local allowlist entry (no stable path for AppImage)
# If protecting ~/.lmstudio, discover path with --dry-run during LM Studio use
```

**Opencode:**
```bash
readlink -f $(which opencode)  # often ~/.opencode/bin/opencode, ~/.local/bin/opencode, or a Node/Bun install
```
```toml
"~/.opencode" = [
    "~/.opencode/bin/opencode",
    "~/.local/bin/opencode",
    "~/.bun/install/global/node_modules/@opencode-ai/",
    "opencode:~/.bun/bin/bun",
    "opencode:~/.nvm/versions/node/",
    "opencode:/usr/bin/node",
]
```

If the OpenCode executable itself lives under watched `~/.opencode`, launching it from a shell can self-block before `execve` changes `/proc/<pid>/exe` to `opencode`. Verify this in enforce mode. If it happens, prefer moving the executable outside the watched directory or treating the watch as an explicit local trade-off rather than broadening the rule to trust the user's shell.

#### Custom tools (use discovery method)

For tools you've built or installed yourself:

```toml
"~/.myapp" = [
    "/full/path/to/your/app",  # Use readlink -f to get exact path
]

"~/.myconfig" = [
    "opencode:~/.bun/bin/bun",  # If a custom OpenCode wrapper runs via bun: use cmdline filter
    "tool:~/.nvm/versions/node/",  # If tool runs via node: use cmdline filter
]
```

**Always use `readlink -f` to discover the actual binary path** before adding to config. For runtime-based tools (Python, Bun, Node), use the `:` cmdline filter syntax.

#### ~/.config/dirblock (self-protection)
```toml
"~/.config/dirblock" = [
    "~/.local/bin/dirblock",
    # "/usr/lib/openssh/sftp-server",  # add if editing config remotely via sshfs
]
```

## Step 4: Validate the config

After editing local policy, validate it:

1. **Check all binary paths exist or are deliberately commented out:**

For each exact-path entry (no trailing `/`), verify the file exists. If a common binary was not found by `which`, keep it commented with `# not found`. If an uncommented exact path does not exist, remove it or resolve the correct path.

```bash
# For each common binary, verify PATH lookup and real executable path
for bin in ssh git gpg cat less vim nvim; do
    if which "$bin" >/dev/null 2>&1; then
        echo "OK: $bin -> $(readlink -f "$(which "$bin")")"
    else
        echo "COMMENT OUT: $bin not found"
    fi
done
```

For tilde-expanded paths, expand `~` to the real home first:
```bash
[ -x "$HOME/.opencode/bin/opencode" ] && echo "OK" || echo "MISSING"
```

Prefix entries (trailing `/`) cannot be validated this way — skip them.

2. **Check all watched directories exist:**
```bash
for dir in ~/.ssh ~/.gnupg ~/.claude ...; do
    [ -d "$dir" ] && echo "OK: $dir" || echo "MISSING: $dir"
done
```

3. **Run in dry-run mode and exercise each tool:**
```bash
dirblock --dry-run --config config/dirblock.toml
```
Then in another terminal, access each watched directory with its expected tool. Verify ALLOWED lines appear, not DRY-RUN DENY.

4. **Check for legitimate tools you may have missed:**
Run in dry-run + verbose mode for an extended period (e.g. a day) and review all DRY-RUN DENY lines. Add any legitimate tools to the allowlist.

## Tilde expansion details

Both watched directory keys and allowlist values support `~`:
- Under `sudo`: resolved via `SUDO_USER` → `getpwnam()` → `pw_dir`
- Without sudo: resolved via `HOME` env var or `getpwuid(getuid())`

This means:
```toml
"~/.ssh" = [
    "~/.local/share/claude/versions/",
]
```
Expands to:
```
"/home/pfrench/.ssh" = ["/home/pfrench/.local/share/claude/versions/"]
```

## Notes for the AI assistant

- **Always read `config/dirblock.toml` before making local policy changes.** This playbook is for updating local protection after unwanted DENY messages, not for generating `config/dirblock_default.toml`.
- Find the existing watched key and insert the new entry into its array — never append a second `"~/.ssh" = [...]` block. TOML does not allow duplicate keys; a second block silently overwrites the first.
- **One executable per line.** Never pack multiple paths on a single line.
- Always use `which` and then `readlink -f "$(which <binary>)"` to verify binary paths on the user's specific system. Paths differ between Arch, Ubuntu, Fedora, etc.
- For common binary examples, if `which` does not find the command, keep the TOML entry commented out with `# not found`.
- **Missing project-specific exact paths must be removed**, not commented out. A path like `~/proj/vendor/.../opencode` that doesn't exist on this machine is a stale install path — remove it.
- Keep `~/.pki`, `~/.config/git`, and `~/.cargo` as opt-in `-for-the-paranoid` watches unless the user explicitly asks to enable them.
- Be careful with watches that contain their own executable, such as some `~/.opencode` and `~/.cargo` installs. The parent shell can be the process opening the executable before `execve`, so an allow for the target binary may not prevent self-blocking.
- Prefer ancestry-profiled entries for general-purpose file readers and editors (`cat`, `less`, `vim`, `nvim`, `python`, `node`, `bun`) instead of unprofiled allows.
- Use the generated built-in `dirblock` profile for local trusted shell/tmux access. Do not define `[profiles].dirblock` in TOML unless the user explicitly wants to override the generated profile.
- Generate separate profiles for separate trust domains, such as CI or service wrappers, instead of broadening `terminal` to include every possible parent process.
- For `~/.ssh`, good interactive defaults are profiled `cat` and `less`; add profiled `vim`/`nvim` only if the user wants to edit SSH config or known_hosts directly.
- When adding a new watched directory, suggest running `--dry-run` first to discover all legitimate accessors before switching to enforce mode.
- If the user reports a tool being blocked, check `/proc/<pid>/exe` for that tool's process to get the exact path to add.
- If the user reports an ancestry denial, use dirblock's `observed ancestry for candidate profile` log to create or update a named profile.
- For Electron-based apps, the exe path may be `/usr/bin/electron`, `/usr/lib/electron/electron`, or an app-specific path. Check with `readlink -f`.
