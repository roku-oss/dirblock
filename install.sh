#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${DIRBLOCK_REPO_URL:-https://github.com/roku-oss/dirblock.git}"
SOURCE_DIR="${DIRBLOCK_SOURCE_DIR:-$PWD/dirblock}"
PREFIX="${DIRBLOCK_PREFIX:-$HOME/.local}"
INSTALL_BIN="$PREFIX/bin/dirblock"
INSTALL_CONFIG="$HOME/.config/dirblock/dirblock.toml"
CAPS="cap_sys_admin,cap_sys_ptrace+ep"

info() {
    printf '==> %s\n' "$*" >&2
}

warn() {
    printf 'WARN: %s\n' "$*" >&2
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

have() {
    command -v "$1" >/dev/null 2>&1
}

confirm() {
    local prompt="$1"
    local answer

    if [ ! -r /dev/tty ]; then
        return 1
    fi

    printf '%s [y/N] ' "$prompt" >/dev/tty
    IFS= read -r answer </dev/tty || return 1
    case "$answer" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

check_python() {
    python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit(1)
PY
}

require_command() {
    have "$1" || die "missing required command: $1"
}

is_dirblock_checkout() {
    local dir="$1"

    [ -d "$dir" ] || return 1
    [ -f "$dir/install.sh" ] || return 1
    [ -f "$dir/Makefile" ] || return 1
    [ -f "$dir/generate_config.py" ] || return 1
    [ -d "$dir/src" ] || return 1
    git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 1
}

script_checkout_dir() {
    local source="${BASH_SOURCE[0]}"
    local script_dir

    [ -n "$source" ] || return 1
    [ -f "$source" ] || return 1

    script_dir="$(cd "$(dirname "$source")" && pwd -P)"
    is_dirblock_checkout "$script_dir" || return 1
    printf '%s\n' "$script_dir"
}

current_checkout_dir() {
    is_dirblock_checkout "$PWD" || return 1
    printf '%s\n' "$PWD"
}

prepare_source_dir() {
    local checkout

    if checkout="$(script_checkout_dir)"; then
        info "using existing checkout: $checkout"
        printf '%s\n' "$checkout"
        return 0
    fi

    if checkout="$(current_checkout_dir)"; then
        info "using current checkout: $checkout"
        printf '%s\n' "$checkout"
        return 0
    fi

    if [ -e "$SOURCE_DIR" ]; then
        if is_dirblock_checkout "$SOURCE_DIR"; then
            info "using existing checkout: $SOURCE_DIR"
            printf '%s\n' "$SOURCE_DIR"
            return 0
        fi
        die "$SOURCE_DIR already exists but is not a dirblock checkout"
    fi

    info "cloning $REPO_URL to $SOURCE_DIR"
    git clone "$REPO_URL" "$SOURCE_DIR"
    printf '%s\n' "$SOURCE_DIR"
}

check_requirements() {
    [ "$(uname -s)" = "Linux" ] || die "dirblock requires Linux"
    [ "${EUID:-$(id -u)}" -ne 0 ] || die "do not run this installer as root"

    require_command git
    require_command make
    require_command g++
    require_command python3
    require_command install
    require_command getcap
    require_command setcap

    check_python || die "python3 must be version 3.11 or newer"
}

warn_if_path_missing() {
    local bin_dir="$PREFIX/bin"
    case ":$PATH:" in
        *":$bin_dir:"*) return 0 ;;
        *)
            warn "$bin_dir is not currently on PATH"
            warn "add this to your shell startup if needed:"
            warn "  export PATH=\"$bin_dir:\$PATH\""
            ;;
    esac
}

capabilities_present() {
    getcap "$INSTALL_BIN" 2>/dev/null | grep -q 'cap_sys_admin.*cap_sys_ptrace\|cap_sys_ptrace.*cap_sys_admin'
}

maybe_set_capabilities() {
    if capabilities_present; then
        info "required capabilities are already present on $INSTALL_BIN"
        return 0
    fi

    printf '\n'
    info "dirblock needs fanotify and process-inspection capabilities:"
    printf '  sudo setcap %s %q\n' "$CAPS" "$INSTALL_BIN"

    if ! have sudo; then
        warn "sudo was not found"
        warn "run this command as root or with your local privilege tool:"
        warn "  setcap $CAPS $INSTALL_BIN"
        return 0
    fi

    if confirm "Run this sudo command now?"; then
        sudo setcap "$CAPS" "$INSTALL_BIN"
        info "capabilities granted"
    else
        warn "capabilities were not granted"
        warn "dirblock will fail to start until you run:"
        warn "  sudo setcap $CAPS $INSTALL_BIN"
    fi
}

print_next_steps() {
    printf '\n'
    info "dirblock installed."

    if have tmux && [ -n "${TMUX:-}" ]; then
        cat <<'EOF'
Run: dirblock --dry-run
Review DENY messages and fine-tune config before enforcement.
After tuning, run: dirblock
EOF
    elif have tmux; then
        cat <<'EOF'
Run: tmux new -s dirblock-test 'dirblock --dry-run'
Review DENY messages and fine-tune config before enforcement.
After tuning, run: tmux new -s dirblock 'dirblock'
EOF
    else
        cat <<'EOF'
tmux was not found. Foreground dry-run mode is available, but closing this terminal stops dirblock.
Run: dirblock --dry-run
Review DENY messages and fine-tune config before enforcement.
Foreground enforcement with `dirblock` can immediately block unexpected workflows.
EOF
    fi
}

main() {
    check_requirements

    local checkout
    checkout="$(prepare_source_dir)"

    cd "$checkout"

    info "building dirblock"
    make release

    info "generating host config"
    python3 generate_config.py

    info "installing binary to $INSTALL_BIN"
    install -d "$PREFIX/bin" "$HOME/.config/dirblock"
    install -m 0755 dirblock "$INSTALL_BIN"
    install -m 0644 config/dirblock.toml "$INSTALL_CONFIG"

    maybe_set_capabilities
    warn_if_path_missing
    print_next_steps
}

main "$@"
