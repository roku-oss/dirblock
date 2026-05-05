#!/usr/bin/env bash
set -u

TARGET="${DIRBLOCK_TEST_TARGET:-$HOME/.ssh/config}"
EXTENDED="${DIRBLOCK_EXTENDED:-0}"

if [[ ! -e "$TARGET" ]]; then
    echo "target does not exist: $TARGET" >&2
    exit 2
fi

tmpdir="$(mktemp -d)"
cleanup() {
    rm -rf "$tmpdir"
}
trap cleanup EXIT

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

first_existing() {
    local path
    for path in "$@"; do
        if [[ -e "$path" ]]; then
            printf '%s\n' "$path"
            return 0
        fi
    done
    return 1
}

print_skip() {
    printf '%-24s %-9s %s\n' "$1" "SKIPPED" "$2"
}

run_case() {
    local name="$1"
    local expected="${2:-}"
    shift 2

    local stdout_file="$tmpdir/${name//[^A-Za-z0-9_.-]/_}.stdout"
    local stderr_file="$tmpdir/${name//[^A-Za-z0-9_.-]/_}.stderr"

    "$@" >"$stdout_file" 2>"$stderr_file"
    local status=$?

    local observed="ALLOWED"
    if grep -qiE 'operation not permitted|permission denied|cannot open|failed to open|could not open|couldn'\''t open' "$stderr_file"; then
        observed="DENIED"
    fi

    local verdict="OBSERVED"
    if [[ -n "$expected" ]]; then
        if [[ "$observed" == "$expected" ]]; then
            verdict="PASS"
        else
            verdict="FAIL expected=$expected"
        fi
    fi

    printf '%-24s %-9s status=%-3d %s\n' "$name" "$observed" "$status" "$verdict"

    if [[ ( "$observed" == "DENIED" || "$verdict" == FAIL* ) && -s "$stderr_file" ]]; then
        sed 's/^/  stderr: /' "$stderr_file"
    fi
}

run_shell_case() {
    local name="$1"
    local expected="${2:-}"
    local script="$3"
    run_case "$name" "$expected" bash -c "$script"
}

run_if_cmd() {
    local cmd="$1"
    local name="$2"
    local expected="$3"
    shift 3
    if have_cmd "$cmd"; then
        run_case "$name" "$expected" "$@"
    else
        print_skip "$name" "missing $cmd"
    fi
}

expect_cat="${DIRBLOCK_EXPECT_CAT:-}"
expect_less="${DIRBLOCK_EXPECT_LESS:-}"
expect_python="${DIRBLOCK_EXPECT_PYTHON:-DENIED}"
expect_nvim="${DIRBLOCK_EXPECT_NVIM:-DENIED}"

echo "dirblock policy smoke test"
echo "target: $TARGET"
echo "command output is captured in a temp dir and deleted; protected file data is not printed"
echo

echo "== Profile/context checks =="
run_case "cat" "$expect_cat" cat "$TARGET"

if command -v timeout >/dev/null 2>&1 && command -v less >/dev/null 2>&1; then
    run_case "timeout less" "$expect_less" timeout 3 less "$TARGET"
else
    print_skip "timeout less" "missing timeout or less"
fi

if have_cmd python3; then
    run_case "python3" "$expect_python" python3 -c \
        'import sys; open(sys.argv[1], "rb").read(1)' "$TARGET"
else
    print_skip "python3" "missing python3"
fi

if have_cmd nvim; then
    run_case "nvim" "$expect_nvim" nvim --headless +"q" "$TARGET"
else
    print_skip "nvim" "missing nvim"
fi

echo
echo "== Positive table checks =="
pubkey="$(first_existing "$HOME/.ssh/id_rsa.pub" "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_ecdsa.pub" || true)"
if [[ -n "$pubkey" ]] && have_cmd ssh-keygen; then
    run_case "ssh-keygen" "ALLOWED" ssh-keygen -l -f "$pubkey"
else
    print_skip "ssh-keygen" "missing public key or ssh-keygen"
fi

run_if_cmd git "git config" "ALLOWED" git config --global --list
run_if_cmd gpg "gpg list-keys" "ALLOWED" gpg --list-keys
run_if_cmd gh "gh auth status" "ALLOWED" gh auth status
run_if_cmd docker "docker info" "ALLOWED" docker info
run_if_cmd kubectl "kubectl context" "ALLOWED" kubectl config current-context

if [[ -e "$HOME/.claude/settings.json" ]]; then
    run_case "claude settings ls" "ALLOWED" ls "$HOME/.claude/settings.json"
else
    print_skip "claude settings ls" "missing ~/.claude/settings.json"
fi

if [[ "$EXTENDED" == "1" ]]; then
    run_if_cmd codex "codex startup" "ALLOWED" timeout 10 codex --help
else
    print_skip "codex startup" "set DIRBLOCK_EXTENDED=1"
fi

echo
echo "== Red-team table checks =="
private_key="$(first_existing "$HOME/.ssh/id_rsa" "$HOME/.ssh/id_ed25519" "$HOME/.ssh/id_ecdsa" || true)"
if [[ -n "$private_key" ]]; then
    run_case "cat private key" "${DIRBLOCK_EXPECT_CAT_PRIVATE:-}" cat "$private_key"
else
    print_skip "cat private key" "missing common private key path"
fi

if have_cmd python3; then
    run_case "python ssh config" "DENIED" python3 -c \
        'import os; open(os.path.expanduser("~/.ssh/config"), "rb").read(1)'
else
    print_skip "python ssh config" "missing python3"
fi

if [[ -e "$HOME/.aws/credentials" ]] && have_cmd curl; then
    run_case "curl aws creds" "DENIED" curl -fsS "file://$HOME/.aws/credentials"
else
    print_skip "curl aws creds" "missing ~/.aws/credentials or curl"
fi

if [[ -e "$HOME/.gnupg/trustdb.gpg" ]]; then
    run_case "cp gpg trustdb" "DENIED" cp "$HOME/.gnupg/trustdb.gpg" "$tmpdir/trustdb.gpg"
else
    print_skip "cp gpg trustdb" "missing ~/.gnupg/trustdb.gpg"
fi

if have_cmd tar; then
    run_case "tar ssh dir" "DENIED" tar czf "$tmpdir/ssh_exfil.tar.gz" "$HOME/.ssh"
else
    print_skip "tar ssh dir" "missing tar"
fi

if [[ -d "$HOME/.config/gh" ]]; then
    run_shell_case "find+cat gh" "DENIED" \
        'find "$HOME/.config/gh" -type f -exec sh -c '"'"'cat "$1" >/dev/null'"'"' sh {} \;'
else
    print_skip "find+cat gh" "missing ~/.config/gh"
fi

if [[ -n "$private_key" ]]; then
    ln -sf "$private_key" "$tmpdir/ssh_key_link"
    run_case "symlink bypass" "${DIRBLOCK_EXPECT_CAT_PRIVATE:-}" cat "$tmpdir/ssh_key_link"
else
    print_skip "symlink bypass" "missing common private key path"
fi

if [[ -e "$HOME/.kube/config" ]]; then
    run_case "dd kube config" "DENIED" dd "if=$HOME/.kube/config" of=/dev/null bs=1 count=100
else
    print_skip "dd kube config" "missing ~/.kube/config"
fi

if have_cmd strace; then
    run_case "strace+cat" "$expect_cat" strace -e openat cat "$TARGET"
else
    print_skip "strace+cat" "missing strace"
fi

echo
echo "== Runtime table checks =="
if have_cmd bun; then
    run_case "bun ssh config" "DENIED" bun -e \
        'require("fs").readFileSync(process.env.HOME + "/.ssh/config")'
    if [[ -e "$HOME/.claude/settings.json" ]]; then
        run_case "bun claude nofilter" "DENIED" bun -e \
            'require("fs").readFileSync(process.env.HOME + "/.claude/settings.json")'
        run_case "bun claude bypass" "ALLOWED" bun -e \
            'require("fs").readFileSync(process.env.HOME + "/.claude/settings.json")' claude
    else
        print_skip "bun claude tests" "missing ~/.claude/settings.json"
    fi
else
    print_skip "bun runtime" "missing bun"
fi

if have_cmd python3; then
    run_case "python claude" "DENIED" python3 -c \
        'import os; open(os.path.expanduser("~/.claude/settings.json"), "rb").read(1)'
fi

echo
echo "== VS Code table checks =="
if [[ -d "$HOME/.config/Code" ]]; then
    if have_cmd python3; then
        for path in \
            "$HOME/.config/Code/User/settings.json" \
            "$HOME/.config/Code/User/mcp.json" \
            "$HOME/.config/Code/User/globalStorage/storage.json"; do
            if [[ -e "$path" ]]; then
                name="python vscode ${path#$HOME/.config/Code/}"
                run_case "$name" "DENIED" python3 -c \
                    'import sys; open(sys.argv[1], "rb").read(1)' "$path"
            else
                print_skip "python vscode ${path#$HOME/.config/Code/}" "missing ${path#$HOME/}"
            fi
        done
    else
        print_skip "python vscode files" "missing python3"
    fi

    run_if_cmd code "code version" "ALLOWED" code --version
    run_if_cmd code "code extensions" "ALLOWED" code --list-extensions
else
    print_skip "vscode config" "missing ~/.config/Code"
fi
