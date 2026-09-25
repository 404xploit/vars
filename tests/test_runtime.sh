#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/vars.sh"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vars-test.XXXXXX")"
trap 'rm -rf -- "$TEST_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

assert_file() {
    [[ -f "$1" ]] || fail "arquivo ausente: $1"
}

assert_contains() {
    local file="$1" needle="$2"
    grep -F -- "$needle" "$file" >/dev/null || fail "${needle} ausente em ${file}"
}

cat > "$TEST_DIR/targets.txt" <<'EOF'
# comentário
https://example.com/path
https://example.com/path
invalid-target
https://example.org/
EOF

RECON_OUT="$TEST_DIR/recon"
PATH=/usr/bin:/bin bash "$SCRIPT" -f "$TEST_DIR/targets.txt" -m recon -j 2 -t 7 -o "$RECON_OUT" >/dev/null 2>&1
assert_file "$RECON_OUT/meta/targets.txt"
assert_file "$RECON_OUT/meta/tool-status.tsv"
assert_file "$RECON_OUT/meta/module-status.tsv"
assert_file "$RECON_OUT/meta/execution-status.tsv"
assert_file "$RECON_OUT/meta/summary.txt"
[[ "$(stat -c '%a' "$RECON_OUT/meta")" == "700" ]] || fail "metadados não estão privados"
assert_contains "$RECON_OUT/meta/targets.txt" "https://example.com/path"
assert_contains "$RECON_OUT/meta/targets.txt" "https://example.org/"
assert_contains "$RECON_OUT/meta/run.txt" $'jobs=2'
assert_contains "$RECON_OUT/meta/run.txt" $'timeout=7'
assert_contains "$RECON_OUT/meta/summary.txt" $'exit_status=0'

SKIPPED_OUT="$TEST_DIR/skipped"
PATH=/usr/bin:/bin bash "$SCRIPT" -u https://example.net -m xss -o "$SKIPPED_OUT" >/dev/null 2>&1
assert_contains "$SKIPPED_OUT/meta/module-status.tsv" $'xss\t'
assert_contains "$SKIPPED_OUT/meta/module-status.tsv" $'\tskipped\t2'
assert_contains "$SKIPPED_OUT/meta/summary.txt" $'exit_status=0'

REUSED_OUT="$TEST_DIR/reused"
mkdir -p "$REUSED_OUT"
printf 'keep\n' > "$REUSED_OUT/marker.txt"
PATH=/usr/bin:/bin bash "$SCRIPT" -u https://example.net -m recon -o "$REUSED_OUT" >/dev/null 2>&1
ISOLATED_RUN="$(find "$REUSED_OUT" -mindepth 1 -maxdepth 1 -type d -name 'run-*' -print -quit)"
[[ -n "$ISOLATED_RUN" ]] || fail "saída existente não foi isolada"
assert_file "$REUSED_OUT/marker.txt"

if bash "$SCRIPT" -u example.com -m recon -o "$TEST_DIR/invalid" >/dev/null 2>&1; then
    fail "URL inválida deveria falhar"
fi

PROXY_OUT="$TEST_DIR/proxy"
if bash "$SCRIPT" -u https://example.net -m recon -p invalid-proxy -o "$PROXY_OUT" >/dev/null 2>&1; then
    fail "proxy inválido deveria falhar"
fi
[[ ! -e "$PROXY_OUT" ]] || fail "proxy inválido criou artefatos antes da validação"

CONTROL_OUT="$TEST_DIR/control"
if VARS_OUTPUT_DIR=$'bad\npath' bash "$SCRIPT" -u https://example.net -m recon >/dev/null 2>&1; then
    fail "diretório com controle deveria falhar"
fi
if KNOXSS_API_KEY=$'bad\nkey' bash "$SCRIPT" -u https://example.net -m recon -o "$CONTROL_OUT" >/dev/null 2>&1; then
    fail "chave com controle deveria falhar"
fi
[[ ! -e "$CONTROL_OUT" ]] || fail "chave inválida criou artefatos antes da validação"

PRECEDENCE_OUT="$TEST_DIR/precedence"
PATH=/usr/bin:/bin VARS_JOBS=9 VARS_TIMEOUT=99 bash "$SCRIPT" -u https://example.net -m recon -j 2 -t 7 -o "$PRECEDENCE_OUT" >/dev/null 2>&1
assert_contains "$PRECEDENCE_OUT/meta/run.txt" $'jobs=2'
assert_contains "$PRECEDENCE_OUT/meta/run.txt" $'timeout=7'

FAKE_BIN="$TEST_DIR/bin"
mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/httpx" <<'EOF'
#!/usr/bin/env bash
exit 7
EOF
chmod +x "$FAKE_BIN/httpx"
KEEP_OUT="$TEST_DIR/keep-going"
if VARS_BIN_DIR="$FAKE_BIN" bash "$SCRIPT" -u https://example.net -m xss -o "$KEEP_OUT" --keep-going >/dev/null 2>&1; then
    fail "keep-going deveria preservar status não zero após falha"
fi
assert_contains "$KEEP_OUT/meta/module-status.tsv" $'recon\t'
assert_contains "$KEEP_OUT/meta/module-status.tsv" $'\tfailed\t'
assert_contains "$KEEP_OUT/meta/module-status.tsv" $'xss\t'
assert_contains "$KEEP_OUT/meta/execution-status.tsv" $'httpx (alvos ativos)\tfailed\t7'

printf 'OK: runtime\n'
