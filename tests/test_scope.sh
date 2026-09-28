#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/vars.sh"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vars-scope-test.XXXXXX")"
trap 'rm -rf -- "$TEST_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

assert_contains() {
    local file="$1" needle="$2"
    grep -F -- "$needle" "$file" >/dev/null || fail "${needle} ausente em ${file}"
}

assert_not_contains() {
    local file="$1" needle="$2"
    if grep -F -- "$needle" "$file" >/dev/null; then
        fail "${needle} não deveria aparecer em ${file}"
    fi
}

FAKE_BIN="$TEST_DIR/bin"
mkdir -p "$FAKE_BIN"

cat > "$FAKE_BIN/httpx" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
input="$(mktemp)"
trap 'rm -f -- "$input"' EXIT
input_file=""
while (($#)); do
    if [[ "$1" == "-l" && $# -ge 2 ]]; then
        input_file="$2"
        shift 2
        continue
    fi
    shift
done
if [[ -n "$input_file" ]]; then
    cat -- "$input_file" > "$input"
else
    cat > "$input"
fi
if [[ "${ACTIVE_REJECT_OUTSIDE:-0}" == 1 ]] && grep -E '(third-party\.invalid|outside\.invalid|cdn\.example\.net|api\.example\.net|evil-example\.net|example\.net\.evil\.invalid)' "$input" >/dev/null; then
    printf 'URL fora do escopo chegou ao httpx\n' >&2
    exit 90
fi
cat "$input"
if [[ "${HTTPX_INJECT:-0}" == 1 ]]; then
    printf '%s\n' 'https://httpx-outside.invalid/injected?x=1'
fi
EOF

cat > "$FAKE_BIN/gau" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
cat >/dev/null
printf '%s\n' \
    'https://example.net/app?id=1' \
    'https://example.net.:8443/trailing-dot?id=1' \
    'https://api.example.net/v1?id=2' \
    'https://third-party.invalid/callback?token=x' \
    'https://example.net.evil.invalid/lookalike?id=1' \
    'https://evil-example.net/lookalike?id=1' \
    'https://evil.invalid\@example.net/parser-bypass?id=1' \
    'https:///missing-host' \
    'https://user@example.net/userinfo?id=1'
EOF

cat > "$FAKE_BIN/uro" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
cat
EOF

cat > "$FAKE_BIN/hakrawler" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
has_subs=0
for arg in "$@"; do
    [[ "$arg" == '-subs' ]] && has_subs=1
done
if [[ "${REJECT_HAKRAWLER_SUBS:-0}" == 1 && "$has_subs" == 1 ]]; then
    printf '%s\n' '-subs usado sem autorização' >&2
    exit 91
fi
if [[ "${REQUIRE_HAKRAWLER_SUBS:-0}" == 1 && "$has_subs" == 0 ]]; then
    printf '%s\n' '-subs ausente com subdomínios autorizados' >&2
    exit 92
fi
input="$(mktemp)"
trap 'rm -f -- "$input"' EXIT
cat > "$input"
if [[ "${ACTIVE_REJECT_OUTSIDE:-0}" == 1 ]] && grep -E '(third-party\.invalid|outside\.invalid|cdn\.example\.net|api\.example\.net)' "$input" >/dev/null; then
    printf 'URL fora do escopo chegou ao hakrawler\n' >&2
    exit 90
fi
printf '%s\n' \
    'https://example.net/local?x=1' \
    'https://cdn.example.net/script.js?x=1' \
    'https://cdn.third-party.invalid/script.js?x=1'
EOF

cat > "$FAKE_BIN/paramspider" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' \
    'https://example.net/from-paramspider?id=1' \
    'https://param-outside.invalid/from-paramspider?id=1'
EOF

cat > "$FAKE_BIN/gf" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${GF_FAIL:-0}" == 1 ]]; then
    exit 17
fi
cat
if [[ "${GF_INJECT:-0}" == 1 ]]; then
    printf '%s\n' 'https://gf-outside.invalid/injected?x=1'
fi
EOF

cat > "$FAKE_BIN/urldedupe" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
cat
if [[ "${URLDEDUPE_INJECT:-0}" == 1 ]]; then
    printf '%s\n' 'https://urldedupe-outside.invalid/injected?x=1'
fi
EOF

cat > "$FAKE_BIN/bhedak" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
input="$(mktemp)"
trap 'rm -f -- "$input"' EXIT
cat > "$input"
if [[ "${ACTIVE_REJECT_OUTSIDE:-0}" == 1 ]] && grep -F 'outside.invalid' "$input" >/dev/null; then
    printf 'URL fora do escopo chegou ao Bhedak\n' >&2
    exit 90
fi
cat "$input"
EOF

cat > "$FAKE_BIN/qsreplace" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${QSREPLACE_FAIL:-0}" == 1 ]]; then
    exit 7
fi
cat
if [[ "${QSREPLACE_INJECT:-0}" == 1 ]]; then
    printf '%s\n' 'https://qsreplace-outside.invalid/injected?x=1'
fi
EOF

cat > "$FAKE_BIN/airixss" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
capture="${AIRIXSS_CAPTURE:?}"
input="$(mktemp)"
trap 'rm -f -- "$input"' EXIT
cat > "$input"
{
    printf '%s\n' '--- invocation ---'
    cat "$input"
} >> "$capture"
if grep -E '(third-party|outside|qsreplace-outside)\.invalid' "$input" >/dev/null; then
    printf 'URL fora do escopo chegou ao Airixss\n' >&2
    exit 90
fi
if [[ "${AIRIXSS_FAIL:-0}" == 1 ]]; then
    exit 7
fi
cat "$input"
EOF

cat > "$FAKE_BIN/freq" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
input="$(mktemp)"
trap 'rm -f -- "$input"' EXIT
cat > "$input"
if [[ "${ACTIVE_REJECT_OUTSIDE:-0}" == 1 ]] && grep -F 'outside.invalid' "$input" >/dev/null; then
    printf 'URL fora do escopo chegou ao Freq\n' >&2
    exit 90
fi
cat "$input"
EOF

cat > "$FAKE_BIN/sqlmap" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
input_file=""
while (($#)); do
    if [[ "$1" == '-m' && $# -ge 2 ]]; then
        input_file="$2"
        shift 2
        continue
    fi
    shift
done
if [[ "${ACTIVE_REJECT_OUTSIDE:-0}" == 1 && -n "$input_file" ]] && grep -F 'outside.invalid' "$input_file" >/dev/null; then
    printf 'URL fora do escopo chegou ao SQLmap\n' >&2
    exit 90
fi
exit 0
EOF

chmod +x "$FAKE_BIN/"*

DEFAULT_OUT="$TEST_DIR/default"
REJECT_HAKRAWLER_SUBS=1 VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u https://example.net -m recon -o "$DEFAULT_OUT" >/dev/null 2>&1
assert_contains "$DEFAULT_OUT/meta/scope.txt" 'example.net'
assert_contains "$DEFAULT_OUT/recon/candidates.txt" 'https://example.net/app?id=1'
assert_contains "$DEFAULT_OUT/recon/candidates.txt" 'https://example.net.:8443/trailing-dot?id=1'
assert_not_contains "$DEFAULT_OUT/recon/candidates.txt" 'https://api.example.net/v1?id=2'
assert_not_contains "$DEFAULT_OUT/recon/candidates.txt" 'https://third-party.invalid/callback?token=x'
assert_not_contains "$DEFAULT_OUT/recon/candidates.txt" 'https://example.net.evil.invalid/lookalike?id=1'
assert_not_contains "$DEFAULT_OUT/recon/candidates.txt" 'https://evil-example.net/lookalike?id=1'
assert_not_contains "$DEFAULT_OUT/recon/candidates.txt" 'parser-bypass'
assert_not_contains "$DEFAULT_OUT/recon/candidates.txt" 'missing-host'
assert_not_contains "$DEFAULT_OUT/recon/candidates.txt" 'userinfo'
assert_contains "$DEFAULT_OUT/misc/paramspider.txt" 'https://example.net/from-paramspider?id=1'
assert_not_contains "$DEFAULT_OUT/misc/paramspider.txt" 'https://param-outside.invalid/from-paramspider?id=1'
assert_contains "$DEFAULT_OUT/meta/out-of-scope.tsv" $'gau\thttps://api.example.net/v1?id=2\tblocked'
assert_contains "$DEFAULT_OUT/meta/out-of-scope.tsv" $'hakrawler\thttps://cdn.third-party.invalid/script.js?x=1\tblocked'
assert_contains "$DEFAULT_OUT/meta/out-of-scope.tsv" $'paramspider\thttps://param-outside.invalid/from-paramspider?id=1\tblocked'
assert_contains "$DEFAULT_OUT/meta/summary.txt" 'blocked='

SUBDOMAIN_OUT="$TEST_DIR/subdomains"
REQUIRE_HAKRAWLER_SUBS=1 VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u https://example.net -m recon -o "$SUBDOMAIN_OUT" --include-subdomains >/dev/null 2>&1
assert_contains "$SUBDOMAIN_OUT/recon/candidates.txt" 'https://api.example.net/v1?id=2'
assert_contains "$SUBDOMAIN_OUT/recon/candidates.txt" 'https://cdn.example.net/script.js?x=1'
assert_not_contains "$SUBDOMAIN_OUT/recon/candidates.txt" 'https://third-party.invalid/callback?token=x'
assert_contains "$SUBDOMAIN_OUT/meta/summary.txt" 'blocked='

ALLOW_OUT="$TEST_DIR/allow"
VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u https://example.net -m recon -o "$ALLOW_OUT" --allow-out-of-scope >/dev/null 2>&1
assert_contains "$ALLOW_OUT/recon/candidates.txt" 'https://third-party.invalid/callback?token=x'
assert_contains "$ALLOW_OUT/recon/candidates.txt" 'https://cdn.third-party.invalid/script.js?x=1'
assert_contains "$ALLOW_OUT/meta/out-of-scope.tsv" $'gau\thttps://third-party.invalid/callback?token=x\tallowed_override'
assert_contains "$ALLOW_OUT/meta/summary.txt" 'allowed_override='
assert_not_contains "$ALLOW_OUT/recon/candidates.txt" 'parser-bypass'
assert_not_contains "$ALLOW_OUT/recon/candidates.txt" 'missing-host'
assert_not_contains "$ALLOW_OUT/recon/candidates.txt" 'userinfo'
if tail -n +2 "$ALLOW_OUT/meta/out-of-scope.tsv" | cut -f2,3 | sort | uniq -d | grep . >/dev/null; then
    fail "auditoria de exceções contém URLs duplicadas"
fi

AIRIXSS_CAPTURE="$TEST_DIR/airixss-input.txt"
XSS_OUT="$TEST_DIR/xss"
AIRIXSS_CAPTURE="$AIRIXSS_CAPTURE" ACTIVE_REJECT_OUTSIDE=1 HTTPX_INJECT=1 GF_INJECT=1 \
    URLDEDUPE_INJECT=1 QSREPLACE_INJECT=1 REJECT_HAKRAWLER_SUBS=1 \
    VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u https://example.net -m xss -o "$XSS_OUT" >/dev/null 2>&1
[[ -f "$AIRIXSS_CAPTURE" ]] || fail "pipelines Airixss não foram exercitados"
assert_contains "$AIRIXSS_CAPTURE" 'https://example.net/local?x=1'
assert_not_contains "$AIRIXSS_CAPTURE" 'third-party.invalid'
assert_not_contains "$AIRIXSS_CAPTURE" 'cdn.example.net'
assert_not_contains "$AIRIXSS_CAPTURE" 'qsreplace-outside.invalid'
assert_not_contains "$AIRIXSS_CAPTURE" 'outside.invalid'

AIRIXSS_FAIL_OUT="$TEST_DIR/airixss-fail"
if AIRIXSS_CAPTURE="$TEST_DIR/airixss-fail-input.txt" AIRIXSS_FAIL=1 \
    VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u https://example.net -m xss -o "$AIRIXSS_FAIL_OUT" >/dev/null 2>&1; then
    fail "falha do Airixss deveria tornar o módulo XSS malsucedido"
fi
assert_contains "$AIRIXSS_FAIL_OUT/meta/execution-status.tsv" $'Bhedak + urldedupe + Airixss\tfailed\t7'

GF_FAIL_OUT="$TEST_DIR/gf-fail"
if AIRIXSS_CAPTURE="$TEST_DIR/gf-fail-airixss.txt" GF_FAIL=1 \
    VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u https://example.net -m xss -o "$GF_FAIL_OUT" --keep-going >/dev/null 2>&1; then
    fail "falha dura do GF deveria tornar o módulo XSS malsucedido"
fi
assert_contains "$GF_FAIL_OUT/meta/execution-status.tsv" $'GF + URO + qsreplace + Airixss\tfailed\t17'

SQLI_FAIL_OUT="$TEST_DIR/sqli-fail"
if QSREPLACE_FAIL=1 VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u 'https://example.net/item?id=1' -m sqli -o "$SQLI_FAIL_OUT" >/dev/null 2>&1; then
    fail "falha do qsreplace deveria tornar o módulo SQLi malsucedido"
fi
assert_contains "$SQLI_FAIL_OUT/meta/execution-status.tsv" $'qsreplace + httpx (SQLi heurístico)\tfailed\t7'

SQLI_GF_FAIL_OUT="$TEST_DIR/sqli-gf-fail"
if GF_FAIL=1 VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u 'https://example.net/item?id=1' -m sqli -o "$SQLI_GF_FAIL_OUT" --keep-going >/dev/null 2>&1; then
    fail "falha dura do GF deveria tornar o módulo SQLi malsucedido"
fi
assert_contains "$SQLI_GF_FAIL_OUT/meta/execution-status.tsv" $'GF + httpx + SQLmap\tfailed\t17'

SCOPE_FILE="$TEST_DIR/scope.txt"
printf '%s\n' '# Escopo autorizado' 'https://example.net/program' > "$SCOPE_FILE"
SCOPE_OUT="$TEST_DIR/scope-file"
VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u https://api.example.net -m recon -o "$SCOPE_OUT" \
    --scope-file "$SCOPE_FILE" --include-subdomains >/dev/null 2>&1
assert_contains "$SCOPE_OUT/meta/scope.txt" 'example.net'
assert_contains "$SCOPE_OUT/meta/run.txt" "scope_source=$SCOPE_FILE"

PORT_OUT="$TEST_DIR/port"
VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u 'https://EXAMPLE.NET:8443/path' -m recon -o "$PORT_OUT" \
    --scope-file "$SCOPE_FILE" >/dev/null 2>&1
assert_contains "$PORT_OUT/meta/scope.txt" 'example.net'

if VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u https://outside.invalid -m recon -o "$TEST_DIR/rejected-target" \
    --scope-file "$SCOPE_FILE" >/dev/null 2>&1; then
    fail "alvo inicial fora do arquivo de escopo deveria falhar"
fi
[[ ! -e "$TEST_DIR/rejected-target" ]] || fail "alvo fora do escopo criou artefatos"

if VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u https://evil-example.net -m recon -o "$TEST_DIR/lookalike-target" \
    --scope-file "$SCOPE_FILE" --include-subdomains >/dev/null 2>&1; then
    fail "host parecido não deveria passar como subdomínio"
fi
[[ ! -e "$TEST_DIR/lookalike-target" ]] || fail "host parecido criou artefatos"

INVALID_SCOPE="$TEST_DIR/invalid-scope.txt"
printf '%s\n' 'example.net/path' > "$INVALID_SCOPE"
if VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u https://example.net -m recon -o "$TEST_DIR/invalid-scope-out" \
    --scope-file "$INVALID_SCOPE" >/dev/null 2>&1; then
    fail "entrada inválida no arquivo de escopo deveria falhar"
fi
[[ ! -e "$TEST_DIR/invalid-scope-out" ]] || fail "escopo inválido criou artefatos"

EMPTY_SCOPE="$TEST_DIR/empty-scope.txt"
: > "$EMPTY_SCOPE"
if VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u https://example.net -m recon -o "$TEST_DIR/empty-scope-out" \
    --scope-file "$EMPTY_SCOPE" >/dev/null 2>&1; then
    fail "arquivo de escopo vazio deveria falhar"
fi
[[ ! -e "$TEST_DIR/empty-scope-out" ]] || fail "escopo vazio criou artefatos"

IPV6_SCOPE="$TEST_DIR/ipv6-scope.txt"
printf '%s\n' '[2001:db8::1]:8443' > "$IPV6_SCOPE"
IPV6_OUT="$TEST_DIR/ipv6"
VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u 'https://[2001:db8::1]:8443/path' -m recon -o "$IPV6_OUT" \
    --scope-file "$IPV6_SCOPE" >/dev/null 2>&1
assert_contains "$IPV6_OUT/meta/scope.txt" '2001:db8::1'

IPV4_MAPPED_SCOPE="$TEST_DIR/ipv4-mapped-scope.txt"
printf '%s\n' '[::ffff:192.0.2.1]' > "$IPV4_MAPPED_SCOPE"
IPV4_MAPPED_OUT="$TEST_DIR/ipv4-mapped"
VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u 'https://[::ffff:192.0.2.1]/path' -m recon -o "$IPV4_MAPPED_OUT" \
    --scope-file "$IPV4_MAPPED_SCOPE" >/dev/null 2>&1
assert_contains "$IPV4_MAPPED_OUT/meta/scope.txt" '::ffff:192.0.2.1'

IPV4_SCOPE="$TEST_DIR/ipv4-scope.txt"
printf '%s\n' '127.0.0.1' > "$IPV4_SCOPE"
if VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
    -u 'https://evil.127.0.0.1/' -m recon -o "$TEST_DIR/ipv4-subdomain" \
    --scope-file "$IPV4_SCOPE" --include-subdomains >/dev/null 2>&1; then
    fail "subdomínio textual de IPv4 não deveria ser autorizado"
fi
[[ ! -e "$TEST_DIR/ipv4-subdomain" ]] || fail "subdomínio textual de IPv4 criou artefatos"

invalid_urls=(
    'https://example.net:'
    'https://example.net:/path'
    'https://[::::]/'
    'https://[1:2:3:4:5:6:7:8:9]/'
    'https://[2001:db8:0:1:2:3:4:5:]/'
    'https://_example.net/'
    'https://example-.net/'
    'https://example.net../'
    'https://example.net..:80/'
    'https://user@example.net/'
    'https://evil.invalid\@example.net/'
)
for index in "${!invalid_urls[@]}"; do
    invalid_out="$TEST_DIR/invalid-url-${index}"
    if VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" \
        -u "${invalid_urls[$index]}" -m recon -o "$invalid_out" >/dev/null 2>&1; then
        fail "authority inválida foi aceita: ${invalid_urls[$index]}"
    fi
    [[ ! -e "$invalid_out" ]] || fail "authority inválida criou artefatos: ${invalid_urls[$index]}"
done

printf 'OK: scope enforcement\n'
