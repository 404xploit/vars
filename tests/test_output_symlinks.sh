#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/vars.sh"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vars-output-symlink-test.XXXXXX")"
trap 'rm -rf -- "$TEST_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

run_vars() {
    VARS_OUTPUT_REUSE=1 PATH=/usr/bin:/bin bash "$SCRIPT" \
        -u https://example.test -m recon -o "$1" >/dev/null 2>&1
}

expect_rejected() {
    local output="$1" description="$2"
    if run_vars "$output"; then
        fail "$description deveria ser rejeitado"
    fi
}

# A symlink used as the output root must not redirect writes.
mkdir -p "$TEST_DIR/root-target"
printf 'preserve-me\n' > "$TEST_DIR/root-target/sentinel"
ln -s "$TEST_DIR/root-target" "$TEST_DIR/root-link"
expect_rejected "$TEST_DIR/root-link" "diretório raiz simbólico"
[[ "$(cat "$TEST_DIR/root-target/sentinel")" == "preserve-me" ]] || fail "arquivo externo foi alterado"

# Existing internal output directories must not be followed.
mkdir -p "$TEST_DIR/internal-target"
printf 'preserve-me\n' > "$TEST_DIR/internal-target/sentinel"
mkdir -p "$TEST_DIR/internal-output"
ln -s "$TEST_DIR/internal-target" "$TEST_DIR/internal-output/meta"
expect_rejected "$TEST_DIR/internal-output" "diretório meta simbólico"
[[ "$(cat "$TEST_DIR/internal-target/sentinel")" == "preserve-me" ]] || fail "meta simbólico alterou destino"

mkdir -p "$TEST_DIR/recon-target" "$TEST_DIR/recon-output"
printf 'preserve-me\n' > "$TEST_DIR/recon-target/sentinel"
ln -s "$TEST_DIR/recon-target" "$TEST_DIR/recon-output/recon"
expect_rejected "$TEST_DIR/recon-output" "diretório recon simbólico"
[[ "$(cat "$TEST_DIR/recon-target/sentinel")" == "preserve-me" ]] || fail "recon simbólico alterou destino"

# Metadata files are checked too, not just their parent directories.
mkdir -p "$TEST_DIR/file-target" "$TEST_DIR/file-output/meta"
printf 'preserve-me\n' > "$TEST_DIR/file-target/sentinel"
ln -s "$TEST_DIR/file-target/sentinel" "$TEST_DIR/file-output/meta/vars.log"
expect_rejected "$TEST_DIR/file-output" "arquivo de log simbólico"
[[ "$(cat "$TEST_DIR/file-target/sentinel")" == "preserve-me" ]] || fail "link vars.log alterou destino"

# A normal reusable output directory remains supported.
mkdir -p "$TEST_DIR/normal-output"
run_vars "$TEST_DIR/normal-output"
[[ -f "$TEST_DIR/normal-output/meta/vars.log" ]] || fail "saída normal não foi criada"

printf 'OK: output symlink protection\n'
