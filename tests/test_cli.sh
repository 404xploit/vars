#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/vars.sh"

assert_contains() {
    local haystack="$1" needle="$2" label="$3"
    [[ "$haystack" == *"$needle"* ]] || {
        printf 'FAIL: %s (ausente: %s)\n' "$label" "$needle" >&2
        exit 1
    }
}

assert_not_contains() {
    local haystack="$1" needle="$2" label="$3"
    [[ "$haystack" != *"$needle"* ]] || {
        printf 'FAIL: %s (inesperado: %s)\n' "$label" "$needle" >&2
        exit 1
    }
}

help_output="$(bash "$SCRIPT" --help)"
assert_contains "$help_output" "Uso: $SCRIPT [opções]" "help exibe uso"
assert_not_contains "$help_output" "feito por 0x404xploit" "help não exibe banner"

version_output="$(bash "$SCRIPT" --version)"
assert_contains "$version_output" "VARS 2.1.0" "version exibe versão"
assert_not_contains "$version_output" "feito por 0x404xploit" "version não exibe banner"

if bash "$SCRIPT" --invalid >/dev/null 2>&1; then
    printf 'FAIL: opção inválida deveria falhar\n' >&2
    exit 1
fi

printf 'OK: CLI\n'
