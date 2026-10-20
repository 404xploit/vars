#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/vars.sh"
README="$ROOT_DIR/README.md"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

# Inventory derived from the legacy script and the public v2 interface.
legacy_tools=(
    httpx gau uro gf dalfox nuclei sqlmap jaeles xray kxss bhedak airixss freq
    hakrawler qsreplace anew paramspider xsstrike log4j-scan urldedupe tool
)
legacy_modes=(full recon xss sqli nuclei log4j)
supported_options=(
    -u -f -o -m -j -t -p -k --keep-going -h -v
    --scope-file --include-subdomains --allow-out-of-scope
)

for tool in "${legacy_tools[@]}"; do
    grep -Eq "(^|[[:space:]|()'])${tool}([[:space:]|()'\"]|$)" "$SCRIPT" "$README" || fail "ferramenta removida do inventário: $tool"
done

for mode in "${legacy_modes[@]}"; do
    grep -F -- "$mode" "$SCRIPT" "$README" >/dev/null || fail "modo removido: $mode"
done

for option in "${supported_options[@]}"; do
    grep -F -- "$option" "$SCRIPT" >/dev/null || fail "opção removida: $option"
done

for module in recon xss sqli nuclei log4j extended; do
    grep -F -- "run_module $module" "$SCRIPT" >/dev/null || fail "módulo ausente no pipeline: $module"
done

# Keep the security regression suite wired into the documented CI workflow.
CI_FILE="$ROOT_DIR/.github/workflows/ci.yml"
[[ -f "$CI_FILE" ]] || fail "workflow de CI ausente"
grep -F 'tests/test_output_symlinks.sh' "$CI_FILE" >/dev/null || fail "teste de symlink fora do CI"
grep -F 'shellcheck -x' "$CI_FILE" >/dev/null || fail "ShellCheck fora do CI"

printf 'OK: inventory (%d tools, %d modes, %d CLI options)\n' "${#legacy_tools[@]}" "${#legacy_modes[@]}" "${#supported_options[@]}"
