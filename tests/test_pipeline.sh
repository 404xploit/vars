#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/vars.sh"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vars-pipeline-test.XXXXXX")"
trap 'rm -rf -- "$TEST_DIR"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

FAKE_BIN="$TEST_DIR/bin"
mkdir -p "$FAKE_BIN"

# Every stub is local and deterministic. It echoes file/stdin inputs when a
# pipeline needs data and otherwise returns success without making requests.
for tool in httpx gau uro gf dalfox nuclei sqlmap jaeles xray kxss bhedak airixss freq hakrawler qsreplace anew paramspider xsstrike log4j-scan urldedupe; do
    cat > "$FAKE_BIN/$tool" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
TOOL="$(basename -- "$0")"
while (($#)); do
    case "$1" in
        -l|file)
            [[ $# -ge 2 ]] && cat -- "$2"
            exit 0
            ;;
    esac
    shift
done
case "$TOOL" in
    httpx|gau|uro|gf|kxss|bhedak|airixss|freq|hakrawler|qsreplace|anew|urldedupe)
        [[ ! -t 0 ]] && cat
        ;;
esac
exit 0
EOF
    chmod +x "$FAKE_BIN/$tool"
done

OUT="$TEST_DIR/results"
RUN_OUT="$TEST_DIR/run.out"
RUN_ERR="$TEST_DIR/run.err"
if ! VARS_BIN_DIR="$FAKE_BIN" PATH=/usr/bin:/bin bash "$SCRIPT" -u https://example.net -m full -j 2 -t 3 -o "$OUT" --keep-going >"$RUN_OUT" 2>"$RUN_ERR"; then
    cat "$RUN_OUT" "$RUN_ERR" >&2
    fail "full pipeline com stubs deveria concluir"
fi

[[ -f "$OUT/meta/tool-status.tsv" ]] || fail "inventário ausente"
[[ -f "$OUT/meta/summary.txt" ]] || fail "resumo ausente"
grep -F '[execution_counts]' "$OUT/meta/summary.txt" >/dev/null || fail "contagens de execução ausentes"
grep -F $'httpx\tavailable' "$OUT/meta/tool-status.tsv" >/dev/null || fail "httpx não foi preservado no inventário"
grep -F $'log4j-scan\tavailable' "$OUT/meta/tool-status.tsv" >/dev/null || fail "log4j-scan não foi preservado no inventário"
grep -F $'extended\t' "$OUT/meta/module-status.tsv" >/dev/null || fail "módulo extended não foi executado"
grep -F $'exit_status=0' "$OUT/meta/summary.txt" >/dev/null || fail "full pipeline terminou com status inesperado"

printf 'OK: pipeline smoke\n'
