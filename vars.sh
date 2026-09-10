#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# VARS banner — kept from the original project.
show_banner() {
    echo "                                                                              "
    echo "                                                                              "
    echo "vvvvvvv           vvvvvvvaaaaaaaaaaaaa  rrrrr   rrrrrrrrr       ssssssssss   "
    echo " v:::::v         v:::::v a::::::::::::a r::::rrr:::::::::r    ss::::::::::s  "
    echo "  v:::::v       v:::::v  aaaaaaaaa:::::ar:::::::::::::::::r ss:::::::::::::s "
    echo "   v:::::v     v:::::v            a::::arr::::::rrrrr::::::rs::::::ssss:::::s"
    echo "    v:::::v   v:::::v      aaaaaaa:::::a r:::::r     r:::::r s:::::s  ssssss "
    echo "     v:::::v v:::::v     aa::::::::::::a r:::::r     rrrrrrr   s::::::s      "
    echo "      v:::::v:::::v     a::::aaaa::::::a r:::::r                  s::::::s   "
    echo "       v:::::::::v     a::::a    a:::::a r:::::r            ssssss   s:::::s "
    echo "        v:::::::v      a::::a    a:::::a r:::::r            s:::::ssss::::::s"
    echo "         v:::::v       a:::::aaaa::::::a r:::::r            s::::::::::::::s "
    echo "          v:::v         a::::::::::aa:::ar:::::r             s:::::::::::ss  "
    echo "           vvv           aaaaaaaaaa  aaaarrrrrrr              sssssssssss    "
    echo "                                                                              "
    echo "feito por 0x404xploit"
    echo "VARS ${VERSION} - Vulnerability Assessment and Recon Script"
}

VERSION="2.0.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="vars_results"
TARGET_URL=""
INPUT_FILE=""
PROXY=""
MODE="full"
JOBS="5"
TIMEOUT="15"
KNOXSS_API_KEY="${KNOXSS_API_KEY:-}"
KEEP_GOING=0
TMP_DIR=""

TOOLS_DIR="${VARS_TOOLS_DIR:-${HOME}/.local/share/vars/tools}"
BIN_DIR="${VARS_BIN_DIR:-${HOME}/.local/bin}"
JAELES_SIGNATURES="${VARS_JAELES_SIGNATURES:-${TOOLS_DIR}/jaeles-signatures}"
NUCLEI_TEMPLATES="${VARS_NUCLEI_TEMPLATES:-${TOOLS_DIR}/nuclei-templates}"
PARAMSPIDER="${VARS_PARAMSPIDER:-${TOOLS_DIR}/ParamSpider/paramspider.py}"
XSSTRIKE="${VARS_XSSTRIKE:-${TOOLS_DIR}/XSStrike/xsstrike.py}"
LOG4J_SCAN="${VARS_LOG4J_SCAN:-${TOOLS_DIR}/log4j-scan/log4j-scan.py}"

log()  { printf '[%s] %s\n' "INFO" "$*"; }
warn() { printf '[%s] %s\n' "WARN" "$*" >&2; }
die()  { printf '[%s] %s\n' "ERROR" "$*" >&2; exit 1; }

cleanup() {
    if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then rm -rf -- "$TMP_DIR"; fi
}
trap cleanup EXIT
trap 'die "Unexpected error at line $LINENO"' ERR

usage() {
    cat <<EOF
Uso: $0 [opções]

  -u <url>       URL única
  -f <arquivo>   Arquivo com URLs, uma por linha
  -o <dir>       Diretório de saída (padrão: vars_results)
  -m <modo>      full|recon|xss|sqli|nuclei|log4j
  -j <jobs>      Concorrência (padrão: 5)
  -t <seg>       Timeout HTTP (padrão: 15)
  -p <proxy>     Proxy HTTP/HTTPS
  -k <chave>     Chave Knoxss; prefira KNOXSS_API_KEY
  --keep-going   Continua quando um módulo falha
  -h             Ajuda
  -v             Versão

Exemplos:
  $0 -u https://example.com -m xss
  $0 -f targets.txt -m full -j 10
  KNOXSS_API_KEY="..." $0 -f targets.txt -m xss

Use somente em ativos próprios ou explicitamente autorizados.
EOF
}

version() { printf 'VARS %s\n' "$VERSION"; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Dependência ausente: $1"; }
has_tool() { command -v "$1" >/dev/null 2>&1; }

check_runtime() {
    local dep
    for dep in awk grep sed sort mktemp xargs curl git; do require_cmd "$dep"; done
    [[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "-j deve ser um inteiro positivo"
    [[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "-t deve ser um inteiro positivo"
    [[ -z "$TARGET_URL" || -z "$INPUT_FILE" ]] || die "Use -u ou -f, não ambos"
    [[ -n "$TARGET_URL" || -n "$INPUT_FILE" ]] || die "Forneça -u ou -f"
    [[ -z "$INPUT_FILE" || -f "$INPUT_FILE" ]] || die "Arquivo não encontrado: $INPUT_FILE"
    case "$MODE" in full|recon|xss|sqli|nuclei|log4j) ;; *) die "Modo inválido: $MODE" ;; esac
}

normalize_targets() {
    local input="$1" output="$2"
    if [[ -f "$input" ]]; then awk 'NF && $1 !~ /^#/ {print $1}' "$input" > "$output"; else printf '%s\n' "$input" > "$output"; fi
    awk '/^https?:\/\// {gsub(/[[:space:]]+$/, ""); print}' "$output" | sort -u > "${output}.clean"
    mv -- "${output}.clean" "$output"
    [[ -s "$output" ]] || die "Nenhuma URL HTTP(S) válida encontrada"
}

setup_output() {
    mkdir -p -- "$OUTPUT_DIR"/{recon,xss,sqli,log4j,nuclei,misc,meta}
    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vars.XXXXXX")"
    printf 'VARS %s\nstarted=%s\nmode=%s\n' "$VERSION" "$(date -Is)" "$MODE" > "$OUTPUT_DIR/meta/run.txt"
}

configure_proxy() {
    [[ -z "$PROXY" ]] && return 0
    [[ "$PROXY" =~ ^https?:// ]] || die "Proxy deve usar http:// ou https://"
    export HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY" http_proxy="$PROXY" https_proxy="$PROXY"
}

check_optional_tools() {
    local tools=(httpx gau uro gf dalfox nuclei sqlmap jaeles xray kxss bhedak airixss freq hakrawler qsreplace anew paramspider xsstrike log4j-scan tool)
    local tool
    log "Inventário de ferramentas:"
    for tool in "${tools[@]}"; do
        if has_tool "$tool"; then printf '  [+] %s\n' "$tool"; else printf '  [-] %s\n' "$tool"; fi
    done
}

recon_module() {
    local targets="$1" live="$OUTPUT_DIR/recon/live.txt"
    : > "$live"
    if has_tool httpx; then httpx -silent -l "$targets" -threads "$JOBS" > "$live" || { warn "httpx falhou"; (( KEEP_GOING == 1 )) || return 1; }; else cp -- "$targets" "$live"; fi
    if has_tool gau; then gau --threads "$JOBS" < "$live" > "$OUTPUT_DIR/recon/gau.txt" || true; else : > "$OUTPUT_DIR/recon/gau.txt"; fi
    if has_tool uro && [[ -s "$OUTPUT_DIR/recon/gau.txt" ]]; then uro < "$OUTPUT_DIR/recon/gau.txt" > "$OUTPUT_DIR/recon/urls.txt" || true; else cp -- "$OUTPUT_DIR/recon/gau.txt" "$OUTPUT_DIR/recon/urls.txt" 2>/dev/null || :; fi
    if has_tool hakrawler; then hakrawler -subs < "$live" > "$OUTPUT_DIR/recon/crawl.txt" 2>&1 || true; fi
    sort -u "$live" "$OUTPUT_DIR/recon/urls.txt" 2>/dev/null | grep -E '^https?://' > "$OUTPUT_DIR/recon/candidates.txt" || true
}

xss_module() {
    local targets="$1" input="$OUTPUT_DIR/recon/candidates.txt"
    [[ -s "$input" ]] || input="$targets"
    if has_tool kxss; then kxss < "$input" > "$OUTPUT_DIR/xss/kxss.txt" 2>&1 || true; fi
    if has_tool dalfox; then dalfox file "$input" --skip-bav > "$OUTPUT_DIR/xss/dalfox.txt" 2>&1 || true; fi
    if has_tool xsstrike && [[ -f "$XSSTRIKE" ]]; then
        : > "$OUTPUT_DIR/xss/xsstrike.txt"
        while IFS= read -r url; do [[ -n "$url" ]] || continue; python3 "$XSSTRIKE" -u "$url" --fuzzer >> "$OUTPUT_DIR/xss/xsstrike.txt" 2>&1 || true; done < "$input"
    fi
    if has_tool nuclei; then nuclei -l "$input" -tags xss -o "$OUTPUT_DIR/xss/nuclei-xss.txt" || true; fi
}

sqli_module() {
    local targets="$1" input="$OUTPUT_DIR/recon/candidates.txt"
    [[ -s "$input" ]] || input="$targets"
    if has_tool gf && has_tool sqlmap; then
        gf sqli < "$input" | sort -u > "$TMP_DIR/sqli.txt" || true
        if [[ -s "$TMP_DIR/sqli.txt" ]]; then sqlmap -m "$TMP_DIR/sqli.txt" --batch --level=1 --output-dir="$OUTPUT_DIR/sqli/sqlmap" > "$OUTPUT_DIR/sqli/sqlmap.log" 2>&1 || true; fi
    fi
    if has_tool nuclei; then nuclei -l "$input" -tags sqli -o "$OUTPUT_DIR/sqli/nuclei-sqli.txt" || true; fi
}

log4j_module() {
    local targets="$1"
    [[ -f "$LOG4J_SCAN" ]] || { has_tool log4j-scan || return 0; }
    while IFS= read -r url; do
        [[ -n "$url" ]] || continue
        if [[ -f "$LOG4J_SCAN" ]]; then python3 "$LOG4J_SCAN" -u "$url" >> "$OUTPUT_DIR/log4j/results.txt" 2>&1 || true; else log4j-scan -u "$url" >> "$OUTPUT_DIR/log4j/results.txt" 2>&1 || true; fi
    done < "$targets"
}

nuclei_module() {
    local targets="$1"
    has_tool nuclei || return 0
    if [[ -d "$NUCLEI_TEMPLATES" ]]; then nuclei -l "$targets" -t "$NUCLEI_TEMPLATES" -o "$OUTPUT_DIR/nuclei/results.txt" || true; else nuclei -l "$targets" -o "$OUTPUT_DIR/nuclei/results.txt" || true; fi
}

knoxss_module() {
    local input="$OUTPUT_DIR/recon/candidates.txt"
    [[ -s "$input" ]] || input="$1"
    [[ -n "$KNOXSS_API_KEY" ]] || { warn "Knoxss ignorado: KNOXSS_API_KEY não configurada"; return 0; }
    : > "$OUTPUT_DIR/xss/knoxss.txt"
    while IFS= read -r url; do
        [[ -n "$url" ]] || continue
        curl --fail --silent --show-error --max-time "$TIMEOUT" -X POST 'https://knoxss.me/api/v3' -H "X-API-KEY: $KNOXSS_API_KEY" --data-urlencode "target=$url" >> "$OUTPUT_DIR/xss/knoxss.txt" 2>&1 || true
    done < "$input"
}

run_mode() {
    local targets="$1"
    case "$MODE" in
        recon) recon_module "$targets" ;;
        xss) recon_module "$targets"; xss_module "$targets"; knoxss_module "$targets" ;;
        sqli) recon_module "$targets"; sqli_module "$targets" ;;
        nuclei) nuclei_module "$targets" ;;
        log4j) log4j_module "$targets" ;;
        full) recon_module "$targets"; xss_module "$targets"; knoxss_module "$targets"; sqli_module "$targets"; log4j_module "$targets"; nuclei_module "$targets" ;;
    esac
}

main() {
    while (($#)); do
        case "$1" in
            -u) [[ $# -ge 2 ]] || die "-u requer uma URL"; TARGET_URL="$2"; shift 2 ;;
            -f) [[ $# -ge 2 ]] || die "-f requer um arquivo"; INPUT_FILE="$2"; shift 2 ;;
            -o) [[ $# -ge 2 ]] || die "-o requer um diretório"; OUTPUT_DIR="$2"; shift 2 ;;
            -m) [[ $# -ge 2 ]] || die "-m requer um modo"; MODE="$2"; shift 2 ;;
            -j) [[ $# -ge 2 ]] || die "-j requer um número"; JOBS="$2"; shift 2 ;;
            -t) [[ $# -ge 2 ]] || die "-t requer segundos"; TIMEOUT="$2"; shift 2 ;;
            -p) [[ $# -ge 2 ]] || die "-p requer um proxy"; PROXY="$2"; shift 2 ;;
            -k) [[ $# -ge 2 ]] || die "-k requer uma chave"; KNOXSS_API_KEY="$2"; shift 2 ;;
            --keep-going) KEEP_GOING=1; shift ;;
            -h|--help) usage; exit 0 ;;
            -v|--version) version; exit 0 ;;
            --) shift; break ;;
            *) die "Opção desconhecida: $1" ;;
        esac
    done
    check_runtime
    setup_output
    configure_proxy
    check_optional_tools
    local targets="$TMP_DIR/targets.txt"
    if [[ -n "$INPUT_FILE" ]]; then normalize_targets "$INPUT_FILE" "$targets"; else normalize_targets "$TARGET_URL" "$targets"; fi
    cp -- "$targets" "$OUTPUT_DIR/meta/targets.txt"
    log "Alvos: $(wc -l < "$targets")"
    log "Modo: $MODE"
    run_mode "$targets"
    printf 'finished=%s\n' "$(date -Is)" >> "$OUTPUT_DIR/meta/run.txt"
    log "Concluído. Resultados: $OUTPUT_DIR"
}

show_banner
main "$@"
