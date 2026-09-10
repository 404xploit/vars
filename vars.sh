#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

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

# User-overridable paths. Nothing is hard-coded to /root anymore.
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
    if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
        rm -rf -- "$TMP_DIR"
    fi
}
trap cleanup EXIT
trap 'die "Unexpected error at line $LINENO"' ERR

usage() {
    cat <<EOF
VARS ${VERSION} - Vulnerability Assessment and Recon Suite

Uso:
  $0 -u <url> [opções]
  $0 -f <arquivo> [opções]

Opções:
  -u <url>       URL única
  -f <arquivo>   Arquivo com URLs, uma por linha
  -o <dir>       Diretório de saída (padrão: vars_results)
  -m <modo>      full|recon|xss|sqli|nuclei|log4j (padrão: full)
  -j <jobs>      Concorrência máxima do pipeline (padrão: 5)
  -t <seg>       Timeout por ferramenta quando suportado (padrão: 15)
  -p <proxy>     Proxy HTTP/HTTPS
  -k <chave>     Chave Knoxss (preferível: KNOXSS_API_KEY)
  --keep-going   Continua mesmo quando um módulo falha
  -h             Ajuda
  -v             Versão

Exemplos:
  $0 -u https://example.com -m xss
  $0 -f targets.txt -m recon -o results
  KNOXSS_API_KEY=... $0 -f targets.txt -m full

Use somente em ativos próprios ou explicitamente autorizados.
EOF
}

version() { printf 'VARS %s\n' "$VERSION"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Dependência ausente: $1"
}

check_runtime() {
    require_cmd awk
    require_cmd grep
    require_cmd sed
    require_cmd sort
    require_cmd mktemp
    require_cmd xargs
    require_cmd curl
    require_cmd git

    [[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "-j deve ser um inteiro positivo"
    [[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "-t deve ser um inteiro positivo"
    [[ -z "$TARGET_URL" || -z "$INPUT_FILE" ]] || die "Use -u ou -f, não ambos"
    [[ -n "$TARGET_URL" || -n "$INPUT_FILE" ]] || die "Forneça -u ou -f"
    [[ -z "$INPUT_FILE" || -f "$INPUT_FILE" ]] || die "Arquivo não encontrado: $INPUT_FILE"

    case "$MODE" in
        full|recon|xss|sqli|nuclei|log4j) ;;
        *) die "Modo inválido: $MODE" ;;
    esac
}

normalize_targets() {
    local input="$1"
    local output="$2"

    if [[ -f "$input" ]]; then
        awk 'NF && $1 !~ /^#/ {print $1}' "$input" > "$output"
    else
        printf '%s\n' "$input" > "$output"
    fi

    # Only accept HTTP(S) URLs. This prevents accidental command/path interpretation.
    awk '
        /^https?:\/\// {
            gsub(/[[:space:]]+$/, ""); print
        }
    ' "$output" | sort -u > "${output}.clean"
    mv -- "${output}.clean" "$output"

    [[ -s "$output" ]] || die "Nenhuma URL HTTP(S) válida encontrada"
}

setup_output() {
    mkdir -p -- "$OUTPUT_DIR"/{recon,xss,sqli,log4j,nuclei,misc,meta}
    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vars.XXXXXX")"
    printf 'VARS %s\n' "$VERSION" > "$OUTPUT_DIR/meta/run.txt"
    printf 'started=%s\n' "$(date -Is)" >> "$OUTPUT_DIR/meta/run.txt"
    printf 'mode=%s\n' "$MODE" >> "$OUTPUT_DIR/meta/run.txt"
}

configure_proxy() {
    [[ -z "$PROXY" ]] && return 0
    [[ "$PROXY" =~ ^https?:// ]] || die "Proxy deve usar http:// ou https://"
    export HTTP_PROXY="$PROXY"
    export HTTPS_PROXY="$PROXY"
    export http_proxy="$PROXY"
    export https_proxy="$PROXY"
    log "Proxy configurado"
}

has_tool() { command -v "$1" >/dev/null 2>&1; }

check_tool() {
    if ! has_tool "$1"; then
        warn "Ferramenta não encontrada: $1 — módulo será ignorado"
        return 1
    fi
    return 0
}

check_optional_tools() {
    local tools=(httpx gau uro gf dalfox nuclei sqlmap jaeles xray kxss bhedak airixss freq hakrawler qsreplace anew paramspider xsstrike log4j-scan)
    log "Inventário de ferramentas:"
    local tool
    for tool in "${tools[@]}"; do
        if has_tool "$tool"; then
            printf '  [+] %s\n' "$tool"
        else
            printf '  [-] %s\n' "$tool"
        fi
    done
}

run_cmd() {
    local name="$1"
    shift
    local logfile="$OUTPUT_DIR/meta/${name}.log"
    log "Running: $name"
    if "$@" >"$logfile" 2>&1; then
        log "OK: $name"
        return 0
    fi
    warn "Falhou: $name (log: $logfile)"
    (( KEEP_GOING == 1 )) && return 0
    return 1
}

run_pipeline() {
    local name="$1"
    local input="$2"
    local output="$3"
    shift 3

    log "Module: $name"
    if "$@" < "$input" > "$output" 2>&1; then
        log "OK: $name"
    else
        warn "Falhou: $name (resultado: $output)"
        (( KEEP_GOING == 1 )) || return 1
    fi
}

recon_module() {
    local targets="$1"
    local live="$OUTPUT_DIR/recon/live.txt"
    : > "$live"

    if check_tool httpx; then
        httpx -silent -l "$targets" -threads "$JOBS" > "$live" || {
            warn "httpx falhou"
            (( KEEP_GOING == 1 )) || return 1
        }
    else
        cp -- "$targets" "$live"
    fi

    if check_tool gau; then
        gau --threads "$JOBS" < "$live" > "$OUTPUT_DIR/recon/gau.txt" || true
    fi

    if check_tool uro && [[ -s "$OUTPUT_DIR/recon/gau.txt" ]]; then
        uro < "$OUTPUT_DIR/recon/gau.txt" > "$OUTPUT_DIR/recon/urls.txt" || true
    else
        cp -- "$OUTPUT_DIR/recon/gau.txt" "$OUTPUT_DIR/recon/urls.txt" 2>/dev/null || true
    fi

    if check_tool hakrawler; then
        hakrawler -subs < "$live" > "$OUTPUT_DIR/recon/crawl.txt" 2>&1 || true
    fi

    sort -u "$live" "$OUTPUT_DIR/recon/urls.txt" 2>/dev/null | grep -E '^https?://' > "$OUTPUT_DIR/recon/candidates.txt" || true
    log "Recon concluído: $OUTPUT_DIR/recon"
}

xss_module() {
    local targets="$1"
    local input="$OUTPUT_DIR/recon/candidates.txt"
    [[ -s "$input" ]] || input="$targets"

    if check_tool kxss; then
        kxss < "$input" > "$OUTPUT_DIR/xss/kxss.txt" 2>&1 || true
    fi

    if check_tool dalfox; then
        dalfox file "$input" --skip-bav > "$OUTPUT_DIR/xss/dalfox.txt" 2>&1 || true
    fi

    if check_tool xsstrike && [[ -f "$XSSTRIKE" ]]; then
        while IFS= read -r url; do
            [[ -n "$url" ]] || continue
            python3 "$XSSTRIKE" -u "$url" --fuzzer >> "$OUTPUT_DIR/xss/xsstrike.txt" 2>&1 || true
        done < "$input"
    fi

    if check_tool nuclei; then
        nuclei -l "$input" -tags xss -o "$OUTPUT_DIR/xss/nuclei-xss.txt" || true
    fi
}

sqli_module() {
    local targets="$1"
    local input="$OUTPUT_DIR/recon/candidates.txt"
    [[ -s "$input" ]] || input="$targets"

    if check_tool gf && check_tool sqlmap; then
        gf sqli < "$input" | sort -u > "$TMP_DIR/sqli.txt" || true
        if [[ -s "$TMP_DIR/sqli.txt" ]]; then
            sqlmap -m "$TMP_DIR/sqli.txt" --batch --level=1 --output-dir="$OUTPUT_DIR/sqli/sqlmap" > "$OUTPUT_DIR/sqli/sqlmap.log" 2>&1 || true
        fi
    fi

    if check_tool nuclei; then
        nuclei -l "$input" -tags sqli -o "$OUTPUT_DIR/sqli/nuclei-sqli.txt" || true
    fi
}

log4j_module() {
    local targets="$1"
    if ! check_tool log4j-scan; then
        [[ -f "$LOG4J_SCAN" ]] || return 0
    fi

    if [[ -f "$LOG4J_SCAN" ]]; then
        while IFS= read -r url; do
            [[ -n "$url" ]] || continue
            python3 "$LOG4J_SCAN" -u "$url" >> "$OUTPUT_DIR/log4j/results.txt" 2>&1 || true
        done < "$targets"
    else
        while IFS= read -r url; do
            [[ -n "$url" ]] || continue
            log4j-scan -u "$url" >> "$OUTPUT_DIR/log4j/results.txt" 2>&1 || true
        done < "$targets"
    fi
}

nuclei_module() {
    local targets="$1"
    check_tool nuclei || return 0
    if [[ -d "$NUCLEI_TEMPLATES" ]]; then
        nuclei -l "$targets" -t "$NUCLEI_TEMPLATES" -o "$OUTPUT_DIR/nuclei/results.txt" || true
    else
        nuclei -l "$targets" -o "$OUTPUT_DIR/nuclei/results.txt" || true
    fi
}

knoxss_module() {
    local input="$OUTPUT_DIR/recon/candidates.txt"
    [[ -s "$input" ]] || input="$1"
    [[ -n "$KNOXSS_API_KEY" ]] || {
        warn "Knoxss ignorado: KNOXSS_API_KEY não configurada"
        return 0
    }
    check_tool curl || return 0
    : > "$OUTPUT_DIR/xss/knoxss.txt"
    while IFS= read -r url; do
        [[ -n "$url" ]] || continue
        curl --fail --silent --show-error --max-time "$TIMEOUT" \
            -X POST 'https://knoxss.me/api/v3' \
            -H "X-API-KEY: $KNOXSS_API_KEY" \
            --data-urlencode "target=$url" >> "$OUTPUT_DIR/xss/knoxss.txt" 2>&1 || true
    done < "$input"
}

run_mode() {
    local targets="$1"
    case "$MODE" in
        recon) recon_module "$targets" ;;
        xss)
            recon_module "$targets"
            xss_module "$targets"
            knoxss_module "$targets"
            ;;
        sqli)
            recon_module "$targets"
            sqli_module "$targets"
            ;;
        nuclei) nuclei_module "$targets" ;;
        log4j) log4j_module "$targets" ;;
        full)
            recon_module "$targets"
            xss_module "$targets"
            knoxss_module "$targets"
            sqli_module "$targets"
            log4j_module "$targets"
            nuclei_module "$targets"
            ;;
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
    if [[ -n "$INPUT_FILE" ]]; then
        normalize_targets "$INPUT_FILE" "$targets"
    else
        normalize_targets "$TARGET_URL" "$targets"
    fi

    cp -- "$targets" "$OUTPUT_DIR/meta/targets.txt"
    log "Alvos: $(wc -l < "$targets")"
    log "Modo: $MODE"
    run_mode "$targets"

    printf 'finished=%s\n' "$(date -Is)" >> "$OUTPUT_DIR/meta/run.txt"
    log "Concluído. Resultados: $OUTPUT_DIR"
}

main "$@"
