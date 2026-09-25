#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

VERSION="2.1.0"

# Defaults can be overridden by VARS_* environment variables. CLI options win.
OUTPUT_DIR="${VARS_OUTPUT_DIR:-vars_results}"
TARGET_URL=""
INPUT_FILE=""
PROXY="${VARS_PROXY:-}"
MODE="${VARS_MODE:-full}"
JOBS="${VARS_JOBS:-5}"
TIMEOUT="${VARS_TIMEOUT:-15}"
KNOXSS_API_KEY="${KNOXSS_API_KEY:-}"
KEEP_GOING="${VARS_KEEP_GOING:-0}"
OUTPUT_REUSE="${VARS_OUTPUT_REUSE:-0}"

TOOLS_DIR="${VARS_TOOLS_DIR:-${HOME}/.local/share/vars/tools}"
BIN_DIR="${VARS_BIN_DIR:-${HOME}/.local/bin}"
PYTHON_BIN="${VARS_PYTHON:-python3}"
JAELES_SIGNATURES="${VARS_JAELES_SIGNATURES:-${TOOLS_DIR}/jaeles-signatures}"
NUCLEI_TEMPLATES="${VARS_NUCLEI_TEMPLATES:-${TOOLS_DIR}/nuclei-templates}"
PARAMSPIDER="${VARS_PARAMSPIDER:-${TOOLS_DIR}/ParamSpider/paramspider.py}"
XSSTRIKE="${VARS_XSSTRIKE:-${TOOLS_DIR}/XSStrike/xsstrike.py}"
LOG4J_SCAN="${VARS_LOG4J_SCAN:-${TOOLS_DIR}/log4j-scan/log4j-scan.py}"

TMP_DIR=""
LOG_FILE=""
RUN_FILE=""
SUMMARY_FILE=""
TOOL_STATUS_FILE=""
MODULE_STATUS_FILE=""
EXECUTION_STATUS_FILE=""
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
START_EPOCH="$(date +%s)"
CURRENT_MODULE_RAN=0
CURRENT_MODULE_FAILED=0
RUN_FAILED=0

# This is the preservation inventory. Entries are retained even when unavailable.
TOOL_NAMES=(
    httpx gau uro gf dalfox nuclei sqlmap jaeles xray kxss bhedak airixss freq
    hakrawler qsreplace anew paramspider xsstrike log4j-scan urldedupe tool
)

# Keep the original banner, but do not print it for --help/--version.
show_banner() {
    printf '%s\n' \
        '                                                                              ' \
        '                                                                              ' \
        'vvvvvvv           vvvvvvvaaaaaaaaaaaaa  rrrrr   rrrrrrrrr       ssssssssss   ' \
        ' v:::::v         v:::::v a::::::::::::a r::::rrr:::::::::r    ss::::::::::s  ' \
        '  v:::::v       v:::::v  aaaaaaaaa:::::ar:::::::::::::::::r ss:::::::::::::s ' \
        '   v:::::v     v:::::v            a::::arr::::::rrrrr::::::rs::::::ssss:::::s' \
        '    v:::::v   v:::::v      aaaaaaa:::::a r:::::r     r:::::r s:::::s  ssssss ' \
        '     v:::::v v:::::v     aa::::::::::::a r:::::r     rrrrrrr   s::::::s      ' \
        '      v:::::v:::::v     a::::aaaa::::::a r:::::r                  s::::::s   ' \
        '       v:::::::::v     a::::a    a:::::a r:::::r            ssssss   s:::::s ' \
        '        v:::::::v      a::::a    a:::::a r:::::r            s:::::ssss::::::s' \
        '         v:::::v       a:::::aaaa::::::a r:::::r            s::::::::::::::s ' \
        '          v:::v         a::::::::::aa:::ar:::::r             s:::::::::::ss  ' \
        '           vvv           aaaaaaaaaa  aaaarrrrrrr              sssssssssss    ' \
        '                                                                              ' \
        'feito por 0x404xploit' \
        "VARS ${VERSION} - Vulnerability Assessment and Recon Script"
}

log() {
    local level="$1"
    shift
    local message="$*"
    local line
    line="[$(date -Is)] [$level] $message"
    printf '%s\n' "$line" >&2
    if [[ -n "$LOG_FILE" && -d "$(dirname -- "$LOG_FILE")" ]]; then
        printf '%s\n' "$line" >> "$LOG_FILE"
    fi
}

warn() {
    local message="$*"
    log WARN "$message" >&2
}

die() {
    local message="$*"
    log ERROR "$message" >&2
    exit 1
}

on_error() {
    local rc="$?"
    local line="$1"
    log ERROR "Falha inesperada na linha ${line} (código ${rc})" >&2
    exit "$rc"
}

cleanup() {
    if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
        rm -rf -- "$TMP_DIR"
    fi
}

write_summary() {
    [[ -n "$SUMMARY_FILE" ]] || return 0
    {
        printf 'VARS %s\n' "$VERSION"
        printf 'run_id=%s\n' "$RUN_ID"
        printf 'output_dir=%s\n' "$OUTPUT_DIR"
        printf 'mode=%s\n' "$MODE"
        printf 'jobs=%s\n' "$JOBS"
        printf 'timeout=%s\n' "$TIMEOUT"
        printf 'keep_going=%s\n' "$KEEP_GOING"
        printf 'started=%s\n' "$(date -u -d "@$START_EPOCH" -Is)"
        printf 'finished=%s\n' "$(date -Is)"
        printf 'exit_status=%s\n' "${1:-0}"
        if [[ -f "$MODULE_STATUS_FILE" ]]; then
            printf '\n[module_counts]\n'
            awk -F '\t' 'NR > 1 { count[$3]++ } END { for (status in count) printf "%s=%d\n", status, count[status] }' "$MODULE_STATUS_FILE" | sort
        fi
        if [[ -f "$EXECUTION_STATUS_FILE" ]]; then
            printf '\n[execution_counts]\n'
            awk -F '\t' 'NR > 1 { count[$3]++ } END { for (status in count) printf "%s=%d\n", status, count[status] }' "$EXECUTION_STATUS_FILE" | sort
        fi
    } > "$SUMMARY_FILE"
}

on_exit() {
    local rc="$?"
    trap - EXIT
    if [[ -n "${RUN_FILE:-}" && -f "$RUN_FILE" ]]; then
        printf 'finished=%s\nexit_status=%s\n' "$(date -Is)" "$rc" >> "$RUN_FILE"
        write_summary "$rc" || true
        if (( rc == 0 )); then
            log INFO "Execução concluída. Resultados: $OUTPUT_DIR"
        else
            log ERROR "Execução encerrada com código $rc. Resultados parciais: $OUTPUT_DIR"
        fi
    fi
    cleanup
    exit "$rc"
}

on_signal() {
    local signal="$1"
    log WARN "Sinal ${signal} recebido; encerrando com segurança" >&2
    exit 130
}

trap 'on_error "$LINENO"' ERR
trap on_exit EXIT
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM

usage() {
    cat <<EOF
Uso: $0 [opções]

  -u <url>       URL única
  -f <arquivo>   Arquivo com URLs, uma por linha
  -o <dir>       Diretório base de saída (padrão: vars_results)
  -m <modo>      full|recon|xss|sqli|nuclei|log4j
  -j <jobs>      Concorrência das ferramentas compatíveis (padrão: 5)
  -t <seg>       Timeout HTTP das integrações compatíveis (padrão: 15)
  -p <proxy>     Proxy HTTP/HTTPS
  -k <chave>     Chave Knoxss; prefira KNOXSS_API_KEY
  --keep-going   Continua quando um módulo falha
  -h, --help     Ajuda
  -v, --version  Versão

Variáveis de configuração: VARS_OUTPUT_DIR, VARS_MODE, VARS_JOBS,
VARS_TIMEOUT, VARS_PROXY, VARS_KEEP_GOING, VARS_OUTPUT_REUSE, VARS_TOOLS_DIR,
VARS_BIN_DIR, VARS_PYTHON, VARS_JAELES_SIGNATURES, VARS_NUCLEI_TEMPLATES,
VARS_PARAMSPIDER, VARS_XSSTRIKE, VARS_LOG4J_SCAN e KNOXSS_API_KEY.

Use somente em ativos próprios ou explicitamente autorizados.
EOF
}

version() {
    printf 'VARS %s\n' "$VERSION"
}

has_tool() {
    command -v "$1" >/dev/null 2>&1
}

require_cmd() {
    has_tool "$1" || die "Dependência básica ausente: $1"
}

tool_available() {
    local tool="$1"
    case "$tool" in
        tool)
            return 1
            ;;
        paramspider)
            if [[ -f "$PARAMSPIDER" ]]; then
                has_tool "$PYTHON_BIN"
            else
                has_tool paramspider
            fi
            ;;
        xsstrike)
            if [[ -f "$XSSTRIKE" ]]; then
                has_tool "$PYTHON_BIN"
            else
                has_tool xsstrike
            fi
            ;;
        log4j-scan)
            if [[ -f "$LOG4J_SCAN" ]]; then
                has_tool "$PYTHON_BIN"
            else
                has_tool log4j-scan
            fi
            ;;
        *)
            has_tool "$tool"
            ;;
    esac
}

tool_location() {
    local tool="$1"
    case "$tool" in
        paramspider)
            if [[ -f "$PARAMSPIDER" ]]; then printf '%s' "$PARAMSPIDER"; else command -v paramspider; fi
            ;;
        xsstrike)
            if [[ -f "$XSSTRIKE" ]]; then printf '%s' "$XSSTRIKE"; else command -v xsstrike; fi
            ;;
        log4j-scan)
            if [[ -f "$LOG4J_SCAN" ]]; then printf '%s' "$LOG4J_SCAN"; else command -v log4j-scan; fi
            ;;
        *) command -v "$tool" ;;
    esac
}

record_tool() {
    local tool="$1" availability="$2" location="$3" detail="$4"
    printf '%s\t%s\t%s\t%s\n' "$tool" "$availability" "$location" "$detail" >> "$TOOL_STATUS_FILE"
}

record_execution() {
    local kind="$1" name="$2" status="$3" rc="$4" duration="$5" detail="$6"
    detail="${detail//$'\t'/ }"
    detail="${detail//$'\n'/ }"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$kind" "$name" "$status" "$rc" "$duration" "$detail" >> "$EXECUTION_STATUS_FILE"
}

record_module() {
    local name="$1" status="$2" rc="$3" duration="$4" detail="$5"
    detail="${detail//$'\t'/ }"
    detail="${detail//$'\n'/ }"
    printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$(date -Is)" "$status" "$rc" "$duration" >> "$MODULE_STATUS_FILE"
    log INFO "Módulo ${name}: ${status} (rc=${rc}, duração=${duration}s${detail:+, ${detail}})"
}

check_runtime() {
    local dep
    for dep in awk grep sed sort mktemp xargs curl git date mkdir cp rm wc find; do
        require_cmd "$dep"
    done
    [[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "-j deve ser um inteiro positivo"
    [[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "-t deve ser um inteiro positivo"
    [[ "$KEEP_GOING" =~ ^[01]$ ]] || die "VARS_KEEP_GOING deve ser 0 ou 1"
    [[ "$OUTPUT_REUSE" =~ ^[01]$ ]] || die "VARS_OUTPUT_REUSE deve ser 0 ou 1"
    [[ -n "$OUTPUT_DIR" && "$OUTPUT_DIR" != "/" ]] || die "Diretório de saída inválido"
    [[ -z "$PROXY" || "$PROXY" =~ ^https?://[^[:space:]]+$ ]] || die "Proxy deve usar http:// ou https:// sem espaços"
    [[ -z "$TARGET_URL" || -z "$INPUT_FILE" ]] || die "Use -u ou -f, não ambos"
    [[ -n "$TARGET_URL" || -n "$INPUT_FILE" ]] || die "Forneça -u ou -f"
    [[ -z "$INPUT_FILE" || -f "$INPUT_FILE" ]] || die "Arquivo não encontrado: $INPUT_FILE"
    [[ -z "$INPUT_FILE" || -r "$INPUT_FILE" ]] || die "Arquivo sem permissão de leitura: $INPUT_FILE"
    case "$MODE" in
        full|recon|xss|sqli|nuclei|log4j) ;;
        *) die "Modo inválido: $MODE" ;;
    esac
}

configure_proxy() {
    [[ -z "$PROXY" ]] && return 0
    [[ "$PROXY" =~ ^https?://[^[:space:]]+$ ]] || die "Proxy deve usar http:// ou https:// sem espaços"
    export HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY" http_proxy="$PROXY" https_proxy="$PROXY"
    log INFO "Proxy HTTP/HTTPS configurado (valor omitido dos logs)"
}

setup_output() {
    if [[ -e "$OUTPUT_DIR" && ! -d "$OUTPUT_DIR" ]]; then
        die "O caminho de saída existe e não é um diretório: $OUTPUT_DIR"
    fi
    [[ ! -L "$OUTPUT_DIR" ]] || die "O diretório de saída não pode ser um link simbólico: $OUTPUT_DIR"
    if [[ -d "$OUTPUT_DIR" && "$OUTPUT_REUSE" != 1 && -n "$(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
        OUTPUT_DIR="${OUTPUT_DIR%/}/run-${RUN_ID}"
        log WARN "O diretório de saída não estava vazio; usando execução isolada: $OUTPUT_DIR"
    fi
    mkdir -p -- "$OUTPUT_DIR"/{recon,xss,sqli,log4j,nuclei,misc,meta}
    chmod 700 -- "$OUTPUT_DIR/meta" 2>/dev/null || true
    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vars.XXXXXX")"
    chmod 700 -- "$TMP_DIR"
    LOG_FILE="$OUTPUT_DIR/meta/vars.log"
    RUN_FILE="$OUTPUT_DIR/meta/run.txt"
    SUMMARY_FILE="$OUTPUT_DIR/meta/summary.txt"
    TOOL_STATUS_FILE="$OUTPUT_DIR/meta/tool-status.tsv"
    MODULE_STATUS_FILE="$OUTPUT_DIR/meta/module-status.tsv"
    EXECUTION_STATUS_FILE="$OUTPUT_DIR/meta/execution-status.tsv"
    : > "$LOG_FILE"
    printf 'VARS %s\nrun_id=%s\nstarted=%s\nmode=%s\njobs=%s\ntimeout=%s\nkeep_going=%s\nproxy_configured=%s\noutput_dir=%s\n' \
        "$VERSION" "$RUN_ID" "$(date -Is)" "$MODE" "$JOBS" "$TIMEOUT" "$KEEP_GOING" "$([[ -n "$PROXY" ]] && printf true || printf false)" "$OUTPUT_DIR" > "$RUN_FILE"
    printf 'tool\tavailability\tlocation\tdetail\n' > "$TOOL_STATUS_FILE"
    printf 'module\tfinished_at\tstatus\trc\tduration_seconds\n' > "$MODULE_STATUS_FILE"
    printf 'kind\tname\tstatus\trc\tduration_seconds\tdetail\n' > "$EXECUTION_STATUS_FILE"
}

check_optional_tools() {
    local tool location
    log INFO "Inventário de ferramentas (ausentes não interrompem a execução):"
    for tool in "${TOOL_NAMES[@]}"; do
        if tool_available "$tool"; then
            location="$(tool_location "$tool")"
            record_tool "$tool" available "$location" "detectada"
            log INFO "  [+] ${tool} (${location})"
        else
            record_tool "$tool" missing "-" "não encontrada ou dependência de script ausente"
            log WARN "  [-] ${tool} (indisponível)"
        fi
    done
}

normalize_one() {
    local line="$1"
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "$line" == \#* ]] && return 2
    [[ "$line" =~ ^https?://[^[:space:]]+$ ]] || return 1
    printf '%s\n' "$line"
}

normalize_targets() {
    local input="$1" output="$2" raw invalid=0 accepted=0 normalized rc
    raw="$TMP_DIR/targets.raw"
    if [[ -f "$input" ]]; then
        cp -- "$input" "$raw"
    else
        printf '%s\n' "$input" > "$raw"
    fi
    : > "$output"
    while IFS= read -r line || [[ -n "$line" ]]; do
        if normalized="$(normalize_one "$line")"; then
            printf '%s\n' "$normalized" >> "$output"
            accepted=$((accepted + 1))
        else
            rc=$?
            [[ "$rc" == 2 ]] && continue
            invalid=$((invalid + 1))
        fi
    done < "$raw"
    sort -u "$output" -o "$output"
    (( invalid > 0 )) && warn "${invalid} entrada(s) ignorada(s) por não serem URLs HTTP(S) válidas"
    (( accepted > 0 )) || die "Nenhuma URL HTTP(S) válida encontrada"
    [[ -s "$output" ]] || die "Nenhuma URL HTTP(S) válida encontrada"
}

module_start() {
    CURRENT_MODULE_RAN=0
    CURRENT_MODULE_FAILED=0
}

module_finish() {
    if (( CURRENT_MODULE_RAN == 0 )); then
        return 2
    fi
    (( CURRENT_MODULE_FAILED == 0 )) && return 0
    return 1
}

step() {
    local tool="$1" label="$2"
    shift 2
    local start rc duration
    if ! tool_available "$tool"; then
        record_execution tool "$label" skipped 0 0 "${tool} ausente"
        log WARN "${label} ignorado: ${tool} indisponível"
        return 0
    fi
    CURRENT_MODULE_RAN=1
    start="$(date +%s)"
    log INFO "Executando ${label}"
    if "$@"; then
        rc=0
    else
        rc=$?
    fi
    duration=$(( $(date +%s) - start ))
    if (( rc == 0 )); then
        record_execution tool "$label" executed "$rc" "$duration" "concluído"
        log INFO "${label} concluído em ${duration}s"
    else
        CURRENT_MODULE_FAILED=1
        record_execution tool "$label" failed "$rc" "$duration" "comando retornou erro"
        warn "${label} falhou com código ${rc}"
    fi
    return 0
}

pipeline_step() {
    local label="$1" output="$2" runner="$3" input="$4"
    shift 4
    local dep start rc duration missing=0
    for dep in "$@"; do
        if ! tool_available "$dep"; then
            missing=1
            record_execution integration "$label" skipped 0 0 "dependência ausente: ${dep}"
            log WARN "${label} ignorado: ${dep} indisponível"
        fi
    done
    (( missing == 1 )) && return 0
    CURRENT_MODULE_RAN=1
    start="$(date +%s)"
    log INFO "Executando ${label}"
    if "$runner" "$input" > "$output" 2>&1; then
        rc=0
    else
        rc=$?
    fi
    duration=$(( $(date +%s) - start ))
    if (( rc == 0 )); then
        record_execution integration "$label" executed "$rc" "$duration" "saída: ${output}"
    else
        CURRENT_MODULE_FAILED=1
        record_execution integration "$label" failed "$rc" "$duration" "saída: ${output}"
        warn "${label} falhou com código ${rc}"
    fi
}

run_xsstrike_target() {
    local url="$1"
    if [[ -f "$XSSTRIKE" ]]; then
        "$PYTHON_BIN" "$XSSTRIKE" -u "$url" --fuzzer
    else
        xsstrike -u "$url" --fuzzer
    fi
}

run_log4j_target() {
    local url="$1"
    if [[ -f "$LOG4J_SCAN" ]]; then
        "$PYTHON_BIN" "$LOG4J_SCAN" -u "$url"
    else
        log4j-scan -u "$url"
    fi
}

run_paramspider() {
    local targets="$1" host
    while IFS= read -r host; do
        [[ -n "$host" ]] || continue
        if [[ -f "$PARAMSPIDER" ]]; then
            "$PYTHON_BIN" "$PARAMSPIDER" -d "$host" --quiet
        else
            paramspider -d "$host" --quiet
        fi
    done < <(awk -F/ '{print $3}' "$targets" | sed 's/:.*//' | sort -u)
}

run_xsstrike_all() {
    local input="$1" url
    : > "$OUTPUT_DIR/xss/xsstrike.txt"
    while IFS= read -r url; do
        [[ -n "$url" ]] || continue
        run_xsstrike_target "$url" >> "$OUTPUT_DIR/xss/xsstrike.txt" 2>&1 || return $?
    done < "$input"
}

run_log4j_all() {
    local input="$1" url
    : > "$OUTPUT_DIR/log4j/results.txt"
    while IFS= read -r url; do
        [[ -n "$url" ]] || continue
        run_log4j_target "$url" >> "$OUTPUT_DIR/log4j/results.txt" 2>&1 || return $?
    done < "$input"
}

run_bhedak() {
    bhedak "\"><svg/onload=alert(1)>*'/---+{{7*7}}" < "$1"
}

run_bhedak_urldedupe() {
    urldedupe -qs < "$1" | bhedak '\"><svg onload=confirm(1)>' | airixss -payload 'confirm(1)' | { grep -E -v 'Not' || true; }
}

run_hakrawler_airixss() {
    httpx -silent -threads "$JOBS" -timeout "$TIMEOUT" < "$1" | hakrawler -subs | { grep '=' || true; } | qsreplace '\"><svg onload=confirm(1)>' | airixss -payload 'confirm(1)' | { grep -E -v 'Not' || true; }
}

run_airixss() {
    { gf xss < "$1" || true; } | uro | httpx -silent -threads "$JOBS" -timeout "$TIMEOUT" | qsreplace '\"><svg onload=confirm(1)>' | airixss -payload 'confirm(1)'
}

run_freq() {
    { gf xss < "$1" || true; } | uro | qsreplace '\"><img src=x onerror=alert(1);>' | freq | { grep -E -v 'Not' || true; }
}

run_xray() {
    local input="$1" url
    : > "$OUTPUT_DIR/misc/xray.txt"
    while IFS= read -r url; do
        [[ -n "$url" ]] || continue
        xray webscan --plugins cmd-injection,sqldet,xss --url "$url" --html-output "$OUTPUT_DIR/misc/xray.html" >> "$OUTPUT_DIR/misc/xray.txt" 2>&1 || return $?
    done < "$input"
}

run_jaeles() {
    local input="$1" url
    : > "$OUTPUT_DIR/misc/jaeles.txt"
    while IFS= read -r url; do
        [[ -n "$url" ]] || continue
        jaeles scan -s "$JAELES_SIGNATURES" -u "$url" >> "$OUTPUT_DIR/misc/jaeles.txt" 2>&1 || return $?
    done < "$input"
}

run_sqli_mass() {
    local input="$1" candidates="$TMP_DIR/sqli-candidates.txt"
    : > "$candidates"
    if tool_available httpx; then
        httpx -silent -l "$input" -threads "$JOBS" -timeout "$TIMEOUT" > "$TMP_DIR/sqli-live.txt" || return $?
    else
        cp -- "$input" "$TMP_DIR/sqli-live.txt"
    fi
    if tool_available anew; then
        { gf sqli < "$TMP_DIR/sqli-live.txt" || true; } | anew > "$candidates" || return $?
    else
        { gf sqli < "$TMP_DIR/sqli-live.txt" || true; } | sort -u > "$candidates" || return $?
    fi
    [[ -s "$candidates" ]] || return 0
    sqlmap -m "$candidates" --batch --random-agent --level 1 --timeout "$TIMEOUT" --output-dir="$OUTPUT_DIR/sqli/sqlmap"
}

run_sqli_qsreplace() {
    local input="$1" responses="$OUTPUT_DIR/sqli/output" probe="$TMP_DIR/sqli-probe.txt"
    mkdir -p -- "$responses"
    : > "$probe"
    { grep '=' < "$input" || true; } | qsreplace "' OR '1" | httpx -silent -threads "$JOBS" -timeout "$TIMEOUT" -store-response-dir "$responses" > "$probe"
    if grep -R -E -q 'syntax|mysql' "$responses" 2>/dev/null; then
        printf 'TARGET potencialmente explorável\n'
    else
        printf 'TARGET sem evidência nos padrões verificados\n'
    fi
}

recon_module() {
    local targets="$1" live="$OUTPUT_DIR/recon/live.txt" gau_file="$OUTPUT_DIR/recon/gau.txt"
    local urls_file="$OUTPUT_DIR/recon/urls.txt" crawl_file="$OUTPUT_DIR/recon/crawl.txt"
    local candidates="$OUTPUT_DIR/recon/candidates.txt"
    module_start
    : > "$live"; : > "$gau_file"; : > "$urls_file"; : > "$crawl_file"; : > "$candidates"
    if tool_available httpx; then
        step httpx 'httpx (alvos ativos)' httpx -silent -l "$targets" -threads "$JOBS" -timeout "$TIMEOUT" > "$live"
    else
        cp -- "$targets" "$live"
        CURRENT_MODULE_RAN=1
        record_execution fallback 'httpx (alvos ativos)' fallback 0 0 'httpx ausente; alvos originais preservados'
        log WARN 'httpx indisponível; usando os alvos originais como fallback'
    fi
    if tool_available gau; then
        step gau 'gau (URLs históricas)' gau --threads "$JOBS" --timeout "$TIMEOUT" < "$live" > "$gau_file"
    else
        record_execution tool 'gau (URLs históricas)' skipped 0 0 'gau ausente'
    fi
    if tool_available uro && [[ -s "$gau_file" ]]; then
        step uro 'uro (normalização de URLs)' uro < "$gau_file" > "$urls_file"
    elif [[ -s "$gau_file" ]]; then
        cp -- "$gau_file" "$urls_file"
        record_execution fallback 'uro (normalização de URLs)' fallback 0 0 'uro ausente; URLs históricas preservadas'
    else
        record_execution tool 'uro (normalização de URLs)' skipped 0 0 'sem entrada ou uro ausente'
    fi
    if tool_available hakrawler; then
        step hakrawler 'hakrawler (crawling)' hakrawler -subs < "$live" > "$crawl_file"
    else
        record_execution tool 'hakrawler (crawling)' skipped 0 0 'hakrawler ausente'
    fi
    awk '/^https?:\/\// {print}' "$live" "$urls_file" "$crawl_file" 2>/dev/null | sort -u > "$candidates"
    if [[ -s "$candidates" ]]; then
        record_execution derived 'recon/candidates.txt' generated 0 0 'URLs HTTP(S) deduplicadas'
        CURRENT_MODULE_RAN=1
    fi
    if tool_available paramspider; then
        step paramspider 'ParamSpider (parâmetros)' run_paramspider "$targets" > "$OUTPUT_DIR/misc/paramspider.txt"
    else
        record_execution tool 'ParamSpider (parâmetros)' skipped 0 0 'paramspider ausente'
    fi
    module_finish
}

xss_module() {
    local targets="$1" input="$OUTPUT_DIR/recon/candidates.txt"
    [[ -s "$input" ]] || input="$targets"
    module_start
    : > "$OUTPUT_DIR/xss/kxss.txt"; : > "$OUTPUT_DIR/xss/dalfox.txt"; : > "$OUTPUT_DIR/xss/nuclei-xss.txt"
    step kxss 'kxss (XSS refletido)' kxss < "$input" > "$OUTPUT_DIR/xss/kxss.txt"
    step dalfox 'Dalfox (XSS)' dalfox file "$input" --skip-bav --worker "$JOBS" --timeout "$TIMEOUT" > "$OUTPUT_DIR/xss/dalfox.txt"
    step xsstrike 'XSStrike (XSS/fuzzer)' run_xsstrike_all "$input"
    step nuclei 'Nuclei (templates XSS)' nuclei -l "$input" -tags xss -c "$JOBS" -timeout "$TIMEOUT" -o "$OUTPUT_DIR/xss/nuclei-xss.txt"
    pipeline_step 'Bhedak (XSS/SSTI)' "$OUTPUT_DIR/xss/bhedak.txt" run_bhedak "$input" bhedak
    pipeline_step 'Bhedak + urldedupe + Airixss' "$OUTPUT_DIR/xss/bhedak-urldedupe.txt" run_bhedak_urldedupe "$input" bhedak urldedupe airixss
    pipeline_step 'Hakrawler + qsreplace + Airixss' "$OUTPUT_DIR/xss/hakrawler-airixss.txt" run_hakrawler_airixss "$input" httpx hakrawler qsreplace airixss
    pipeline_step 'GF + URO + qsreplace + Airixss' "$OUTPUT_DIR/xss/airixss.txt" run_airixss "$input" gf uro httpx qsreplace airixss
    pipeline_step 'GF + URO + qsreplace + Freq' "$OUTPUT_DIR/xss/freq.txt" run_freq "$input" gf uro qsreplace freq
    if [[ -n "$KNOXSS_API_KEY" ]]; then
        : > "$OUTPUT_DIR/xss/knoxss.txt"
        local url start rc duration knoxss_header="$TMP_DIR/knoxss.header"
        if ! tool_available curl; then
            record_execution integration 'Knoxss API' skipped 0 0 'curl ausente'
        else
            printf 'X-API-KEY: %s\n' "$KNOXSS_API_KEY" > "$knoxss_header"
            chmod 600 -- "$knoxss_header"
            CURRENT_MODULE_RAN=1
            start="$(date +%s)"
            while IFS= read -r url; do
                [[ -n "$url" ]] || continue
                curl --fail --silent --show-error --max-time "$TIMEOUT" -X POST 'https://knoxss.me/api/v3' \
                    -H "@$knoxss_header" --data-urlencode "target=$url" >> "$OUTPUT_DIR/xss/knoxss.txt" 2>&1 || { CURRENT_MODULE_FAILED=1; }
            done < "$input"
            rc="$CURRENT_MODULE_FAILED"
            duration=$(( $(date +%s) - start ))
            if (( rc == 0 )); then
                record_execution integration 'Knoxss API' executed 0 "$duration" 'resposta salva sem registrar a chave'
            else
                record_execution integration 'Knoxss API' failed 1 "$duration" 'uma ou mais requisições falharam'
            fi
        fi
    else
        record_execution integration 'Knoxss API' skipped 0 0 'KNOXSS_API_KEY não configurada'
        log WARN 'Knoxss ignorado: KNOXSS_API_KEY não configurada'
    fi
    module_finish
}

sqli_module() {
    local targets="$1" input="$OUTPUT_DIR/recon/candidates.txt"
    [[ -s "$input" ]] || input="$targets"
    module_start
    mkdir -p -- "$OUTPUT_DIR/sqli/sqlmap"
    : > "$OUTPUT_DIR/sqli/sqlmap.log"; : > "$OUTPUT_DIR/sqli/qsreplace.txt"; : > "$OUTPUT_DIR/sqli/nuclei-sqli.txt"
    pipeline_step 'GF + httpx + SQLmap' "$OUTPUT_DIR/sqli/sqlmap.log" run_sqli_mass "$input" httpx gf sqlmap
    pipeline_step 'qsreplace + httpx (SQLi heurístico)' "$OUTPUT_DIR/sqli/qsreplace.txt" run_sqli_qsreplace "$input" httpx qsreplace
    step nuclei 'Nuclei (templates SQLi)' nuclei -l "$input" -tags sqli -c "$JOBS" -timeout "$TIMEOUT" -o "$OUTPUT_DIR/sqli/nuclei-sqli.txt"
    module_finish
}

log4j_module() {
    local targets="$1"
    module_start
    step log4j-scan 'Log4j scan' run_log4j_all "$targets"
    module_finish
}

nuclei_module() {
    local targets="$1"
    module_start
    if [[ -d "$NUCLEI_TEMPLATES" ]]; then
        step nuclei 'Nuclei (templates configurados)' nuclei -l "$targets" -t "$NUCLEI_TEMPLATES" -c "$JOBS" -timeout "$TIMEOUT" -o "$OUTPUT_DIR/nuclei/results.txt"
    else
        step nuclei 'Nuclei (templates padrão)' nuclei -l "$targets" -c "$JOBS" -timeout "$TIMEOUT" -o "$OUTPUT_DIR/nuclei/results.txt"
    fi
    module_finish
}

extended_module() {
    local targets="$1"
    module_start
    if [[ -d "$JAELES_SIGNATURES" ]]; then
        pipeline_step 'Jaeles (assinaturas)' "$OUTPUT_DIR/misc/jaeles.txt" run_jaeles "$targets" jaeles
    else
        record_execution integration 'Jaeles (assinaturas)' skipped 0 0 "assinaturas ausentes: ${JAELES_SIGNATURES}"
    fi
    pipeline_step 'Xray (webscan)' "$OUTPUT_DIR/misc/xray.txt" run_xray "$targets" xray
    module_finish
}

run_module() {
    local name="$1" function_name="$2" targets="$3" start rc duration status detail
    start="$(date +%s)"
    log INFO "Iniciando módulo ${name}"
    if "$function_name" "$targets"; then
        rc=0
    else
        rc=$?
    fi
    duration=$(( $(date +%s) - start ))
    case "$rc" in
        0) status=ok; detail="concluído" ;;
        2) status=skipped; detail="nenhuma ferramenta disponível" ;;
        *) status=failed; detail="uma ou mais etapas falharam" ;;
    esac
    record_module "$name" "$status" "$rc" "$duration" "$detail"
    if (( rc != 0 && rc != 2 )); then
        RUN_FAILED=1
    fi
    if (( rc != 0 && rc != 2 && KEEP_GOING != 1 )); then
        die "Módulo ${name} falhou; use --keep-going para continuar"
    fi
    return 0
}

run_mode() {
    local targets="$1"
    case "$MODE" in
        recon)
            run_module recon recon_module "$targets"
            ;;
        xss)
            run_module recon recon_module "$targets"
            run_module xss xss_module "$targets"
            ;;
        sqli)
            run_module recon recon_module "$targets"
            run_module sqli sqli_module "$targets"
            ;;
        nuclei)
            run_module nuclei nuclei_module "$targets"
            ;;
        log4j)
            run_module log4j log4j_module "$targets"
            ;;
        full)
            run_module recon recon_module "$targets"
            run_module xss xss_module "$targets"
            run_module sqli sqli_module "$targets"
            run_module log4j log4j_module "$targets"
            run_module nuclei nuclei_module "$targets"
            run_module extended extended_module "$targets"
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
    show_banner
    if [[ -d "$BIN_DIR" ]]; then
        PATH="$BIN_DIR:$PATH"
        export PATH
    fi
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
    log INFO "Alvos válidos: $(wc -l < "$targets")"
    log INFO "Modo: ${MODE}; concorrência: ${JOBS}; timeout: ${TIMEOUT}s"
    run_mode "$targets"
    if (( RUN_FAILED != 0 )); then
        die "Uma ou mais etapas falharam; consulte ${SUMMARY_FILE}"
    fi
}

main "$@"
