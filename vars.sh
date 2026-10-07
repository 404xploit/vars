#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

VERSION="2.3.0"

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
SCOPE_FILE="${VARS_SCOPE_FILE:-}"
INCLUDE_SUBDOMAINS="${VARS_INCLUDE_SUBDOMAINS:-0}"
ALLOW_OUT_OF_SCOPE="${VARS_ALLOW_OUT_OF_SCOPE:-0}"

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
SCOPE_HOSTS_FILE=""
OUT_OF_SCOPE_FILE=""
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

declare -A SCOPE_HOSTS=()
declare -A RECORDED_SCOPE_URLS=()

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
        printf 'scope_source=%s\n' "$([[ -n "$SCOPE_FILE" ]] && printf '%s' "$SCOPE_FILE" || printf 'targets')"
        printf 'include_subdomains=%s\n' "$INCLUDE_SUBDOMAINS"
        printf 'allow_out_of_scope=%s\n' "$ALLOW_OUT_OF_SCOPE"
        if [[ -f "$SCOPE_HOSTS_FILE" ]]; then
            printf 'scope_hosts=%s\n' "$(wc -l < "$SCOPE_HOSTS_FILE")"
        fi
        printf 'started=%s\n' "$(date -u -d "@$START_EPOCH" -Is)"
        printf 'finished=%s\n' "$(date -Is)"
        printf 'exit_status=%s\n' "${1:-0}"
        if [[ -f "$OUT_OF_SCOPE_FILE" ]]; then
            printf '\n[scope_counts]\n'
            awk -F '\t' 'NR > 1 { count[$3]++ } END { for (action in count) printf "%s=%d\n", action, count[action] }' "$OUT_OF_SCOPE_FILE" | sort
        fi
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
  --scope-file <arquivo>
                  Define os hosts autorizados, um host ou URL por linha
  --include-subdomains
                  Autoriza subdomínios dos hosts do escopo
  --allow-out-of-scope
                  Mantém URLs descobertas fora do escopo, registrando a exceção
  --keep-going   Continua quando um módulo falha
  -h, --help     Ajuda
  -v, --version  Versão

Variáveis de configuração: VARS_OUTPUT_DIR, VARS_MODE, VARS_JOBS,
VARS_TIMEOUT, VARS_PROXY, VARS_KEEP_GOING, VARS_OUTPUT_REUSE, VARS_SCOPE_FILE,
VARS_INCLUDE_SUBDOMAINS, VARS_ALLOW_OUT_OF_SCOPE, VARS_TOOLS_DIR, VARS_BIN_DIR,
VARS_PYTHON, VARS_JAELES_SIGNATURES, VARS_NUCLEI_TEMPLATES, VARS_PARAMSPIDER,
VARS_XSSTRIKE, VARS_LOG4J_SCAN e KNOXSS_API_KEY.

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

contains_control_chars() {
    [[ "$1" =~ [[:cntrl:]] ]]
}

validate_no_control_chars() {
    local name="$1" value="$2"
    if contains_control_chars "$value"; then
        die "${name} não pode conter caracteres de controle"
    fi
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
    for dep in awk grep sed sort mktemp xargs curl git date mkdir cp rm wc find realpath; do
        require_cmd "$dep"
    done
    [[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "-j deve ser um inteiro positivo"
    [[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "-t deve ser um inteiro positivo"
    [[ "$KEEP_GOING" =~ ^[01]$ ]] || die "VARS_KEEP_GOING deve ser 0 ou 1"
    [[ "$OUTPUT_REUSE" =~ ^[01]$ ]] || die "VARS_OUTPUT_REUSE deve ser 0 ou 1"
    [[ "$INCLUDE_SUBDOMAINS" =~ ^[01]$ ]] || die "VARS_INCLUDE_SUBDOMAINS deve ser 0 ou 1"
    [[ "$ALLOW_OUT_OF_SCOPE" =~ ^[01]$ ]] || die "VARS_ALLOW_OUT_OF_SCOPE deve ser 0 ou 1"
    [[ -n "$OUTPUT_DIR" && "$OUTPUT_DIR" != "/" ]] || die "Diretório de saída inválido"
    [[ -z "$PROXY" || "$PROXY" =~ ^https?://[^[:space:]]+$ ]] || die "Proxy deve usar http:// ou https:// sem espaços"
    validate_no_control_chars "Diretório de saída" "$OUTPUT_DIR"
    validate_no_control_chars "Diretório de ferramentas" "$TOOLS_DIR"
    validate_no_control_chars "Diretório de binários" "$BIN_DIR"
    validate_no_control_chars "Interpretador Python" "$PYTHON_BIN"
    validate_no_control_chars "Assinaturas Jaeles" "$JAELES_SIGNATURES"
    validate_no_control_chars "Templates Nuclei" "$NUCLEI_TEMPLATES"
    validate_no_control_chars "Caminho ParamSpider" "$PARAMSPIDER"
    validate_no_control_chars "Caminho XSStrike" "$XSSTRIKE"
    validate_no_control_chars "Caminho log4j-scan" "$LOG4J_SCAN"
    validate_no_control_chars "Chave Knoxss" "$KNOXSS_API_KEY"
    validate_no_control_chars "URL alvo" "$TARGET_URL"
    validate_no_control_chars "Arquivo de entrada" "$INPUT_FILE"
    validate_no_control_chars "Arquivo de escopo" "$SCOPE_FILE"
    [[ -z "$TARGET_URL" || -z "$INPUT_FILE" ]] || die "Use -u ou -f, não ambos"
    [[ -n "$TARGET_URL" || -n "$INPUT_FILE" ]] || die "Forneça -u ou -f"
    [[ -z "$INPUT_FILE" || -f "$INPUT_FILE" ]] || die "Arquivo não encontrado: $INPUT_FILE"
    [[ -z "$INPUT_FILE" || -r "$INPUT_FILE" ]] || die "Arquivo sem permissão de leitura: $INPUT_FILE"
    [[ -z "$SCOPE_FILE" || -f "$SCOPE_FILE" ]] || die "Arquivo de escopo não encontrado: $SCOPE_FILE"
    [[ -z "$SCOPE_FILE" || -r "$SCOPE_FILE" ]] || die "Arquivo de escopo sem permissão de leitura: $SCOPE_FILE"
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

setup_temp() {
    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vars.XXXXXX")"
    chmod 700 -- "$TMP_DIR"
}

# Reject symlinks in every existing component of the output path. Checking only
# OUTPUT_DIR itself is insufficient when one of its parents redirects writes.
reject_symlink_ancestors() {
    local path="$1" existing canonical
    [[ "$path" == /* ]] || path="$PWD/$path"
    existing="$path"
    while [[ ! -e "$existing" && ! -L "$existing" && "$existing" != "/" ]]; do
        existing="${existing%/*}"
        [[ -n "$existing" ]] || existing="/"
    done
    [[ ! -L "$existing" ]] || die "Componente do caminho de saída não pode ser link simbólico: $existing"
    canonical="$(realpath -- "$existing")" || die "Não foi possível resolver o caminho de saída: $existing"
    [[ "$canonical" == "$existing" ]] || die "Componente do caminho de saída resolve para outro destino: $existing -> $canonical"
}

setup_output() {
    local path
    reject_symlink_ancestors "$OUTPUT_DIR"
    if [[ -e "$OUTPUT_DIR" && ! -d "$OUTPUT_DIR" ]]; then
        die "O caminho de saída existe e não é um diretório: $OUTPUT_DIR"
    fi
    [[ ! -L "$OUTPUT_DIR" ]] || die "O diretório de saída não pode ser um link simbólico: $OUTPUT_DIR"
    for path in recon xss sqli log4j nuclei misc meta; do
        [[ ! -L "$OUTPUT_DIR/$path" ]] || die "Caminho de saída não pode ser link simbólico: $OUTPUT_DIR/$path"
        if [[ -e "$OUTPUT_DIR/$path" && ! -d "$OUTPUT_DIR/$path" ]]; then
            die "Caminho de saída deve ser um diretório: $OUTPUT_DIR/$path"
        fi
    done
    for path in vars.log run.txt summary.txt tool-status.tsv module-status.tsv execution-status.tsv scope.txt out-of-scope.tsv; do
        [[ ! -L "$OUTPUT_DIR/meta/$path" ]] || die "Caminho de saída não pode ser link simbólico: $OUTPUT_DIR/meta/$path"
        if [[ -e "$OUTPUT_DIR/meta/$path" && ! -f "$OUTPUT_DIR/meta/$path" ]]; then
            die "Metadado de saída deve ser um arquivo regular: $OUTPUT_DIR/meta/$path"
        fi
    done
    if [[ -d "$OUTPUT_DIR" && "$OUTPUT_REUSE" != 1 && -n "$(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
        OUTPUT_DIR="${OUTPUT_DIR%/}/run-${RUN_ID}"
        log WARN "O diretório de saída não estava vazio; usando execução isolada: $OUTPUT_DIR"
    fi
    reject_symlink_ancestors "$OUTPUT_DIR"
    [[ ! -L "$OUTPUT_DIR" ]] || die "O diretório de saída não pode ser um link simbólico: $OUTPUT_DIR"
    mkdir -p -- "$OUTPUT_DIR"/{recon,xss,sqli,log4j,nuclei,misc,meta}
    for path in recon xss sqli log4j nuclei misc meta; do
        [[ ! -L "$OUTPUT_DIR/$path" ]] || die "Caminho de saída não pode ser link simbólico: $OUTPUT_DIR/$path"
        [[ -d "$OUTPUT_DIR/$path" ]] || die "Caminho de saída deve ser um diretório: $OUTPUT_DIR/$path"
    done
    for path in vars.log run.txt summary.txt tool-status.tsv module-status.tsv execution-status.tsv scope.txt out-of-scope.tsv; do
        [[ ! -L "$OUTPUT_DIR/meta/$path" ]] || die "Caminho de saída não pode ser link simbólico: $OUTPUT_DIR/meta/$path"
        if [[ -e "$OUTPUT_DIR/meta/$path" && ! -f "$OUTPUT_DIR/meta/$path" ]]; then
            die "Metadado de saída deve ser um arquivo regular: $OUTPUT_DIR/meta/$path"
        fi
    done
    chmod 700 -- "$OUTPUT_DIR/meta"
    LOG_FILE="$OUTPUT_DIR/meta/vars.log"
    RUN_FILE="$OUTPUT_DIR/meta/run.txt"
    SUMMARY_FILE="$OUTPUT_DIR/meta/summary.txt"
    TOOL_STATUS_FILE="$OUTPUT_DIR/meta/tool-status.tsv"
    MODULE_STATUS_FILE="$OUTPUT_DIR/meta/module-status.tsv"
    EXECUTION_STATUS_FILE="$OUTPUT_DIR/meta/execution-status.tsv"
    SCOPE_HOSTS_FILE="$OUTPUT_DIR/meta/scope.txt"
    OUT_OF_SCOPE_FILE="$OUTPUT_DIR/meta/out-of-scope.tsv"
    : > "$LOG_FILE"
    printf 'VARS %s\nrun_id=%s\nstarted=%s\nmode=%s\njobs=%s\ntimeout=%s\nkeep_going=%s\nproxy_configured=%s\noutput_dir=%s\n' \
        "$VERSION" "$RUN_ID" "$(date -Is)" "$MODE" "$JOBS" "$TIMEOUT" "$KEEP_GOING" "$([[ -n "$PROXY" ]] && printf true || printf false)" "$OUTPUT_DIR" > "$RUN_FILE"
    printf 'tool\tavailability\tlocation\tdetail\n' > "$TOOL_STATUS_FILE"
    printf 'module\tfinished_at\tstatus\trc\tduration_seconds\n' > "$MODULE_STATUS_FILE"
    printf 'kind\tname\tstatus\trc\tduration_seconds\tdetail\n' > "$EXECUTION_STATUS_FILE"
    : > "$SCOPE_HOSTS_FILE"
    printf 'source\turl\taction\treason\n' > "$OUT_OF_SCOPE_FILE"
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
    extract_url_host "$line" >/dev/null || return 1
    printf '%s\n' "$line"
}

count_ipv6_side() {
    local side="$1" part count=0 index
    local -a parts=()
    [[ -n "$side" ]] || { printf '0\n'; return 0; }
    [[ "$side" != :* && "$side" != *: ]] || return 1
    IFS=':' read -r -a parts <<< "$side"
    for index in "${!parts[@]}"; do
        part="${parts[$index]}"
        if [[ "$part" == *.* ]]; then
            (( index == ${#parts[@]} - 1 )) || return 1
            valid_ipv4_literal "$part" || return 1
            count=$((count + 2))
        else
            [[ "$part" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
            count=$((count + 1))
        fi
    done
    printf '%s\n' "$count"
}

valid_ipv6_literal() {
    local value="$1" left right left_count right_count ipv4
    [[ "$value" == *:* && "$value" != *:::* ]] || return 1
    if [[ "$value" == *.* ]]; then
        ipv4="${value##*:}"
        valid_ipv4_literal "$ipv4" || return 1
    fi
    if [[ "$value" == *::* ]]; then
        left="${value%%::*}"
        right="${value#*::}"
        [[ "$right" != *::* ]] || return 1
        left_count="$(count_ipv6_side "$left")" || return 1
        right_count="$(count_ipv6_side "$right")" || return 1
        (( left_count + right_count < 8 ))
    else
        left_count="$(count_ipv6_side "$value")" || return 1
        (( left_count == 8 ))
    fi
}

valid_ipv4_literal() {
    local value="$1" octet
    local -a octets=()
    IFS='.' read -r -a octets <<< "$value"
    (( ${#octets[@]} == 4 )) || return 1
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}

valid_dns_host() {
    local host="$1" label
    local -a labels=()
    (( ${#host} <= 253 )) || return 1
    [[ "$host" != *..* && "$host" != .* && "$host" != *. ]] || return 1
    if [[ "$host" =~ ^[0-9.]+$ ]]; then
        valid_ipv4_literal "$host"
        return
    fi
    IFS='.' read -r -a labels <<< "$host"
    for label in "${labels[@]}"; do
        (( ${#label} >= 1 && ${#label} <= 63 )) || return 1
        [[ "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
    done
}

parse_authority_host() {
    local authority="$1" host port="" has_port=0
    [[ -n "$authority" ]] || return 1
    [[ "$authority" != *"\\"* && "$authority" != *"@"* && "$authority" != *"/"* && "$authority" != *"?"* && "$authority" != *"#"* ]] || return 1
    if [[ "$authority" == \[* ]]; then
        [[ "$authority" =~ ^\[([0-9A-Fa-f:.]+)\](:([0-9]+))?$ ]] || return 1
        host="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[3]:-}"
    else
        [[ "$authority" != *:*:* ]] || return 1
        if [[ "$authority" == *:* ]]; then
            has_port=1
            host="${authority%%:*}"
            port="${authority##*:}"
        else
            host="$authority"
        fi
    fi
    host="${host,,}"
    host="${host%.}"
    [[ -n "$host" ]] || return 1
    if (( has_port == 1 )) || [[ -n "$port" ]]; then
        [[ "$port" =~ ^[0-9]+$ && ${#port} -le 5 ]] || return 1
        (( 10#$port >= 1 && 10#$port <= 65535 )) || return 1
    fi
    if [[ "$host" == *:* ]]; then
        valid_ipv6_literal "$host" || return 1
    else
        valid_dns_host "$host" || return 1
    fi
    printf '%s\n' "$host"
}

extract_url_host() {
    local url="$1" authority
    [[ "$url" =~ ^https?://[^[:space:]]+$ ]] || return 1
    [[ "$url" != *"\\"* ]] || return 1
    authority="${url#*://}"
    authority="${authority%%[/?#]*}"
    parse_authority_host "$authority"
}

normalize_scope_host() {
    local value="$1" host
    value="${value%$'\r'}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    [[ -z "$value" || "$value" == \#* ]] && return 2
    if [[ "$value" =~ ^https?:// ]]; then
        host="$(extract_url_host "$value")" || return 1
    else
        host="$(parse_authority_host "$value")" || return 1
    fi
    printf '%s\n' "$host"
}

host_in_scope() {
    local host="${1,,}" base
    [[ -n "${SCOPE_HOSTS[$host]+set}" ]] && return 0
    if [[ "$INCLUDE_SUBDOMAINS" == 1 ]]; then
        for base in "${!SCOPE_HOSTS[@]}"; do
            [[ "$base" != *:* && ! "$base" =~ ^[0-9.]+$ ]] || continue
            [[ "$host" == *."$base" ]] && return 0
        done
    fi
    return 1
}

url_in_scope() {
    local host
    host="$(extract_url_host "$1")" || return 1
    host_in_scope "$host"
}

record_out_of_scope() {
    local source="$1" url="$2" action="$3" reason="$4" key
    key="${action}"$'\t'"${url}"
    [[ -n "${RECORDED_SCOPE_URLS[$key]+set}" ]] && return 0
    RECORDED_SCOPE_URLS["$key"]=1
    source="${source//$'\t'/ }"
    url="${url//$'\t'/ }"
    reason="${reason//$'\t'/ }"
    printf '%s\t%s\t%s\t%s\n' "$source" "$url" "$action" "$reason" >> "$OUT_OF_SCOPE_FILE"
}

load_scope() {
    local targets="$1" line host url rc
    SCOPE_HOSTS=()
    RECORDED_SCOPE_URLS=()
    if [[ -n "$SCOPE_FILE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            if host="$(normalize_scope_host "$line")"; then
                SCOPE_HOSTS["$host"]=1
            else
                rc=$?
                (( rc == 2 )) && continue
                die "Entrada inválida no arquivo de escopo: $line"
            fi
        done < "$SCOPE_FILE"
    else
        while IFS= read -r url; do
            [[ -n "$url" ]] || continue
            host="$(extract_url_host "$url")" || die "Não foi possível extrair o host do alvo: $url"
            SCOPE_HOSTS["$host"]=1
        done < "$targets"
    fi
    (( ${#SCOPE_HOSTS[@]} > 0 )) || die "O escopo autorizado está vazio"
    while IFS= read -r url; do
        [[ -n "$url" ]] || continue
        url_in_scope "$url" || die "Alvo fora do escopo autorizado: $url"
    done < "$targets"
    log INFO "Escopo carregado: ${#SCOPE_HOSTS[@]} host(s); subdomínios=$INCLUDE_SUBDOMAINS; exceção=$ALLOW_OUT_OF_SCOPE"
}

write_scope_metadata() {
    local scope_source
    scope_source="$([[ -n "$SCOPE_FILE" ]] && printf '%s' "$SCOPE_FILE" || printf 'targets')"
    printf '%s\n' "${!SCOPE_HOSTS[@]}" | sort > "$SCOPE_HOSTS_FILE"
    printf 'scope_source=%s\ninclude_subdomains=%s\nallow_out_of_scope=%s\n' \
        "$scope_source" "$INCLUDE_SUBDOMAINS" "$ALLOW_OUT_OF_SCOPE" >> "$RUN_FILE"
}

filter_scoped_urls() {
    local source="$1" input="$2" output="$3" line normalized host action
    local filtered="$TMP_DIR/scope-filter.$RANDOM.$$"
    : > "$filtered"
    while IFS= read -r line || [[ -n "$line" ]]; do
        if ! normalized="$(normalize_one "$line")"; then
            continue
        fi
        if url_in_scope "$normalized"; then
            printf '%s\n' "$normalized" >> "$filtered"
            continue
        fi
        host="$(extract_url_host "$normalized")" || continue
        if [[ "$ALLOW_OUT_OF_SCOPE" == 1 ]]; then
            action="allowed_override"
            printf '%s\n' "$normalized" >> "$filtered"
        else
            action="blocked"
        fi
        record_out_of_scope "$source" "$normalized" "$action" "host ${host} fora do escopo autorizado"
    done < "$input"
    sort -u "$filtered" > "$output"
    rm -f -- "$filtered"
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
    local targets="$1" url host hosts="$TMP_DIR/paramspider-hosts.txt"
    : > "$hosts"
    while IFS= read -r url; do
        [[ -n "$url" ]] || continue
        host="$(extract_url_host "$url")" || continue
        printf '%s\n' "$host" >> "$hosts"
    done < "$targets"
    sort -u "$hosts" -o "$hosts"
    while IFS= read -r host; do
        [[ -n "$host" ]] || continue
        if [[ -f "$PARAMSPIDER" ]]; then
            "$PYTHON_BIN" "$PARAMSPIDER" -d "$host" --quiet
        else
            paramspider -d "$host" --quiet
        fi
    done < "$hosts"
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

run_gf_to_file() {
    local pattern="$1" input="$2" output="$3" rc
    if gf "$pattern" < "$input" > "$output"; then
        return 0
    else
        rc=$?
    fi
    if (( rc == 1 )); then
        : > "$output"
        return 0
    fi
    return "$rc"
}

run_bhedak_urldedupe() {
    local input="$1" dedupe_raw="$TMP_DIR/xss-urldedupe.raw" dedupe_scoped="$TMP_DIR/xss-urldedupe.scoped"
    local bhedak_raw="$TMP_DIR/xss-bhedak.raw" bhedak_scoped="$TMP_DIR/xss-bhedak.scoped"
    local result="$TMP_DIR/xss-bhedak.result" rc
    if urldedupe -qs < "$input" > "$dedupe_raw"; then
        :
    else
        rc=$?
        return "$rc"
    fi
    filter_scoped_urls 'xss/urldedupe' "$dedupe_raw" "$dedupe_scoped"
    [[ -s "$dedupe_scoped" ]] || return 0
    if bhedak '\"><svg onload=confirm(1)>' < "$dedupe_scoped" > "$bhedak_raw"; then
        :
    else
        rc=$?
        return "$rc"
    fi
    filter_scoped_urls 'xss/bhedak' "$bhedak_raw" "$bhedak_scoped"
    [[ -s "$bhedak_scoped" ]] || return 0
    if airixss -payload 'confirm(1)' < "$bhedak_scoped" > "$result"; then
        { grep -E -v 'Not' "$result" || true; }
    else
        rc=$?
        return "$rc"
    fi
}

run_hakrawler_scoped() {
    if [[ "$INCLUDE_SUBDOMAINS" == 1 ]]; then
        hakrawler -subs
    else
        hakrawler
    fi
}

run_hakrawler_airixss() {
    local input="$1" httpx_raw="$TMP_DIR/xss-hakrawler-httpx.raw" httpx_scoped="$TMP_DIR/xss-hakrawler-httpx.scoped"
    local raw="$TMP_DIR/xss-hakrawler.raw" scoped="$TMP_DIR/xss-hakrawler.scoped"
    local mutated="$TMP_DIR/xss-hakrawler-mutated.raw" filtered="$TMP_DIR/xss-hakrawler-mutated.scoped"
    local result="$TMP_DIR/xss-hakrawler.result" rc
    if httpx -silent -threads "$JOBS" -timeout "$TIMEOUT" < "$input" > "$httpx_raw"; then
        :
    else
        rc=$?
        return "$rc"
    fi
    filter_scoped_urls 'xss/hakrawler-httpx' "$httpx_raw" "$httpx_scoped"
    [[ -s "$httpx_scoped" ]] || return 0
    if run_hakrawler_scoped < "$httpx_scoped" > "$raw"; then
        :
    else
        rc=$?
        return "$rc"
    fi
    filter_scoped_urls 'xss/hakrawler' "$raw" "$scoped"
    [[ -s "$scoped" ]] || return 0
    if { grep '=' < "$scoped" || true; } | qsreplace '\"><svg onload=confirm(1)>' > "$mutated"; then
        :
    else
        rc=$?
        return "$rc"
    fi
    filter_scoped_urls 'xss/qsreplace' "$mutated" "$filtered"
    [[ -s "$filtered" ]] || return 0
    if airixss -payload 'confirm(1)' < "$filtered" > "$result"; then
        { grep -E -v 'Not' "$result" || true; }
    else
        rc=$?
        return "$rc"
    fi
}

run_airixss() {
    local input="$1" gf_raw="$TMP_DIR/xss-airixss-gf.raw" gf_scoped="$TMP_DIR/xss-airixss-gf.scoped"
    local uro_raw="$TMP_DIR/xss-airixss-uro.raw" uro_scoped="$TMP_DIR/xss-airixss-uro.scoped"
    local raw="$TMP_DIR/xss-httpx.raw" scoped="$TMP_DIR/xss-httpx.scoped"
    local mutated="$TMP_DIR/xss-airixss-mutated.raw" filtered="$TMP_DIR/xss-airixss-mutated.scoped" rc
    run_gf_to_file xss "$input" "$gf_raw" || return $?
    filter_scoped_urls 'xss/gf' "$gf_raw" "$gf_scoped"
    [[ -s "$gf_scoped" ]] || return 0
    if uro < "$gf_scoped" > "$uro_raw"; then
        :
    else
        rc=$?
        return "$rc"
    fi
    filter_scoped_urls 'xss/uro' "$uro_raw" "$uro_scoped"
    [[ -s "$uro_scoped" ]] || return 0
    if httpx -silent -threads "$JOBS" -timeout "$TIMEOUT" < "$uro_scoped" > "$raw"; then
        :
    else
        rc=$?
        return "$rc"
    fi
    filter_scoped_urls 'xss/httpx' "$raw" "$scoped"
    [[ -s "$scoped" ]] || return 0
    if qsreplace '\"><svg onload=confirm(1)>' < "$scoped" > "$mutated"; then
        :
    else
        rc=$?
        return "$rc"
    fi
    filter_scoped_urls 'xss/qsreplace' "$mutated" "$filtered"
    [[ -s "$filtered" ]] || return 0
    airixss -payload 'confirm(1)' < "$filtered"
}

run_freq() {
    local input="$1" gf_raw="$TMP_DIR/xss-freq-gf.raw" gf_scoped="$TMP_DIR/xss-freq-gf.scoped"
    local uro_raw="$TMP_DIR/xss-freq-uro.raw" uro_scoped="$TMP_DIR/xss-freq-uro.scoped"
    local raw="$TMP_DIR/xss-freq.raw" scoped="$TMP_DIR/xss-freq.scoped"
    local result="$TMP_DIR/xss-freq.result" rc
    run_gf_to_file xss "$input" "$gf_raw" || return $?
    filter_scoped_urls 'xss/freq-gf' "$gf_raw" "$gf_scoped"
    [[ -s "$gf_scoped" ]] || return 0
    if uro < "$gf_scoped" > "$uro_raw"; then
        :
    else
        rc=$?
        return "$rc"
    fi
    filter_scoped_urls 'xss/freq-uro' "$uro_raw" "$uro_scoped"
    [[ -s "$uro_scoped" ]] || return 0
    if qsreplace '\"><img src=x onerror=alert(1);>' < "$uro_scoped" > "$raw"; then
        :
    else
        rc=$?
        return "$rc"
    fi
    filter_scoped_urls 'xss/freq-input' "$raw" "$scoped"
    [[ -s "$scoped" ]] || return 0
    if freq < "$scoped" > "$result"; then
        { grep -E -v 'Not' "$result" || true; }
    else
        rc=$?
        return "$rc"
    fi
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
    local input="$1" candidates="$TMP_DIR/sqli-candidates.txt" candidates_raw="$TMP_DIR/sqli-candidates.raw"
    local live_raw="$TMP_DIR/sqli-live.raw" live="$TMP_DIR/sqli-live.txt"
    local gf_raw="$TMP_DIR/sqli-gf.raw" gf_scoped="$TMP_DIR/sqli-gf.scoped"
    : > "$candidates"
    if tool_available httpx; then
        httpx -silent -l "$input" -threads "$JOBS" -timeout "$TIMEOUT" > "$live_raw" || return $?
        filter_scoped_urls 'sqli/httpx' "$live_raw" "$live"
    else
        cp -- "$input" "$live"
    fi
    run_gf_to_file sqli "$live" "$gf_raw" || return $?
    filter_scoped_urls 'sqli/gf' "$gf_raw" "$gf_scoped"
    [[ -s "$gf_scoped" ]] || return 0
    if tool_available anew; then
        anew < "$gf_scoped" > "$candidates_raw" || return $?
    else
        sort -u "$gf_scoped" > "$candidates_raw" || return $?
    fi
    filter_scoped_urls 'sqli/candidates' "$candidates_raw" "$candidates"
    [[ -s "$candidates" ]] || return 0
    sqlmap -m "$candidates" --batch --random-agent --level 1 --timeout "$TIMEOUT" --output-dir="$OUTPUT_DIR/sqli/sqlmap"
}

run_sqli_qsreplace() {
    local input="$1" responses="$OUTPUT_DIR/sqli/output" probe="$TMP_DIR/sqli-probe.txt"
    local raw="$TMP_DIR/sqli-qsreplace.raw" scoped="$TMP_DIR/sqli-qsreplace.scoped" rc
    mkdir -p -- "$responses"
    : > "$probe"
    if { grep '=' < "$input" || true; } | qsreplace "' OR '1" > "$raw"; then
        :
    else
        rc=$?
        return "$rc"
    fi
    filter_scoped_urls 'sqli/qsreplace' "$raw" "$scoped"
    [[ -s "$scoped" ]] || { printf 'Nenhum candidato SQLi dentro do escopo\n'; return 0; }
    if httpx -silent -threads "$JOBS" -timeout "$TIMEOUT" -store-response-dir "$responses" < "$scoped" > "$probe"; then
        :
    else
        rc=$?
        return "$rc"
    fi
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
    local live_raw="$TMP_DIR/recon-live.raw" gau_raw="$TMP_DIR/recon-gau.raw"
    local urls_raw="$TMP_DIR/recon-urls.raw" crawl_raw="$TMP_DIR/recon-crawl.raw"
    local candidates_raw="$TMP_DIR/recon-candidates.raw" paramspider_raw="$TMP_DIR/paramspider.raw"
    module_start
    : > "$live"; : > "$gau_file"; : > "$urls_file"; : > "$crawl_file"; : > "$candidates"
    : > "$live_raw"; : > "$gau_raw"; : > "$urls_raw"; : > "$crawl_raw"; : > "$candidates_raw"
    if tool_available httpx; then
        step httpx 'httpx (alvos ativos)' httpx -silent -l "$targets" -threads "$JOBS" -timeout "$TIMEOUT" > "$live_raw"
        filter_scoped_urls 'httpx' "$live_raw" "$live"
    else
        cp -- "$targets" "$live"
        CURRENT_MODULE_RAN=1
        record_execution fallback 'httpx (alvos ativos)' fallback 0 0 'httpx ausente; alvos originais preservados'
        log WARN 'httpx indisponível; usando os alvos originais como fallback'
    fi
    if tool_available gau; then
        step gau 'gau (URLs históricas)' gau --threads "$JOBS" --timeout "$TIMEOUT" < "$live" > "$gau_raw"
        filter_scoped_urls 'gau' "$gau_raw" "$gau_file"
    else
        record_execution tool 'gau (URLs históricas)' skipped 0 0 'gau ausente'
    fi
    if tool_available uro && [[ -s "$gau_file" ]]; then
        step uro 'uro (normalização de URLs)' uro < "$gau_file" > "$urls_raw"
        filter_scoped_urls 'uro' "$urls_raw" "$urls_file"
    elif [[ -s "$gau_file" ]]; then
        cp -- "$gau_file" "$urls_file"
        record_execution fallback 'uro (normalização de URLs)' fallback 0 0 'uro ausente; URLs históricas preservadas'
    else
        record_execution tool 'uro (normalização de URLs)' skipped 0 0 'sem entrada ou uro ausente'
    fi
    if tool_available hakrawler; then
        step hakrawler 'hakrawler (crawling)' run_hakrawler_scoped < "$live" > "$crawl_raw"
        filter_scoped_urls 'hakrawler' "$crawl_raw" "$crawl_file"
    else
        record_execution tool 'hakrawler (crawling)' skipped 0 0 'hakrawler ausente'
    fi
    awk '/^https?:\/\// {print}' "$live" "$urls_file" "$crawl_file" 2>/dev/null | sort -u > "$candidates_raw"
    filter_scoped_urls 'recon/candidates.txt' "$candidates_raw" "$candidates"
    if [[ -s "$candidates" ]]; then
        record_execution derived 'recon/candidates.txt' generated 0 0 'URLs HTTP(S) deduplicadas'
        CURRENT_MODULE_RAN=1
    fi
    if tool_available paramspider; then
        step paramspider 'ParamSpider (parâmetros)' run_paramspider "$targets" > "$paramspider_raw"
        filter_scoped_urls 'paramspider' "$paramspider_raw" "$OUTPUT_DIR/misc/paramspider.txt"
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
            --scope-file) [[ $# -ge 2 ]] || die "--scope-file requer um arquivo"; SCOPE_FILE="$2"; shift 2 ;;
            --include-subdomains) INCLUDE_SUBDOMAINS=1; shift ;;
            --allow-out-of-scope) ALLOW_OUT_OF_SCOPE=1; shift ;;
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
    setup_temp
    local targets="$TMP_DIR/targets.txt"
    if [[ -n "$INPUT_FILE" ]]; then
        normalize_targets "$INPUT_FILE" "$targets"
    else
        normalize_targets "$TARGET_URL" "$targets"
    fi
    load_scope "$targets"
    setup_output
    write_scope_metadata
    configure_proxy
    cp -- "$targets" "$OUTPUT_DIR/meta/targets.txt"
    check_optional_tools
    log INFO "Alvos válidos: $(wc -l < "$targets")"
    log INFO "Modo: ${MODE}; concorrência: ${JOBS}; timeout: ${TIMEOUT}s"
    run_mode "$targets"
    if (( RUN_FAILED != 0 )); then
        die "Uma ou mais etapas falharam; consulte ${SUMMARY_FILE}"
    fi
}

main "$@"
