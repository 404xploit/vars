#!/bin/bash
#!/bin/bash
echo "                                                                              "
echo "                                                                              "
echo "                                                                              "
echo "                                                                              "
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

echo "Iniciando Vulnerability Assessment and Recon Script..."

# Função para exibir ajuda
show_help() {
    echo ""
    echo "Uso: $0 [opções]"
    echo ""
    echo "Opções disponíveis:"
    echo "  -u <target_url>   Escaneia uma única URL (ex.: https://testphp.vulnweb.com)"
    echo "  -f <input_file>   Escaneia múltiplas URLs a partir de um arquivo (uma por linha)"
    echo "  -i                Instala todas as dependências necessárias para o funcionamento do script"
    echo "  -o <output_dir>   Define o diretório de saída para os resultados (padrão: url_vuln_scan_results)"
    echo "  -p <proxy>        Define um proxy para as ferramentas (ex.: http://127.0.0.1:8080)"
    echo "  -h                Exibe esta mensagem de ajuda"
    echo ""
    echo "Exemplos de uso:"
    echo "  $0 -u https://testphp.vulnweb.com -o results"
    echo "  $0 -f urls.txt -o results -p http://127.0.0.1:8080"
    echo "  $0 -i"
    echo ""
    exit 0
}

OUTPUT_DIR="url_vuln_scan_results"
PROXY=""
KNOXSS_API_KEY="APIDOKNOXSS" # Substitua pelo seu Knoxss API key
JAELES_SIGNATURES="/jaeles-signatures"
NUCLEI_TEMPLATES="/root/nuclei-templates"
PARAMSPIDER="/root/tools/paramspider/paramspider.py"
XSSTRIKE="/root/tools/xsstrike/xsstrike.py"
LOG4J_SCAN="/root/tools/log4j-scan/log4j-scan.py"

# Função para checar e instalar dependências
install_deps() {
    echo "Verificando e instalando dependências..."

    # Verificar go e python3-pip
    if ! command -v go >/dev/null 2>&1; then
        echo "[ERRO] Go não está instalado. Instale com: sudo apt install golang"
        exit 1
    fi
    echo " Go encontrado: $(go version)"

    if ! command -v pip3 >/dev/null 2>&1; then
        echo "[ERRO] python3-pip não está instalado. Instale com: sudo apt install python3-pip"
        exit 1
    fi
    echo " pip3 encontrado: $(pip3 --version)"

    # Verificar se /tmp é gravável
    if ! [ -w /tmp ]; then
        echo "[ERRO] Diretório /tmp não é gravável. Corrija permissões: sudo chmod 1777 /tmp"
        exit 1
    fi
    echo " /tmp é gravável"

    # Pacotes do sistema
    local sys_deps=("curl" "jq" "grep" "awk" "sed" "xargs" "unzip")
    for dep in "${sys_deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            echo " Instalando $dep..."
            sudo apt update && sudo apt install -y "$dep" || echo "[ERRO] Falha ao instalar $dep"
        else
            echo " $dep já está instalado"
        fi
    done

    # Ferramentas baseadas em Go
    local go_deps=(
        "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "gau:github.com/lc/gau/v2/cmd/gau@latest"
        "uro:github.com/s0md3v/uro@latest"
        "gf:github.com/tomnomnom/gf@latest"
        "nuclei:github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
        "airixss:github.com/ferreiraklet/airixss@latest"
        "freq:github.com/emadshanab/Freq@latest"
        "dalfox:github.com/hahwul/dalfox@latest"
        "kxss:github.com/tomnomnom/hacks/kxss@latest"
    )
    for dep in "${go_deps[@]}"; do
        local name="${dep%%:*}"
        local repo="${dep#*:}"
        if ! command -v "$name" >/dev/null 2>&1; then
            echo " Instalando $name..."
            go install "$repo" || echo "[AVISO] Falha ao instalar $name. Tente manualmente: go install $repo"
            if [ -f "/root/go/bin/$name" ]; then
                sudo mv "/root/go/bin/$name" /usr/local/bin/ || echo "[ERRO] Falha ao mover $name para /usr/local/bin"
            else
                echo "[AVISO] Binário de $name não encontrado em /root/go/bin. Verifique o ambiente Go."
            fi
        else
            echo " $name já está instalado"
        fi
    done

    # xray
    if ! command -v xray >/dev/null 2>&1; then
        echo " Instalando xray..."
        LATEST_XRAY=$(curl -s https://api.github.com/repos/chaitin/xray/releases/latest | jq -r '.assets[] | select(.name | contains("linux_amd64")) | .browser_download_url')
        if [ -n "$LATEST_XRAY" ]; then
            curl -L "$LATEST_XRAY" -o /tmp/xray.zip || echo "[ERRO] Falha ao baixar xray"
            unzip /tmp/xray.zip -d /tmp/xray || echo "[ERRO] Falha ao descompactar xray"
            sudo mv /tmp/xray/xray /usr/local/bin/ || echo "[ERRO] Falha ao mover xray para /usr/local/bin"
            rm -rf /tmp/xray /tmp/xray.zip
        else
            echo "[AVISO] Falha ao buscar binário do xray. Instale manualmente: https://github.com/chaitin/xray/releases"
        fi
    else
        echo " xray já está instalado"
    fi

    # bhedak
    if ! command -v bhedak >/dev/null 2>&1; then
        echo " Instalando bhedak..."
        git clone https://github.com/R0X4R/bhedak.git /tmp/bhedak || { echo "[ERRO] Falha ao clonar bhedak"; exit 1; }
        cd /tmp/bhedak
        go mod init github.com/R0X4R/bhedak || echo "[AVISO] go mod init falhou, tentando compilar mesmo assim"
        go build -o bhedak . || { echo "[ERRO] Falha ao compilar bhedak"; exit 1; }
        sudo mv bhedak /usr/local/bin/ || echo "[ERRO] Falha ao mover bhedak para /usr/local/bin"
        cd - >/dev/null
        rm -rf /tmp/bhedak
    else
        echo " bhedak já está instalado"
    fi

    # sqlmap
    if ! command -v sqlmap >/dev/null 2>&1; then
        echo " Instalando sqlmap..."
        git clone https://github.com/sqlmapproject/sqlmap.git /tmp/sqlmap || echo "[ERRO] Falha ao clonar sqlmap"
        sudo ln -s /tmp/sqlmap/sqlmap.py /usr/local/bin/sqlmap || echo "[ERRO] Falha ao criar link para sqlmap"
    else
        echo " sqlmap já está instalado"
    fi

    # jaeles
    if ! command -v jaeles >/dev/null 2>&1; then
        echo " Instalando jaeles..."
        git clone https://github.com/jaeles-project/jaeles.git /tmp/jaeles || echo "[ERRO] Falha ao clonar jaeles"
        cd /tmp/jaeles && go build && sudo mv jaeles /usr/local/bin/ || echo "[ERRO] Falha ao compilar ou mover jaeles"
        sudo mkdir -p "$JAELES_SIGNATURES"
        git clone https://github.com/jaeles-project/jaeles-signatures.git "$JAELES_SIGNATURES" || echo "[ERRO] Falha ao clonar assinaturas do jaeles"
        rm -rf /tmp/jaeles
    else
        echo " jaeles já está instalado"
    fi

    # Paramspider
    if ! [ -f "$PARAMSPIDER" ]; then
        echo " Instalando paramspider..."
        git clone https://github.com/devanshbatham/ParamSpider.git /root/tools/paramspider || echo "[ERRO] Falha ao clonar paramspider"
        sudo ln -s "$PARAMSPIDER" /usr/local/bin/paramspider || echo "[ERRO] Falha ao criar link para paramspider"
        sudo chmod +x "$PARAMSPIDER"
    else
        echo " paramspider já está instalado em $PARAMSPIDER"
    fi

    # xsstrike
    if ! [ -f "$XSSTRIKE" ]; then
        echo " Instalando xsstrike..."
        git clone https://github.com/s0md3v/XSStrike.git /root/tools/xsstrike || echo "[ERRO] Falha ao clonar xsstrike"
        pip3 install -r /root/tools/xsstrike/requirements.txt || echo "[ERRO] Falha ao instalar dependências do xsstrike"
        sudo ln -s "$XSSTRIKE" /usr/local/bin/xsstrike || echo "[ERRO] Falha ao criar link para xsstrike"
    else
        echo " xsstrike já está instalado em $XSSTRIKE"
    fi

    # log4j-scan
    if ! [ -f "$LOG4J_SCAN" ]; then
        echo " Instalando log4j-scan..."
        git clone https://github.com/fullhunt/log4j-scan.git /root/tools/log4j-scan || echo "[ERRO] Falha ao clonar log4j-scan"
        pip3 install -r /root/tools/log4j-scan/requirements.txt || echo "[ERRO] Falha ao instalar dependências do log4j-scan"
        sudo ln -s "$LOG4J_SCAN" /usr/local/bin/log4j-scan || echo "[ERRO] Falha ao criar link para log4j-scan"
    else
        echo " log4j-scan já está instalado em $LOG4J_SCAN"
    fi

    # Nuclei templates
    if ! [ -d "$NUCLEI_TEMPLATES" ]; then
        echo " Instalando templates do nuclei..."
        sudo mkdir -p "$NUCLEI_TEMPLATES"
        git clone https://github.com/projectdiscovery/nuclei-templates.git "$NUCLEI_TEMPLATES" || echo "[ERRO] Falha ao clonar templates do nuclei"
    else
        echo " Templates do nuclei já estão instalados em $NUCLEI_TEMPLATES"
    fi

    echo " Instalação de dependências concluída. Configure KNOXSS_API_KEY no script."
}

# Função para verificar dependências
check_deps() {
    echo " Verificando dependências..."
    local deps=("curl" "jq" "httpx" "gau" "uro" "gf" "xargs" "grep" "awk" "sed" "xray" "bhedak" "airixss" "freq" "dalfox" "sqlmap" "jaeles" "nuclei" "kxss" "paramspider" "xsstrike" "log4j-scan")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            echo "[ERRO] $dep não está instalado ou não está no PATH. Execute com -i para instalar dependências."
            exit 1
        fi
        echo " $dep encontrado"
    done
    if ! [ -d "$JAELES_SIGNATURES" ]; then
        echo "[ERRO] Assinaturas do jaeles não encontradas em $JAELES_SIGNATURES. Execute com -i para instalar."
        exit 1
    fi
    if ! [ -d "$NUCLEI_TEMPLATES" ]; then
        echo "[ERRO] Templates do nuclei não encontrados em $NUCLEI_TEMPLATES. Execute com -i para instalar."
        exit 1
    fi
}

# Função para criar estrutura de diretórios de saída
setup_output() {
    echo " Configurando diretório de saída: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR" "$OUTPUT_DIR/xss" "$OUTPUT_DIR/sqli" "$OUTPUT_DIR/log4j" "$OUTPUT_DIR/misc" || { echo "[ERRO] Falha ao criar diretórios"; exit 1; }
}

# Função: Escaneamento Xray
xray_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/xss/xray_vuln.html"
    echo " Executando escaneamento Xray em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para xray_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        xargs -a "$input" -I@ sh -c "xray webscan --plugins cmd-injection,sqldet,xss --url \"@\" --html-output \"$output\" || true"
    else
        echo "$input" | xargs -I@ sh -c "xray webscan --plugins cmd-injection,sqldet,xss --url \"@\" --html-output \"$output\" || true"
    fi
}

# Função: Escaneamento Knoxss XSS
knoxss_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/xss/knoxss_results.txt"
    echo " Executando escaneamento Knoxss XSS em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para knoxss_scan"
        return 1
    fi
    if [ "$KNOXSS_API_KEY" = "APIDOKNOXSS" ]; then
        echo "[ERRO] KNOXSS_API_KEY não configurada. Defina no script."
        return 1
    fi
    if [ -f "$input" ]; then
        cat "$input" | grep "=" | uro | gf xss | awk "{ print \"curl https://knoxss.me/api/v3 -d \\\"target=\\\"\$1\\\"\\\" -H \\\"X-API-KEY: $KNOXSS_API_KEY\\\"\"}" | sh > "$output" || echo "[ERRO] Falha no escaneamento Knoxss"
    else
        echo "$input" | grep "=" | uro | gf xss | awk "{ print \"curl https://knoxss.me/api/v3 -d \\\"target=\\\"\$1\\\"\\\" -H \\\"X-API-KEY: $KNOXSS_API_KEY\\\"\"}" | sh > "$output" || echo "[ERRO] Falha no escaneamento Knoxss"
    fi
}

# Função: Escaneamento Log4j
log4j_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/log4j/log4j_results.txt"
    echo " Executando escaneamento Log4j em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para log4j_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        cat "$input" | httpx -silent | xargs -I@ sh -c "log4j-scan -u \"@\" || true" > "$output" 2>&1
    else
        echo "$input" | httpx -silent | xargs -I@ sh -c "log4j-scan -u \"@\" || true" > "$output" 2>&1
    fi
}

# Função: Escaneamento urldedupe + bhedak XSS
bhedak_urldedupe_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/xss/bhedak_urldedupe_results.txt"
    echo " Executando escaneamento bhedak com urldedupe XSS em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para bhedak_urldedupe_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        cat "$input" | urldedupe -qs | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not' > "$output" || echo "[ERRO] Falha no escaneamento bhedak_urldedupe"
    else
        echo "$input" | urldedupe -qs | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not' > "$output" || echo "[ERRO] Falha no escaneamento bhedak_urldedupe"
    fi
}

# Função: Escaneamento Hakrawler + airixss XSS
hakrawler_airixss_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/xss/hakrawler_airixss_results.txt"
    echo " Executando escaneamento hakrawler + airixss XSS em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para hakrawler_airixss_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        cat "$input" | httpx -silent | hakrawler -subs | grep "=" | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not' > "$output" || echo "[ERRO] Falha no escaneamento hakrawler_airixss"
    else
        echo "$input" | httpx -silent | hakrawler -subs | grep "=" | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not' > "$output" || echo "[ERRO] Falha no escaneamento hakrawler_airixss"
    fi
}

# Função: Escaneamento Airixss XSS
airixss_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/xss/airixss_results.txt"
    echo " Executando escaneamento airixss XSS em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para airixss_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        cat "$input" | gf xss | uro | httpx -silent | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" > "$output" || echo "[ERRO] Falha no escaneamento airixss"
    else
        echo "$input" | gf xss | uro | httpx -silent | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" > "$output" || echo "[ERRO] Falha no escaneamento airixss"
    fi
}

# Função: Escaneamento Freq XSS
freq_xss_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/xss/freq_xss_results.txt"
    echo " Executando escaneamento freq XSS em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para freq_xss_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        cat "$input" | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq | egrep -v 'Not' > "$output" || echo "[ERRO] Falha no escaneamento freq"
    else
        echo "$input" | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq | egrep -v 'Not' > "$output" || echo "[ERRO] Falha no escaneamento freq"
    fi
}

# Função: Escaneamento Bhedak XSS e SSTI
bhedak_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/xss/bhedak_results.txt"
    echo " Executando escaneamento bhedak XSS e SSTI em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para bhedak_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        cat "$input" | bhedak "\"><svg/onload=alert(1)>*'/---+{{7*7}}" > "$output" || echo "[ERRO] Falha no escaneamento bhedak"
    else
        echo "$input" | bhedak "\"><svg/onload=alert(1)>*'/---+{{7*7}}" > "$output" || echo "[ERRO] Falha no escaneamento bhedak"
    fi
}

# Função: Escaneamento Dalfox (xsstrike)
dalfox_xsstrike_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/xss/dalfox_xsstrike_results.txt"
    echo " Executando escaneamento dalfox (xsstrike) em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para dalfox_xsstrike_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        xargs -a "$input" -I@ bash -c "xsstrike -u @ --fuzzer || true" > "$output" 2>&1
    else
        echo "$input" | xargs -I@ bash -c "xsstrike -u @ --fuzzer || true" > "$output" 2>&1
    fi
}

# Função: Escaneamento Dalfox URL
dalfox_url_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/xss/dalfox_url_results.txt"
    echo " Executando escaneamento dalfox URL em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para dalfox_url_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        cat "$input" | anew | httpx -silent -threads 500 | xargs -I@ dalfox url @ > "$output" 2>&1 || echo "[ERRO] Falha no escaneamento dalfox"
    else
        echo "$input" | httpx -silent -threads 500 | xargs -I@ dalfox url @ > "$output" 2>&1 || echo "[ERRO] Falha no escaneamento dalfox"
    fi
}

# Função: Escaneamento de parâmetros com chaos
chaos_param_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/misc/chaos_param_results.txt"
    echo " Executando escaneamento de parâmetros com chaos em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para chaos_param_scan"
        return 1
    fi
    local domains
    if [ -f "$input" ]; then
        domains=$(cat "$input" | awk -F/ '{print $3}' | sort -u | grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    else
        domains=$(echo "$input" | awk -F/ '{print $3}' | sort -u | grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    fi
    if [ -z "$domains" ]; then
        echo "[ERRO] Nenhum domínio válido extraído de $input"
        return 1
    fi
    echo "$domains" | xargs -I@ sh -c "paramspider -d @ --quiet || echo '[ERRO] Falha no paramspider para @'" > "$output" 2>&1
}


# Função: Escaneamento Kxss XSS
kxss_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/xss/kxss_results.txt"
    echo " Executando escaneamento kxss XSS em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para kxss_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        cat "$input" | kxss > "$output" || echo "[ERRO] Falha no escaneamento kxss"
    else
        echo "$input" | kxss > "$output" || echo "[ERRO] Falha no escaneamento kxss"
    fi
}

# Função: Escaneamento SQLi massivo
sqli_mass_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/sqli/sqli_results.txt"
    echo " Executando escaneamento SQLi massivo em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para sqli_mass_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        cat "$input" | httpx -silent | anew | gf sqli > sqli_temp.txt && sqlmap -m sqli_temp.txt --batch --random-agent --level 1 > "$output" 2>&1 || echo "[ERRO] Falha no escaneamento SQLi massivo"
        rm -f sqli_temp.txt
    else
        echo "$input" | httpx -silent | anew | gf sqli > sqli_temp.txt && sqlmap -m sqli_temp.txt --batch --random-agent --level 1 > "$output" 2>&1 || echo "[ERRO] Falha no escaneamento SQLi massivo"
        rm -f sqli_temp.txt
    fi
}

# Função: Escaneamento SQLi com qsreplace
sqli_qsreplace_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/sqli/sqli_qsreplace_results.txt"
    echo " Executando escaneamento SQLi com qsreplace em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para sqli_qsreplace_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        cat "$input" | grep "=" | qsreplace "' OR '1" | httpx -silent -store-response-dir "$OUTPUT_DIR/sqli/output" -threads 100 | grep -q -rn "syntax\|mysql" "$OUTPUT_DIR/sqli/output" 2>/dev/null && printf "TARGET \033[0;32mPode ser Explorável\e[m\n" || printf "TARGET \033[0;31mNão Vulnerável\e[m\n" > "$output" || echo "[ERRO] Falha no escaneamento SQLi qsreplace"
    else
        echo "$input" | grep "=" | qsreplace "' OR '1" | httpx -silent -store-response-dir "$OUTPUT_DIR/sqli/output" -threads 100 | grep -q -rn "syntax\|mysql" "$OUTPUT_DIR/sqli/output" 2>/dev/null && printf "TARGET \033[0;32mPode ser Explorável\e[m\n" || printf "TARGET \033[0;31mNão Vulnerável\e[m\n" > "$output" || echo "[ERRO] Falha no escaneamento SQLi qsreplace"
    fi
}

# Função: Escaneamento SQLi URL
sqli_url_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/sqli/sqli_url_results.txt"
    echo " Executando escaneamento SQLi URL em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para sqli_url_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        cat "$input" | httpx -silent | anew | gf sqli > sqli_temp.txt && sqlmap -m sqli_temp.txt --batch --random-agent --level 1 > "$output" 2>&1 || echo "[ERRO] Falha no escaneamento SQLi URL"
        rm -f sqli_temp.txt
    else
        echo "$input" | httpx -silent | anew | gf sqli > sqli_temp.txt && sqlmap -m sqli_temp.txt --batch --random-agent --level 1 > "$output" 2>&1 || echo "[ERRO] Falha no escaneamento SQLi URL"
        rm -f sqli_temp.txt
    fi
}

# Função: Escaneamento Nuclei
nuclei_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/misc/nuclei_results.txt"
    echo " Executando escaneamento nuclei em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para nuclei_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        cat "$input" | httpx -silent -threads 1000 | nuclei -t "$NUCLEI_TEMPLATES" -o "$output" || echo "[ERRO] Falha no escaneamento nuclei"
    else
        echo "$input" | httpx -silent -threads 1000 | nuclei -t "$NUCLEI_TEMPLATES" -o "$output" || echo "[ERRO] Falha no escaneamento nuclei"
    fi
}

# Função: Escaneamento Jaeles URL
jaeles_url_scan() {
    local input="$1"
    local output="$OUTPUT_DIR/misc/jaeles_url_results.txt"
    echo " Executando escaneamento jaeles URL em $input"
    if [ -z "$input" ]; then
        echo "[ERRO] Entrada vazia para jaeles_url_scan"
        return 1
    fi
    if [ -f "$input" ]; then
        cat "$input" | anew | httpx -silent -threads 500 | xargs -I@ jaeles scan -s "$JAELES_SIGNATURES" -u @ > "$output" 2>&1 || echo "[ERRO] Falha no escaneamento jaeles"
    else
        echo "$input" | httpx -silent -threads 500 | xargs -I@ jaeles scan -s "$JAELES_SIGNATURES" -u @ > "$output" 2>&1 || echo "[ERRO] Falha no escaneamento jaeles"
    fi
}

# Parsear argumentos
echo " Parseando argumentos..."
while getopts "u:f:o:p:ih" opt; do
    case $opt in
        u) TARGET_URL="$OPTARG" ;;
        f) INPUT_FILE="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        p) PROXY="$OPTARG" ;;
        i) INSTALL_DEPS=1 ;;
        h) show_help ;;
        *) echo "[ERRO] Uso: $0 [-u target_url | -f input_file | -i | -h] [-o output_dir] [-p proxy]"; exit 1 ;;
    esac
done

# Lidar com instalação de dependências
if [ -n "$INSTALL_DEPS" ]; then
    echo " Executando install_deps..."
    install_deps
    exit 0
fi

# Validar entrada
echo " Validando entrada..."
if [ -z "$TARGET_URL" ] && [ -z "$INPUT_FILE" ]; then
    echo "[ERRO] Forneça uma URL alvo (-u), arquivo de entrada (-f), use -i para instalar dependências ou -h para ajuda"
    exit 1
fi
if [ -n "$INPUT_FILE" ] && [ ! -f "$INPUT_FILE" ]; then
    echo "[ERRO] Arquivo de entrada $INPUT_FILE não existe"
    exit 1
fi

# Configurar proxy
if [ -n "$PROXY" ]; then
    echo " Configurando proxy: $PROXY"
    export HTTP_PROXY="$PROXY"
    export HTTPS_PROXY="$PROXY"
fi

# Verificar dependências
check_deps

# Configurar diretório de saída
setup_output

# Determinar entrada
if [ -n "$INPUT_FILE" ]; then
    INPUT="$INPUT_FILE"
else
    INPUT="$TARGET_URL"
fi
echo " Entrada definida: $INPUT"

# Executar escaneamentos
xray_scan "$INPUT"
knoxss_scan "$INPUT"
log4j_scan "$INPUT"
bhedak_urldedupe_scan "$INPUT"
hakrawler_airixss_scan "$INPUT"
airixss_scan "$INPUT"
freq_xss_scan "$INPUT"
bhedak_scan "$INPUT"
dalfox_xsstrike_scan "$INPUT"
dalfox_url_scan "$INPUT"
chaos_param_scan "$INPUT"
kxss_scan "$INPUT"
sqli_mass_scan "$INPUT"
sqli_qsreplace_scan "$INPUT"
sqli_url_scan "$INPUT"
nuclei_scan "$INPUT"
jaeles_url_scan "$INPUT"

echo " Todos os escaneamentos concluídos. Resultados salvos em $OUTPUT_DIR"
