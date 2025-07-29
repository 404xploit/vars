<img src="https://capsule-render.vercel.app/api?type=transparent&height=300&color=gradient&text=VARS&desc=Vulnerability%20Assessment%20and%20Recon%20Script&fontAlignY=50&descSize=30&fontSize=100&descAlignY=68">


![Shell Script](https://img.shields.io/badge/Bash-Script-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Made with ❤️](https://img.shields.io/badge/made%20with-%E2%9D%A4-red)

**VARS** (Vulnerability Automated Recon Suite) é um script Bash poderoso e automatizado para **varredura de vulnerabilidades web**, combinando as melhores ferramentas do ecossistema de bug bounty, pentest e red teaming.

---

## 🚀 Funcionalidades

- ✅ Escaneia URLs individuais ou arquivos com listas de domínios
- ✅ Detecta automaticamente:
  - Cross-Site Scripting (XSS)
  - SQL Injection (SQLi)
  - Server-Side Template Injection (SSTI)
  - Log4Shell (CVE-2021-44228)
- 🔍 Coleta de parâmetros ocultos com ParamSpider
- 📂 Resultados organizados em diretórios por categoria (xss, sqli, etc.)
- 🔁 Totalmente automatizado e fácil de usar
- ☠️ Integração com ferramentas líderes do mercado (Nuclei, Jaeles, Knoxss, XSStrike, Dalfox, Xray, etc.)
- 🔌 Suporte a proxy HTTP para redirecionamento via Burp/ZAP

---

## 🧰 Ferramentas utilizadas

O VARS integra e automatiza o uso de diversas ferramentas de segurança:

| Ferramenta       | Finalidade                          |
|------------------|--------------------------------------|
| `httpx`          | Verificação de URLs ativas          |
| `gf`             | Filtros para XSS, SQLi, etc.         |
| `dalfox`         | XSS avançado e fuzzing              |
| `nuclei`         | PoC scanner baseado em templates     |
| `jaeles`         | Scanner modular com fuzzing         |
| `xsstrike`       | Detecção e exploração de XSS         |
| `sqlmap`         | Teste de injeção SQL automatizado    |
| `xray`           | Scanner avançado para web vulns     |
| `paramspider`    | Coleta de parâmetros de URLs         |
| `log4j-scan`     | Scanner para Log4Shell               |
| `bhedak`, `airixss`, `kxss`, `freq` | Detecção e fuzz complementar |

---

## 🛠️ Instalação

Para instalar todas as dependências necessárias, execute:

```bash
chmod +x vars.sh
./vars.sh -i
```

---

## ⚙️ Uso

```bash
./vars.sh [opções]
```

### Opções disponíveis:

| Opção | Descrição                                                  |
| ----- | ---------------------------------------------------------- |
| `-u`  | Escanear uma única URL (ex: `https://testphp.vulnweb.com`) |
| `-f`  | Escanear URLs de um arquivo (uma por linha)                |
| `-o`  | Diretório de saída (padrão: `url_vuln_scan_results`)       |
| `-p`  | Definir proxy HTTP (ex: `http://127.0.0.1:8080`)           |
| `-i`  | Instalar dependências                                      |
| `-h`  | Exibir ajuda                                               |

### Exemplos:

```bash
./vars.sh -u https://example.com -o results
./vars.sh -f targets.txt -o results -p http://127.0.0.1:8080
./vars.sh -i
```

---

## 🧠 Requisitos

- Go instalado (`sudo apt install golang`)
- Python3 + pip3
- Linux com permissão de escrita em `/tmp`
- Conexão ativa com a internet

---

## 📁 Estrutura dos Resultados

```
url_vuln_scan_results/
├── xss/
├── sqli/
├── log4j/
├── misc/
```

---

## 📊 Metodologia

Abaixo está o diagrama da metodologia do script, representado em Mermaid, ilustrando o fluxo de execução desde a entrada até a geração dos resultados:

```mermaid
flowchart TD
    Start([Início do Script]) --> Args[Parsear argumentos]
    
    Args --> CheckInstallDeps{Flag -i foi usada?}
    CheckInstallDeps -- Sim --> InstallDeps[Executar install_deps\ne sair]
    CheckInstallDeps -- Não --> ValidateInput[Validar entrada: -u ou -f]

    ValidateInput -->|Sem -u ou -f| ErrorNoInput[Erro: URL ou arquivo necessário]
    ValidateInput -->|Arquivo -f inválido| ErrorFile[Erro: Arquivo não encontrado]
    ValidateInput -->|Entrada válida| SetProxy{Proxy fornecido?}
    
    SetProxy -- Sim --> ConfigurarProxy[Exportar HTTP_PROXY\ne HTTPS_PROXY]
    SetProxy -- Não --> SkipProxy[Ignorar proxy]

    ConfigurarProxy --> CheckDeps
    SkipProxy --> CheckDeps

    CheckDeps[Verificar dependências\ninstaladas] -->|Ausentes| ErrorDeps[Erro: Use -i]
    CheckDeps -->|OK| SetupOut[Criar estrutura\nde diretórios]
    
    SetupOut --> DetermineInput[Definir INPUT:\nURL ou Arquivo]
    DetermineInput --> Scans[Executar módulos\nde escaneamento]

    subgraph Escaneamentos
        Scans --> Xray[Xray Scan\nXSS, SQLi, Cmd Inj]
        Scans --> Knoxss[Knoxss XSS Scan]
        Scans --> Log4j[Log4j Scan]
        Scans --> BhedakUR[Bhedak +\nUrldedupe XSS]
        Scans --> Hakrawler[Hakrawler +\nAirixss]
        Scans --> Airixss[Airixss]
        Scans --> Freq[Freq XSS]
        Scans --> Bhedak[Bhedak\nXSS/SSTI]
        Scans --> DalfoxXS[Dalfox +\nXSStrike]
        Scans --> DalfoxURL[Dalfox\nURL Scan]
        Scans --> Chaos[Chaos\nParamSpider]
        Scans --> KXSS[KXSS Scan]
        Scans --> SQLiMass[SQLi Massivo]
        Scans --> SQLiQS[SQLi com\nqsreplace]
        Scans --> SQLiURL[SQLi com\nURL]
        Scans --> Nuclei[Nuclei Scan]
        Scans --> Jaeles[Jaeles Scan]
    end

    Jaeles --> Done([✔ Todos os Scans Concluídos])

    %% Estilos
    classDef start fill:#2ecc71,stroke:#27ae60,stroke-width:2px,color:#fff
    classDef error fill:#e74c3c,stroke:#c0392b,stroke-width:2px,color:#fff
    classDef process fill:#3498db,stroke:#2980b9,stroke-width:2px,color:#fff
    classDef decision fill:#e67e22,stroke:#d35400,stroke-width:2px,color:#fff
    classDef scan fill:#9b59b6,stroke:#8e44ad,stroke-width:2px,color:#fff
    classDef subgraphStyle fill:none,stroke:#7f8c8d,stroke-width:2px

    class Start,Done start
    class Args,InstallDeps,ConfigurarProxy,SkipProxy,CheckDeps,SetupOut,DetermineInput,Scans process
    class ErrorNoInput,ErrorFile,ErrorDeps error
    class CheckInstallDeps,SetProxy,ValidateInput decision
    class Xray,Knoxss,Log4j,BhedakUR,Hakrawler,Airixss,Freq,Bhedak,DalfoxXS,DalfoxURL,Chaos,KXSS,SQLiMass,SQLiQS,SQLiURL,Nuclei,Jaeles scan
    class Escaneamentos subgraphStyle
```

## 🤝 Contribuição

Pull Requests e sugestões são bem-vindas! Abra uma issue ou envie seu PR.

---

## ⚠️ Aviso Legal

Este script foi desenvolvido **exclusivamente para fins educacionais e de teste em ambientes autorizados**. O uso indevido pode violar leis locais. **Use com responsabilidade.**
