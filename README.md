# VARS

**Vulnerability Assessment and Recon Suite** — um orquestrador Bash modular para recon e avaliação automatizada de aplicações web em ativos autorizados.

> **Status:** v2.0.0 — refatoração do pipeline e da CLI.

## O que mudou no v2

- CLI simplificada com modos `full`, `recon`, `xss`, `sqli`, `nuclei` e `log4j`.
- Remoção de caminhos obrigatórios em `/root`.
- Validação de entrada para aceitar somente URLs HTTP(S).
- `set -Eeuo pipefail` e tratamento centralizado de erros.
- Diretórios temporários isolados e limpeza automática.
- Saídas separadas por módulo e logs em `meta/`.
- Ferramentas opcionais não impedem a execução do restante do pipeline.
- Concorrência configurável com `-j`.
- Timeout configurável para integrações HTTP que o suportam.
- Chave Knoxss obtida de `KNOXSS_API_KEY` ou `-k`, em vez de ficar hard-coded no código.
- Recon separado do estágio de scanners, reduzindo trabalho duplicado.

## Instalação

VARS não instala automaticamente ferramentas com privilégios de root. Instale as ferramentas que deseja utilizar e garanta que estejam no `PATH`.

Dependências básicas:

- Bash 4+
- curl
- git
- awk, grep, sed, sort, xargs, mktemp

Ferramentas opcionais reconhecidas incluem `httpx`, `gau`, `uro`, `gf`, `dalfox`, `nuclei`, `sqlmap`, `jaeles`, `xray`, `kxss`, `bhedak`, `airixss`, `freq`, `hakrawler`, `qsreplace`, `anew`, `paramspider`, `xsstrike` e `log4j-scan`.

Para usar ferramentas Python por caminho local, configure as variáveis correspondentes, por exemplo:

```bash
export VARS_TOOLS_DIR="$HOME/.local/share/vars/tools"
```

## Uso

```bash
chmod +x vars.sh

./vars.sh -u https://example.com
./vars.sh -u https://example.com -m recon
./vars.sh -u https://example.com -m xss
./vars.sh -f targets.txt -m sqli -o results
./vars.sh -f targets.txt -m full -j 10
./vars.sh -f targets.txt -p http://127.0.0.1:8080
KNOXSS_API_KEY="[SUA_CHAVE]" ./vars.sh -f targets.txt -m xss
```

### Modos

| Modo | Objetivo |
|---|---|
| `recon` | Descoberta e normalização de URLs |
| `xss` | Recon + scanners de XSS |
| `sqli` | Recon + identificação de candidatos SQLi + SQLmap/Nuclei |
| `nuclei` | Nuclei sobre os alvos fornecidos |
| `log4j` | Avaliação Log4j nos alvos fornecidos |
| `full` | Pipeline completo |

### Opções

```text
-u <url>       URL única
-f <arquivo>   Arquivo com URLs
-o <dir>       Diretório de saída
-m <modo>      full|recon|xss|sqli|nuclei|log4j
-j <jobs>      Concorrência do pipeline
-t <seg>       Timeout de integrações HTTP
-p <proxy>     Proxy HTTP/HTTPS
-k <chave>     Chave Knoxss
--keep-going   Continua quando um módulo falha
-h             Ajuda
-v             Versão
```

## Estrutura dos resultados

```text
vars_results/
├── meta/
│   ├── run.txt
│   ├── targets.txt
│   └── *.log
├── recon/
│   ├── live.txt
│   ├── gau.txt
│   ├── crawl.txt
│   ├── urls.txt
│   └── candidates.txt
├── xss/
├── sqli/
├── log4j/
├── nuclei/
└── misc/
```

O arquivo `meta/run.txt` registra versão, modo e horários da execução. Os logs de ferramentas ficam em `meta/` para facilitar troubleshooting.

## Arquitetura

```text
Targets
   │
   ▼
Normalize + Validate
   │
   ▼
Recon ──────────────┐
   │                │
   ├── live         │
   ├── historical   │
   ├── crawl        │
   └── candidates   │
                    ▼
              Scanner modules
             ┌──────┼──────┐
             ▼      ▼      ▼
            XSS    SQLi   Nuclei
             │      │      │
             └──────┼──────┘
                    ▼
                 Results
```

A intenção do projeto é orquestrar ferramentas existentes sem esconder o comportamento de cada scanner. Cada módulo pode ser substituído ou expandido sem alterar a validação e o gerenciamento de execução.

## Segurança operacional

- Use o VARS somente contra ativos próprios ou explicitamente autorizados.
- Evite colocar chaves API em commits. Prefira variáveis de ambiente.
- Use `-j` conservadoramente para não causar rate limiting ou indisponibilidade.
- Revise os resultados manualmente antes de reportar uma vulnerabilidade.
- Scanners automatizados podem gerar falsos positivos e falsos negativos.

## Roadmap

- [ ] Configuração declarativa em YAML/TOML.
- [ ] Plugins/módulos independentes.
- [ ] Output JSON/JSONL normalizado.
- [ ] Deduplicação baseada em URL + parâmetro + tipo de finding.
- [ ] Profiles `quick`, `passive`, `standard` e `aggressive`.
- [ ] Testes automatizados para parsing e pipelines.
- [ ] CI com ShellCheck e testes em alvos locais de laboratório.

## Contribuição

Issues e Pull Requests são bem-vindos. Ao adicionar uma integração, documente a dependência, o formato de saída, limitações e como o módulo pode ser executado isoladamente.

## Aviso legal

O VARS foi desenvolvido para pesquisa, educação, bug bounty e testes de segurança autorizados. O usuário é responsável por garantir que possui autorização para testar os ativos envolvidos.
