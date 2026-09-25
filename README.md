# VARS — Vulnerability Automated Recon Suite

**VARS** é um script Bash para automatizar reconhecimento e triagem de segurança web em ativos próprios ou explicitamente autorizados. A versão atual preserva as opções de linha de comando da série 2.x e acrescenta isolamento de resultados, inventário de ferramentas, status por etapa, fallbacks e metadados de execução.

> **Uso autorizado somente.** O operador é responsável por obter autorização, respeitar escopo, limites de taxa e legislação aplicável. O projeto não deve ser usado contra sistemas de terceiros sem permissão explícita.

## Características principais

VARS aceita uma URL individual ou um arquivo de alvos. As entradas são filtradas para URLs HTTP(S), normalizadas e deduplicadas antes da execução. O pipeline é modular e pode executar reconhecimento, XSS, SQL injection, Nuclei, Log4j ou o fluxo completo.

As ferramentas opcionais são detectadas individualmente. A ausência de uma ferramenta não interrompe automaticamente o pipeline: a execução registra a ferramenta como indisponível e utiliza um fallback seguro quando esse fallback mantém o significado do resultado. Falhas de ferramentas são registradas com código de retorno e duração.

Cada execução cria metadados, logs e arquivos de status. Se o diretório solicitado já tiver conteúdo, VARS cria uma subpasta `run-<timestamp>-<pid>` para não sobrescrever resultados anteriores. A reutilização explícita de um diretório existente exige `VARS_OUTPUT_REUSE=1`.

## Requisitos

Os requisitos básicos são:

- Bash 4 ou superior;
- Linux compatível com Ubuntu/Debian e Kali Linux;
- `awk`, `grep`, `sed`, `sort`, `mktemp`, `xargs`, `curl`, `git`, `date`, `mkdir`, `cp`, `rm`, `wc` e `find`;
- `python3` somente quando forem usadas as integrações em formato de script: ParamSpider, XSStrike ou log4j-scan.

As ferramentas de segurança são opcionais. O VARS não instala dependências automaticamente e nunca executa comandos de instalação privilegiados.

## Instalação

Clone o repositório e torne o script executável:

```bash
git clone https://github.com/404xploit/vars.git
cd vars
chmod +x vars.sh tests/test_cli.sh tests/test_runtime.sh
./vars.sh --help
```

Instale apenas as ferramentas compatíveis com o seu ambiente e deixe-as no `PATH`. Para ferramentas Python mantidas fora do `PATH`, use os caminhos documentados na seção de configuração.

## Uso básico

```bash
./vars.sh -u https://example.com -m recon
./vars.sh -f targets.txt -m xss -o results
./vars.sh -f targets.txt -m sqli -j 10 -t 30
./vars.sh -f targets.txt -p http://127.0.0.1:8080 --keep-going
KNOXSS_API_KEY="sua-chave" ./vars.sh -f targets.txt -m xss
```

Execute scanners apenas sobre alvos autorizados. O exemplo acima usa `example.com` apenas como placeholder; substitua-o por um ativo dentro do escopo permitido.

## Opções da CLI

| Opção | Descrição |
| --- | --- |
| `-u <url>` | Escaneia uma URL HTTP(S). |
| `-f <arquivo>` | Lê URLs do arquivo, uma por linha; linhas vazias e comentários iniciados por `#` são ignorados. |
| `-o <dir>` | Define o diretório base de saída. O padrão é `vars_results`. |
| `-m <modo>` | Seleciona `full`, `recon`, `xss`, `sqli`, `nuclei` ou `log4j`. O padrão é `full`. |
| `-j <jobs>` | Define a concorrência passada às ferramentas que oferecem controle de workers ou threads. O padrão é `5`. |
| `-t <seg>` | Define o timeout em segundos para integrações que aceitam esse parâmetro. O padrão é `15`. |
| `-p <proxy>` | Define um proxy `http://` ou `https://` e exporta as variantes maiúsculas e minúsculas usadas por clientes HTTP. O valor não é gravado nos logs. |
| `-k <chave>` | Define a chave da API do Knoxss para a execução atual. Prefira `KNOXSS_API_KEY`. A chave nunca é impressa. |
| `--keep-going` | Continua para os módulos seguintes após falha de um módulo. O status final continua sendo não zero quando houve falha. |
| `-h`, `--help` | Exibe a ajuda sem banner e sem executar validação de alvo. |
| `-v`, `--version` | Exibe a versão sem banner. |

As opções existentes mantêm seu significado. `-u` e `-f` são mutuamente exclusivos. Uma execução sem alvo, com modo inválido, valor numérico inválido, proxy inválido ou arquivo inexistente termina com erro claro.

## Modos

| Modo | Pipeline |
| --- | --- |
| `recon` | Verificação de alvos ativos com httpx quando disponível, coleta histórica com gau, normalização com uro, crawling com hakrawler e geração de `recon/candidates.txt`. ParamSpider é executado quando disponível. |
| `xss` | Reconhecimento seguido por kxss, Dalfox, XSStrike, Nuclei com tags XSS, Bhedak, cadeias Airixss/Freq e Knoxss quando a chave estiver configurada. Cada integração é opcional. |
| `sqli` | Reconhecimento seguido por GF/HTTPX/SQLmap, uma verificação heurística com qsreplace/HTTPX e Nuclei com tags SQLi. |
| `nuclei` | Executa Nuclei diretamente sobre os alvos. Usa `VARS_NUCLEI_TEMPLATES` quando o diretório existir; caso contrário usa os templates padrão da instalação. |
| `log4j` | Executa log4j-scan sobre cada URL quando o binário ou script estiver disponível. |
| `full` | Executa, em ordem, `recon`, `xss`, `sqli`, `log4j`, `nuclei` e as integrações legadas de Jaeles e Xray. |

A execução é sequencial entre módulos para priorizar estabilidade e isolamento. O valor de `-j` é aplicado dentro das ferramentas que o suportam; ele não cria um número arbitrário de processos Bash fora do controle dos scanners.

## Ferramentas preservadas

O inventário de cada execução mantém todas as integrações suportadas pelo projeto e informa `available` ou `missing` em `meta/tool-status.tsv`.

| Ferramenta | Uso no pipeline |
| --- | --- |
| `httpx` | Verificação de alvos ativos e requisições de suporte. |
| `gau` | Coleta de URLs históricas. |
| `uro` | Normalização e deduplicação de URLs. |
| `gf` | Seleção de candidatos para XSS e SQLi. |
| `dalfox` | Triagem de XSS. |
| `nuclei` | Templates de segurança, incluindo tags XSS e SQLi. |
| `sqlmap` | Triagem automatizada de SQLi a partir de candidatos. |
| `jaeles` | Execução das assinaturas configuradas, quando disponíveis. |
| `xray` | Web scan com os plugins legados do projeto. |
| `kxss` | Identificação de parâmetros refletidos. |
| `bhedak` | Cadeias de XSS/SSTI e integração com deduplicação. |
| `airixss` | Verificações complementares de XSS. |
| `freq` | Verificação complementar de XSS. |
| `hakrawler` | Crawling de URLs e subdomínios. |
| `qsreplace` | Substituição de parâmetros nas cadeias legadas de XSS e SQLi. |
| `anew` | Deduplicação na cadeia de candidatos SQLi quando instalado. |
| `paramspider` | Coleta de parâmetros a partir de domínios. |
| `xsstrike` | XSS e fuzzer por script Python. |
| `log4j-scan` | Verificação de Log4Shell por binário ou script Python. |
| `urldedupe` | Integração legada de deduplicação para a cadeia Bhedak/Airixss. |
| Knoxss API | Integração remota de XSS habilitada somente com `KNOXSS_API_KEY`. |

A entrada histórica `tool` permanece no inventário de compatibilidade como marcador legado, mas não é tratada como scanner e é sempre reportada como indisponível. Ela não executa comandos.

## Configuração

A precedência é **CLI > variáveis de ambiente > valores padrão**. As variáveis abaixo são opcionais:

| Variável | Padrão | Finalidade |
| --- | --- | --- |
| `VARS_OUTPUT_DIR` | `vars_results` | Diretório padrão de saída. |
| `VARS_MODE` | `full` | Modo padrão. |
| `VARS_JOBS` | `5` | Concorrência padrão. |
| `VARS_TIMEOUT` | `15` | Timeout padrão em segundos. |
| `VARS_PROXY` | vazio | Proxy padrão. |
| `VARS_KEEP_GOING` | `0` | Use `1` para o equivalente padrão de `--keep-going`. |
| `VARS_OUTPUT_REUSE` | `0` | Use `1` para permitir reutilização explícita de um diretório não vazio. |
| `VARS_TOOLS_DIR` | `~/.local/share/vars/tools` | Raiz dos recursos mantidos fora do `PATH`. |
| `VARS_BIN_DIR` | `~/.local/bin` | Diretório de binários adicionado ao início do `PATH` se existir. |
| `VARS_PYTHON` | `python3` | Interpretador usado pelos scripts Python. |
| `VARS_JAELES_SIGNATURES` | `$VARS_TOOLS_DIR/jaeles-signatures` | Diretório de assinaturas do Jaeles. |
| `VARS_NUCLEI_TEMPLATES` | `$VARS_TOOLS_DIR/nuclei-templates` | Diretório de templates do Nuclei. |
| `VARS_PARAMSPIDER` | `$VARS_TOOLS_DIR/ParamSpider/paramspider.py` | Caminho alternativo do ParamSpider. |
| `VARS_XSSTRIKE` | `$VARS_TOOLS_DIR/XSStrike/xsstrike.py` | Caminho alternativo do XSStrike. |
| `VARS_LOG4J_SCAN` | `$VARS_TOOLS_DIR/log4j-scan/log4j-scan.py` | Caminho alternativo do log4j-scan. |
| `KNOXSS_API_KEY` | vazio | Chave usada pela integração Knoxss. |

Não coloque chaves em arquivos versionados. Para reduzir exposição, o log grava apenas que a integração Knoxss foi habilitada ou ignorada; ele não grava a chave nem o valor do proxy. Valores de ambiente usados como caminhos, alvos, proxy ou credenciais são rejeitados quando contêm caracteres de controle. O processo usa `umask 077`, e o diretório de metadados da execução recebe permissões `700`.

## Proxy, timeout e concorrência

`-p` valida o esquema `http://` ou `https://` e configura `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy` e `https_proxy` apenas no processo do VARS e nos filhos. `-t` é aplicado quando a ferramenta oferece uma opção equivalente; integrações que não expõem timeout próprio continuam sujeitas ao comportamento nativo da ferramenta. `-j` é passado às ferramentas com suporte a threads, workers ou concorrência.

A ausência de uma ferramenta não é tratada como um convite para instalar ou baixar código durante a execução. O operador pode instalar e atualizar dependências separadamente, de acordo com a política do ambiente.

## Estrutura dos resultados

Uma execução bem-sucedida cria esta estrutura, mantendo os caminhos principais da série 2.x:

```text
vars_results/
├── recon/
│   ├── live.txt
│   ├── gau.txt
│   ├── urls.txt
│   ├── crawl.txt
│   └── candidates.txt
├── xss/
├── sqli/
│   └── sqlmap/
├── log4j/
├── nuclei/
├── misc/
└── meta/
    ├── run.txt
    ├── targets.txt
    ├── vars.log
    ├── summary.txt
    ├── tool-status.tsv
    ├── module-status.tsv
    └── execution-status.tsv
```

Os arquivos TSV têm cabeçalho e podem ser processados por ferramentas Unix. `tool-status.tsv` registra disponibilidade e localização. `execution-status.tsv` registra etapas executadas, ignoradas ou falhas, com código de retorno e duração. `module-status.tsv` registra o estado de cada módulo. `summary.txt` reúne os metadados e as contagens finais.

## Tratamento de falhas e códigos de saída

O comportamento padrão interrompe a execução quando um módulo selecionado falha, preservando os resultados parciais. Com `--keep-going`, os módulos seguintes são executados, mas o processo termina com código `1` se qualquer módulo tiver falhado. Uma ferramenta ausente pode resultar em uma etapa `skipped`; quando todas as etapas disponíveis forem ignoradas, isso é registrado sem transformar a ausência opcional em falha fatal.

| Código | Significado |
| --- | --- |
| `0` | Execução concluída sem falha de módulo. |
| `1` | Entrada ou configuração inválida, dependência básica ausente, falha de módulo ou falha inesperada. |
| `130` | Execução interrompida por `SIGINT` ou `SIGTERM`. |

Sinais são tratados para remover o diretório temporário privado. O diretório temporário usa `mktemp -d` e é removido por `trap` no encerramento.

## Testes e validação

Os testes não executam scanners contra sistemas reais. O teste de runtime usa alvos fictícios, restringe o `PATH` para simular ferramentas ausentes e cria um stub local para simular uma falha de ferramenta.

```bash
bash -n vars.sh
bash tests/test_cli.sh
bash tests/test_runtime.sh
bash tests/test_inventory.sh
bash tests/test_pipeline.sh
shellcheck -x vars.sh tests/test_cli.sh tests/test_runtime.sh tests/test_inventory.sh tests/test_pipeline.sh
```

A suíte cobre parsing de ajuda e versão, rejeição de opções inválidas, validação de URL, deduplicação, criação de metadados, isolamento de saída, precedência CLI sobre ambiente, continuidade após falha, preservação do status final não zero, um inventário explícito das ferramentas, módulos e opções da CLI e um smoke test do pipeline completo com stubs locais. Nenhum teste dispara scanners contra um sistema real.

O repositório também possui uma workflow de GitHub Actions em `.github/workflows/ci.yml`. Cada push para `main` e cada pull request executa a validação de sintaxe, os testes, o inventário, o smoke test e o ShellCheck em um runner Ubuntu.

## Troubleshooting

Se uma ferramenta aparecer como `missing`, confirme sua instalação, permissões de execução e presença no `PATH`. Para scripts Python, confirme `VARS_PYTHON` e o caminho configurado pela variável correspondente. Para Jaeles e Nuclei, confirme também a existência dos diretórios de assinaturas ou templates.

Se uma execução for interrompida por falha de scanner, examine `meta/vars.log`, `meta/execution-status.tsv` e `meta/summary.txt`. Use `--keep-going` para obter resultados dos módulos restantes, lembrando que uma falha continuará refletida no código de saída.

Se resultados anteriores estiverem no diretório escolhido, procure a pasta `run-*` criada automaticamente. Para reutilizar conscientemente um diretório, defina `VARS_OUTPUT_REUSE=1` e faça backup dos resultados que deseja preservar.

## Contribuição

Pull requests e sugestões são bem-vindos. Mudanças em integrações devem manter a entrada correspondente no inventário e acrescentar testes com mocks ou stubs quando a ferramenta externa não puder ser executada em ambiente de CI.

## Licença e aviso

Consulte os arquivos do repositório para as informações de licença aplicáveis. O uso indevido de scanners de segurança pode violar leis e contratos. Utilize o VARS somente dentro de um escopo autorizado.
