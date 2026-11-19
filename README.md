# Bounty Harness

Executor Python 3.11+ para workflows de superfície externa autorizada. Carrega
`skill.yaml` do [G-Skills](https://github.com/GalakCV/G-Skills) e executa seus scripts.
Não contém auditoria de código, SAST ou varredura de repositórios.

## Começando

### Milestone 5: agentes DeepSeek

O CLI seleciona automaticamente a camada de agentes quando `DEEPSEEK_API_KEY` está
no ambiente. A chave não é lida de arquivos nem gravada no contexto, nas evidências
ou nos traces. Sem chave, o plano determinístico continua disponível.

```powershell
python -m pip install -e .
$env:BOUNTY_SKILLS = "$PWD/.external/G-Skills"
# Defina DEEPSEEK_API_KEY no ambiente da sua sessão, sem colocá-la no repositório.
python -m bounty recon --target demo --cost-budget 1 --workers 4
python -m bounty show --target demo
python -m bounty explore --target demo --skill api-testing --host api.example.com --i-am-authorized
python -m bounty report --target demo
```

O alvo `demo` precisa ter sido inicializado pelos comandos abaixo. Se ele usa
fixture, as ferramentas continuam offline, mas **o modelo utiliza a API e créditos
reais quando a chave está definida**. Os testes usam clientes injetados, sem chave
real nem créditos. Os alvos existentes têm orçamento de custo zero: forneça
`--cost-budget` no recon antes de habilitar o modelo. O valor é em USD e a reserva
de custo é compartilhada atomicamente entre os agentes.

| Papel | Modelo padrão | Configuração |
|---|---|---|
| Captain | `deepseek-reasoner` | `DEEPSEEK_CAPTAIN_MODEL` |
| Especialistas de fase/host | modelo do Captain | `DEEPSEEK_WORKER_MODEL` |
| Triager independente | `deepseek-chat` | `DEEPSEEK_TRIAGER_MODEL` |

`DEEPSEEK_BASE_URL` configura o endpoint HTTPS (padrão `https://api.deepseek.com`).
Os IDs pedidos no milestone são os padrões; podem ser substituídos conforme os
modelos disponíveis na conta. O Captain escolhe ferramentas e argumentos, observa
o resultado, ajusta a estratégia e delega tarefas a até quatro especialistas LLM
concorrentes, em profundidade 1. Cada especialista recebe somente sua card/runbook.
Um especialista não pode delegar a outro. Scripts upstream continuam disponíveis
pela função `run_phase`; suas dependências são verificadas e scripts com arquivos
compartilhados são serializados. Chamadas diretas aos tools permanecem concorrentes.

O modelo recebe envelopes de flags, taxas, retries, profundidade e arquivos.
Argumentos inválidos retornam um erro corrigível; abuso repetido ou tentativa fora
do escopo aciona o breaker. Workers compartilham orçamento e limites de taxa.
O adapter `katana` é um crawler GET limitado pelo broker (até 20 páginas, depth 3,
mesmo host, sem redirects), não uma execução irrestrita do binário upstream.

O Triager usa JSON validado com `state`, `confidence`, `rationale` e `next_step`.
Estados: `true_positive`, `false_positive`, `needs_review`. Evidência de fixture ou
ausência de observação nunca pode ser promovida a `true_positive`. Cada candidato
precisa citar uma evidência produzida pelo próprio worker; a avaliação é feita por
uma chamada LLM separada. Sem chave, a classificação segue como `hypothesis`.

Timeout/retries: `DEEPSEEK_TIMEOUT` (30s), `DEEPSEEK_MAX_RETRIES` (2),
`DEEPSEEK_MAX_OUTPUT_TOKENS` (2048). O SDK não faz retries adicionais ocultos.
Custos estimados por milhão: `DEEPSEEK_INPUT_USD_PER_MILLION`,
`DEEPSEEK_CACHED_INPUT_USD_PER_MILLION`, `DEEPSEEK_OUTPUT_USD_PER_MILLION`.
Os padrões são estimativas conservadoras configuráveis, não uma cotação garantida.
Cache hit/miss e custo observado ficam nos traces. O prefixo estável (instruções e
card) vem antes do slice variável do blackboard, seguindo o
[cache por prefixo do DeepSeek](https://api-docs.deepseek.com/guides/kv_cache/).

### Replay

Os traces registram decisões operacionais, chamadas e respostas redigidas por
agente, sem gravar `reasoning_content`. Esse campo fica somente na memória para a
continuação do protocolo de [tool calling](https://api-docs.deepseek.com/guides/tool_calls/).
`temperature=0` é enviado, mas não promete determinismo de amostragem: o provedor
[pode ignorá-lo em thinking mode](https://api-docs.deepseek.com/guides/thinking_mode/).
O replay reutiliza as respostas registradas, valida o hash do pedido público e
interrompe se contexto ou observações divergirem.

```powershell
# Alvo novo, mesmo escopo/fixture e blackboard inicial da gravação.
python -m bounty init --target replay-demo --scope examples/scope.json --fixture examples/fixture.json
python -m bounty recon --target replay-demo --cost-budget 1 --replay runs/demo/traces/events.jsonl
```

Replay dispensa chave e recusa alvos live. Ele reproduz escolhas contra fixtures,
não promete que um alvo real continuará retornando a mesma resposta. Traces com
várias campanhas usam a última, ou a escolhida por `--replay-campaign <id>`. O relatório
inclui o caminho escolhido pelos agentes e os veredictos do Triager.

### Fluxo determinístico e verificação offline

No PowerShell, a partir desta pasta:

```powershell
python -m pip install -e .
# Se o clone ainda não existir:
git clone https://github.com/GalakCV/G-Skills.git .external/G-Skills
git -C .external/G-Skills checkout 178cccf450791adfb2be58fe92bb674d6ff6f53d
$env:BOUNTY_SKILLS = "$PWD/.external/G-Skills"

# Milestone 1: script http-probe real, respostas locais controladas.
bounty init --target demo --scope examples/scope.json --fixture examples/fixture.json
bounty validate --target demo
bounty recon --target demo --phase http-probe
bounty recon --target demo --phase http-probe
bounty show --target demo

# Milestone 2: quatro fases de recon, ainda no modo fixture desse alvo.
bounty recon --target demo
bounty report --target demo --format md
bounty targets

# Milestone 3: host escolhido, aprovação explícita, mesmo modo offline.
bounty explore --target demo --skill api-testing --host api.example.com --i-am-authorized
bounty explore --target demo --skill web-testing --host demo.example.com --i-am-authorized

# Milestone 4: infraestrutura com observações de fixture.
bounty explore --target demo --skill infra --host api.example.com --i-am-authorized

# Testes: clone acima, pytest e Git Bash no Windows.
python -m pytest -q
```

`python -m bounty` funciona sem instalação editável. O clone local já está presente
neste workspace; `skills.lock.json` registra origem e revisão. `--skills` ou
`BOUNTY_SKILLS` configuram o caminho; o padrão é `~/.agents/skills/`.

Fixtures executam os **scripts reais** com substitutos dos comandos de rede.
Relatórios as identificam como offline e suas linhas são hipóteses, nunca evidência
de vulnerabilidade real. Não misture um alvo fixture com avaliação real: crie outro
nome. Git Bash precisa acessar a pasta; o sandbox do aplicativo pode exigir
aprovação para executar esses testes no Windows.

### Execução real

Requer **Linux, Bash, bubblewrap funcional e ferramentas ProjectDiscovery**.
Windows nativo recusa execução real: não há backend equivalente de isolamento de
rede nesse sistema. O backend Linux foi implementado, mas **não foi executado neste
ambiente Windows**; valide-o no seu ambiente antes de uma campanha.

Instale `subfinder`, `assetfinder`, `waybackurls`, `gau`, `dnsx`, **ProjectDiscovery
httpx** (não o pacote Python homônimo), `curl`, `openssl`, bubblewrap, uma wordlist
DNS e os utilitários POSIX usados pelas skills: awk, sort, sed, grep, head, wc e timeout.

```bash
export BOUNTY_SKILLS="$HOME/.agents/skills"
export BOUNTY_DNS_WORDLIST=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
python -m bounty init --target programa --scope /caminho/scope-autorizado.json
python -m bounty validate --target programa
python -m bounty recon --target programa
python -m bounty show --target programa
python -m bounty explore --target programa --skill api-testing --host api.dominio-autorizado.com
python -m bounty report --target programa
```

Explore pede `y/N`, mostrando alvo, host e escopo. Em modo não interativo exige
`--i-am-authorized`. Recon nunca chama explore. Inicialização automática:
`bounty recon --target programa --scope scope.json`. Para a fatia inicial adicione
`--phase http-probe`: os seeds são sua entrada explícita, sem alegar execução das
dependências de descoberta.

Escopo:

```json
{"seeds":["example.com"],"in_scope":["*.example.com"],"out_of_scope":["private.example.com"]}
```

O filtro upstream normaliza DNS/URLs; `*.example.com` inclui o apex. Exclusões
vencem inclusões. O contrato atual aceita nomes DNS, não CIDRs nem endereços IPv6.
Autorização de domínio não implica autorização para buckets ou CNAMEs de terceiros.

### Cobertura dos manifestos

| Skill | Executado | Pendências explícitas |
|---|---|---|
| recon | passive-enum, active-discovery, http-probe, surface-mapping | Ferramentas/wordlist no modo real |
| api-testing | spec-recon; auth-enforcement com `--paths` | BOLA, BFLA e mass-assignment são runbooks |
| web-testing | Planejamento e registro dos runbooks | Manifesto não declara fases executáveis |
| cloud | asset-fingerprint, bucket-exposure | metadata-reach e misconfig são runbooks |
| infra | takeover, tls | exposed-services e dns são runbooks |

`--paths caminhos.txt` fornece paths GET de baixa sensibilidade **revisados pelo
operador**. Não deriva caminhos seguros de uma especificação. Query, parâmetros e
traversal são recusados. Miner de specs e helpers avulsos permanecem manuais:
seus manifestos não especificam encadeamento nem contrato de saída completo.

Bucket-exposure usa o nome do alvo como prefixo, conforme o script upstream.
Cada URL gerada precisa estar no escopo; a primeira tentativa fora dele interrompe
a campanha. Não infere propriedade de buckets. Takeover nunca registra recursos;
consultas adicionais a CNAMEs fora do escopo são recusadas. HTTP não segue redirects.
Nenhum endpoint de credenciais de metadata é executado automaticamente.

### Estado e evidências

Cada alvo mantém `runs/<slug>/blackboard.db`, `raw/`, `traces/`, `findings/`,
`report/`, `hosts/`, `out/` e `work/`. O banco não é limpo. Surface usa chave host;
findings usam skill/fase/host/título. Reexecuções atualizam observações e deduplicam
findings; traces e cobertura de fases preservam histórico. `init --fresh` arquiva
a pasta anterior com um sufixo único antes de criar outra.

Um lock impede campanhas simultâneas no mesmo alvo. Após encerramento forçado pelo
SO, confira o PID em `campaign.lock` antes de remover somente esse arquivo. Nunca
é necessário apagar o banco. Erros/interrupções produzem relatório parcial;
breaker registra motivo e orçamento em `breaker.json`.

Budgets em `context.json`: segundos, iterações e custo; taxas HTTP/DNS separadas.
Sem chave, não há chamadas a modelos nem custo de tokens.
Breaker cobre erros consecutivos, taxa de erros em janela, 429 repetidos, escopo
e orçamento. Backoff não repete automaticamente uma requisição 429. Hosts sem
resposta continuam como `dead`, conforme a saída da skill.

### Extensões e confiança

- Skills: diretórios com `SKILL.md`, `safety.md`, `skill.yaml`; ciclos, tiers
  desconhecidos e `code-audit` são recusados.
- Argumentos ausentes no upstream: `bounty/adapters.yaml` ou `harness.yaml` na
  skill, mapeados por nome da skill e ID da fase.
- Tools: entry points `bounty.tools` recebem a camada determinística.
- Specialists: `bounty.specialists`, com captain e triager separados.
- Relatórios: `bounty.reports`; Markdown é o sink padrão.

Sem chave, Captain é um planejador determinístico de DAG. Com chave, ele dirige
ferramentas e especialistas LLM. Triager exige evidência para julgar impacto. Traces
guardam decisões, justificativas operacionais, chamadas, gates e estado do breaker;
não guardam raciocínio privado de modelos.

Plugins instalados, executáveis de rede e operador são confiáveis. Scripts live
executam em bubblewrap sem rede, com filesystem restrito; ferramentas passam pelo
broker. Python urllib/DNS também são roteados pelo broker. Resultados são redigidos
antes de retornar ao worker. Redação por padrões não detecta todo segredo arbitrário.

Fixture só aceita scripts revisados cujos hashes estão em `bounty/trusted.json`;
não oferece sandbox de SO para código arbitrário no Windows. Atualizar skills
exige revisão antes de atualizar hashes. Skills com contratos completos dispensam
mudança no executor; novas capacidades de rede exigem adapter registrado e revisado.

Hashes e snapshots de execução normalizam CRLF/LF. `.gitattributes` fixa LF em
Python e shell nos dois repositórios. O workflow de CI executa as fixtures em Linux
com Python 3.11 e 3.12. Novas skills podem declarar `tools` por fase; as permissões
da ferramenta ainda precisam estar registradas na camada determinística.

`AGENTS.md` e `skills/05-field-lessons.md` citados no pedido não estavam no workspace.
Foram aplicados contratos, safety cards e lições disponíveis no G-Skills, incluindo
stdin fechado, status observado, scope_filter e verificação DNS.
