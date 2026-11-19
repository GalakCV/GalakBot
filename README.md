# Bounty Harness

Executor Python 3.11+ para workflows de superfície externa autorizada. Carrega
`skill.yaml` do [G-Skills](https://github.com/GalakCV/G-Skills) e executa seus scripts.
Não contém auditoria de código, SAST ou varredura de repositórios.

## Começando

No PowerShell, a partir desta pasta:

```powershell
python -m pip install -e .
# Se o clone ainda não existir:
git clone https://github.com/GalakCV/G-Skills.git .external/G-Skills
git -C .external/G-Skills checkout 0cea363af3f1c0ca2414cc777c53dc4d08d3fa69
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
Não há chamadas a modelos nem custo de tokens neste backend determinístico.
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

Captain é um planejador determinístico de DAG com um worker, profundidade 1.
Triager nunca transforma saída de detector em confirmação de impacto. Traces
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

`AGENTS.md` e `skills/05-field-lessons.md` citados no pedido não estavam no workspace.
Foram aplicados contratos, safety cards e lições disponíveis no G-Skills, incluindo
stdin fechado, status observado, scope_filter e verificação DNS.
