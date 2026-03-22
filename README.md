# Motor de Decisão IAM Adaptativo ao Risco

> Decisão = f(risco, regra_de_negócio, maturidade, restrição_regulatória)

Arquitetura de decisão de acesso orientada a risco, onde o acesso não é definido por fluxo fixo, mas por avaliação dinâmica baseada em contexto, capacidade operacional e limites regulatórios. O motor executa em tempo real, produz um decision trace completo e alimenta uma camada de maturidade que calibra as regras ao longo do tempo.

---

## Demo interativo

O motor de decisão roda inteiramente no browser — sem backend, sem dependências externas.

**[→ Abrir demo](https://gilbertocrv.github.io/risk-adaptive-iam-decision-model)**

---

## Conceito central

O modelo não decide apenas com base no risco.

Ele considera quatro vetores independentes:

- **risco do evento** — calculado por regras determinísticas
- **regras de negócio** — aplicadas dinamicamente ao contexto
- **maturidade organizacional** — define até onde o risco pode ser tolerado
- **restrições regulatórias** — quando presentes, dominam todos os outros fatores

---

## Ordem de prioridade na decisão

```
1. Restrição regulatória   →  não pode ser relaxada por risco ou maturidade
2. Maturidade organizacional →  eleva a exigência quando HIGH
3. Score de risco           →  define a zona dinâmica e condicionada
```

---

## Papel da maturidade

Maturidade não é apenas diagnóstico — ela é **input de decisão**.

> Define até onde o risco pode ser tolerado pela organização.

| Nível  | Comportamento na decisão |
|--------|--------------------------|
| LOW    | Não altera a decisão — risco define |
| MEDIUM | Exige mitigação quando risco ≥ 100 |
| HIGH   | Bloqueia ou força controle quando risco ≥ 50 |

---

## Zonas de decisão

| Zona         | Origem da decisão                          |
|--------------|--------------------------------------------|
| Dinâmica     | Score de risco (baixo ou alto)             |
| Condicionada | Risco crítico + maturidade MEDIUM          |
| Restrita     | Restrição regulatória ou maturidade HIGH   |

---

## Regras de risco

| Regra | Condição                        | Score |
|-------|---------------------------------|-------|
| R1    | Papel privilegiado              | +50   |
| R2    | MFA desabilitado                | +40   |
| R3    | Inatividade > 30 dias           | +20   |
| R4    | Ambiente de produção            | +30   |

### Papéis privilegiados reconhecidos

`global admin` · `db admin` · `system admin` · `cloud admin` · `security admin` ·
`network admin` · `domain admin` · `root` · `superuser` · `sysadmin` · `administrator`

---

## Restrições regulatórias (hard constraints)

| Constraint | Framework  | Condição                                                              |
|------------|------------|-----------------------------------------------------------------------|
| C1         | SOX        | MFA desabilitado em acesso privilegiado                               |
| C2         | ISO 27001  | MFA desabilitado em acesso crítico                                    |
| C3         | PCI DSS    | MFA desabilitado em acesso administrativo a ambientes de dados de cartão |

---

## Saída — decision trace completo

Cada decisão responde quatro perguntas:

| Campo                   | Pergunta respondida                          |
|-------------------------|----------------------------------------------|
| `risk_score`, `decision` | O que aconteceu?                            |
| `risk_factors`, `regulatory_violations` | Por que aconteceu?          |
| `decision_basis`        | De onde veio a decisão?                      |
| `applied_zone`, `decision_path` | Em que parte do modelo caiu?         |

```json
{
  "event_id": "evt-a3f1c9d20e4b",
  "timestamp": "2025-03-22T14:32:00Z",
  "model_version": "0.3.0",
  "rule_version": "1.1.0",
  "user": "admin01",
  "recurso_alvo": "portal-admin-producao",
  "ambiente": "production",
  "frameworks_declarados": ["ISO27001", "SOX"],
  "maturity_level": "MEDIUM",
  "risk_score": 140,
  "risk_classification": "CRITICO",
  "risk_factors": [
    { "regra": "R1", "motivo": "papel privilegiado",    "score": 50 },
    { "regra": "R2", "motivo": "MFA desabilitado",      "score": 40 },
    { "regra": "R3", "motivo": "inativo há 45 dias",    "score": 20 },
    { "regra": "R4", "motivo": "ambiente de produção",  "score": 30 }
  ],
  "regulatory_violations": [
    { "constraint": "C1", "framework": "SOX",      "motivo": "MFA obrigatório para acesso privilegiado (SOX)" },
    { "constraint": "C2", "framework": "ISO27001", "motivo": "autenticação forte obrigatória para acesso crítico (ISO 27001)" }
  ],
  "decision": "BLOCK_OR_ENFORCE_MFA",
  "decision_basis": "restricao_regulatoria",
  "applied_zone": "restrita",
  "maturity_influence": null,
  "decision_path": [
    "risco_calculado",
    "constraint_detectada",
    "zona_restrita_aplicada",
    "decisao_gerada"
  ]
}
```

---

## Maturidade — métricas e relatório

### O que mede

A camada de maturidade lê o histórico de decisões persistido e avalia:

- **% de decisões fora da tolerância** — classificação CRITICO ou decisão BLOCK/REQUIRE_ACTION
- **Distribuição por zona** — dinâmica / condicionada / restrita
- **Regras mais ativadas** — quais vetores de risco dominam o ambiente
- **Constraints mais acionadas** — quais frameworks geram mais bloqueios
- **Sinais de correlação** — padrões por usuário ao longo do tempo

### Estados de maturidade

| Estado   | Critério                                      |
|----------|-----------------------------------------------|
| ESTÁVEL  | < 20% das decisões fora da tolerância         |
| INSTÁVEL | Entre 20% e 40% fora da tolerância            |
| CRÍTICO  | > 40% fora da tolerância                      |

### "Fora da tolerância"

Uma decisão é considerada fora da tolerância quando:
- `risk_classification` = `CRITICO`, **ou**
- `decision` = `BLOCK_OR_ENFORCE_MFA` ou `REQUIRE_ACTION`

Restrições regulatórias e escalamentos por maturidade entram nesse cálculo — são indicadores de que o ambiente opera com controles insuficientes.

---

## Sinais de correlação

| Sinal                  | Condição                                         |
|------------------------|--------------------------------------------------|
| `REPEATED_CRITICAL`    | Mesmo usuário com ≥ 3 decisões CRITICO           |
| `REGULATORY_RECURRENCE`| Mesmo usuário com ≥ 2 violações regulatórias     |
| `ESCALATING_RISK`      | Scores crescentes nas últimas 3 decisões do usuário |
| `PERSISTENT_NO_MFA`    | MFA nunca habilitado em nenhuma decisão do usuário |

---

## Uso

```bash
# Decisão individual
python engine/decision_engine.py examples/caso1_zona_restrita.json

# Lote completo + relatório de maturidade
python run_batch.py

# Suite de testes
python tests/test_decision_engine.py
```

---

## Estrutura do repositório

```
iam-decision-model/
├── index.html                            ← demo interativo (GitHub Pages)
├── run_batch.py                          ← executor em lote + relatório
├── engine/
│   ├── decision_engine.py               ← motor de decisão principal
│   ├── persistence.py                   ← persistência append-only em JSONL
│   ├── correlation.py                   ← detecção de padrões por usuário
│   └── maturity.py                      ← relatório de maturidade
├── tests/
│   └── test_decision_engine.py          ← 16 testes (zonas, maturidade, persistência, correlação)
├── examples/
│   ├── caso1_zona_restrita.json
│   ├── caso2_zona_condicionada.json
│   ├── caso3_zona_dinamica_restricao.json
│   ├── caso4_zona_dinamica_allow.json
│   ├── caso5_maturidade_high.json
│   └── caso6_pci_dss.json
├── evidence/                             ← gerado automaticamente (JSONL, um arquivo por dia)
└── docs/
    └── architecture.md
```

### Formato de evidência (JSONL)

Cada linha de `evidence/YYYY-MM-DD.jsonl` é um decision trace completo em JSON.
O formato é append-only — cada execução do engine adiciona uma linha ao arquivo do dia.

---

## Como demonstrar em 2 minutos

1. Abra o [demo interativo](https://gilbertocrv.github.io/risk-adaptive-iam-decision-model)
2. Execute o **Caso 1** — observe zona restrita, violação SOX + ISO27001, decision_path com `constraint_detectada`
3. Execute o **Caso 5** — mesmo perfil do caso 3, mas maturidade HIGH força bloqueio sem violação regulatória
4. Execute o **Caso 4** — risco baixo, allow, decision_path limpo
5. Observe o painel de maturidade acumulando métricas após cada decisão

---

## O que o modelo não faz

- Não substitui soluções IAM (Entra ID, Okta, CyberArk)
- Não executa autenticação
- Não define workflow de provisionamento
- Não gerencia sessões ou tokens

O processo garante coleta de dados, consistência e rastreabilidade. A lógica vive nas regras e no cálculo de risco — não no processo.

---

## Compatibilidade regulatória

ISO 27001 · SOX · PCI DSS · LGPD

---

## Versões

| Componente     | Versão | Mudanças                                              |
|----------------|--------|-------------------------------------------------------|
| Model          | 0.3.0  | Maturidade como input de decisão                      |
| Rules          | 1.1.0  | PCI DSS (C3), lista explícita de papéis privilegiados |
| Model          | 0.2.0  | Decision trace completo, persistência, correlação     |
| Rules          | 1.0.0  | R1-R4, C1-C2                                          |

`model_version` e `rule_version` são embutidos em cada decision trace — toda decisão histórica é rastreável à versão exata da lógica que a produziu.

---

## Próximos passos

- [ ] Question Engine / Hypothesis Layer — identificar o que o modelo ainda não sabe
- [ ] LGPD como constraint implementada (hoje declarada como compatibilidade)
- [ ] Agregador multi-sessão para maturidade persistida entre execuções do batch

---

## Autor

**Gilberto Gonçalves dos Santos Filho**
Analista de Governança de Identidades — IAM · PAM · GRC

[LinkedIn](https://linkedin.com/in/gilberto-filho-4430a3184) · [GitHub](https://github.com/gilbertocrv)

---

*Conteúdo educacional independente baseado em normas públicas. Não substitui consultoria técnica ou jurídica especializada.*
