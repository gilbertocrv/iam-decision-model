"""
Executor em lote — Motor de Decisão IAM Adaptativo ao Risco
------------------------------------------------------------
Executa múltiplos casos de entrada, persiste cada decisão em evidence/
e gera o relatório de maturidade a partir da evidência acumulada.

Uso
---
  python run_batch.py                    # usa casos internos
  python run_batch.py examples/caso1.json
  python run_batch.py examples/          # todos os JSON de uma pasta
"""

import json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "engine"))

from decision_engine import decide
from persistence import save, DEFAULT_DIR
from maturity import build_report


# ─── Casos internos de referência ────────────────────────────────────────────

CASOS_INTERNOS = [
    # Zona restrita — violação regulatória
    {"user":"admin01","role":"Global Admin","mfa_enabled":False,"last_login_days":45,
     "environment":"production","target_resource":"portal-admin","framework":["ISO27001","SOX"],"maturity_level":"MEDIUM"},
    {"user":"admin01","role":"Global Admin","mfa_enabled":False,"last_login_days":50,
     "environment":"production","target_resource":"sistema-faturamento","framework":["ISO27001","SOX"],"maturity_level":"MEDIUM"},
    {"user":"admin01","role":"Global Admin","mfa_enabled":False,"last_login_days":55,
     "environment":"production","target_resource":"diretorio-usuarios","framework":["ISO27001","SOX"],"maturity_level":"MEDIUM"},
    # Zona condicionada — risco crítico
    {"user":"dba_senior","role":"DB Admin","mfa_enabled":True,"last_login_days":35,
     "environment":"production","target_resource":"db-cluster-prod","framework":[],"maturity_level":"LOW"},
    {"user":"dba_senior","role":"DB Admin","mfa_enabled":True,"last_login_days":38,
     "environment":"production","target_resource":"db-replica-prod","framework":[],"maturity_level":"LOW"},
    # Zona dinâmica — com restrição
    {"user":"dba02","role":"DB Admin","mfa_enabled":True,"last_login_days":10,
     "environment":"production","target_resource":"db-cluster-prod","framework":["ISO27001"],"maturity_level":"LOW"},
    {"user":"eng01","role":"Read Admin","mfa_enabled":True,"last_login_days":8,
     "environment":"production","target_resource":"portal-logs","framework":["ISO27001"],"maturity_level":"LOW"},
    # Zona dinâmica — maturidade HIGH eleva decisão
    {"user":"dba02","role":"DB Admin","mfa_enabled":True,"last_login_days":10,
     "environment":"production","target_resource":"db-cluster-prod","framework":["ISO27001"],"maturity_level":"HIGH"},
    # Zona dinâmica — allow
    {"user":"user99","role":"Viewer","mfa_enabled":True,"last_login_days":5,
     "environment":"staging","target_resource":"dashboard-relatorios","framework":["ISO27001"],"maturity_level":"LOW"},
    {"user":"user42","role":"Viewer","mfa_enabled":True,"last_login_days":3,
     "environment":"staging","target_resource":"dashboard-analytics","framework":["ISO27001"],"maturity_level":"LOW"},
    # PCI DSS
    {"user":"dba_pci","role":"DB Admin","mfa_enabled":False,"last_login_days":5,
     "environment":"production","target_resource":"db-dados-cartao","framework":["PCI DSS"],"maturity_level":"MEDIUM"},
]


def carregar_casos(caminho: Path) -> list[dict]:
    casos = []
    arquivos = [caminho] if caminho.is_file() else sorted(caminho.glob("*.json"))
    for arq in arquivos:
        with open(arq) as f:
            dados = json.load(f)
        dados.pop("_descricao", None)
        casos.append(dados)
    return casos


def executar_lote(casos: list[dict], evidence_dir=DEFAULT_DIR) -> list[dict]:
    resultados = []
    for caso in casos:
        registro = decide(caso)
        arq_log  = save(registro, evidence_dir)
        resultados.append(registro)
        print(f"  [{registro['decision']:<28}]  {registro['user']:<14}  maturidade: {registro['maturity_level']}  →  {arq_log.name}")
    return resultados


if __name__ == "__main__":
    evidence_dir = DEFAULT_DIR

    if len(sys.argv) > 1:
        casos = carregar_casos(Path(sys.argv[1]))
    else:
        casos = CASOS_INTERNOS

    print(f"\nExecutor em lote — {len(casos)} casos\n{'─' * 60}")
    executar_lote(casos, evidence_dir)

    print(f"\n{'─' * 60}")
    print(f"  Decisões salvas em: {evidence_dir}/\n")
    print("Relatório de maturidade\n" + "─" * 60)
    relatorio = build_report(evidence_dir)
    print(json.dumps(relatorio, indent=2, ensure_ascii=False))
