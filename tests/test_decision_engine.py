"""
Suite de testes — Motor de Decisão IAM Adaptativo ao Risco
Versão do modelo testada: 0.3.0

Cobertura
---------
  - Zonas de decisão (restrita, condicionada, dinâmica)
  - Maturidade como input de decisão (LOW / MEDIUM / HIGH)
  - Restrição regulatória sobrepõe risco baixo
  - Restrição regulatória sobrepõe maturidade
  - PCI DSS como constraint (C3)
  - Estrutura do decision_path
  - Completude dos campos de saída
  - Persistência (gravar e reler JSONL)
  - Correlação (sinais por usuário)
  - Relatório de maturidade
"""

import sys, os, json, tempfile, shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "engine"))
from decision_engine import decide, calcular_risco as calculate_risk, verificar_constraints as check_regulatory_constraints, eh_privilegiado as is_privileged
from persistence import save, load_all
from correlation import correlate
from maturity import build_report


# ─── Helpers ──────────────────────────────────────────────────────────────────

def verifica(label, case, esperado):
    resultado = decide(case)
    ok = all(resultado.get(k) == v for k, v in esperado.items())
    status = "OK  " if ok else "ERRO"
    print(f"  [{status}] {label}")
    if not ok:
        for k, v in esperado.items():
            if resultado.get(k) != v:
                print(f"         {k}: esperado={v!r}  obtido={resultado.get(k)!r}")
    return ok


# ─── Testes de zonas ──────────────────────────────────────────────────────────

def teste_zona_restrita_sox_iso():
    return verifica(
        "Zona restrita — violação SOX + ISO27001",
        {"user":"admin01","role":"Global Admin","mfa_enabled":False,
         "last_login_days":45,"environment":"production",
         "target_resource":"portal-admin","framework":["ISO27001","SOX"],
         "maturity_level":"MEDIUM"},
        {"decision":"BLOCK_OR_ENFORCE_MFA","decision_basis":"restricao_regulatoria",
         "applied_zone":"restrita","risk_score":140,"risk_classification":"CRITICO"},
    )

def teste_zona_restrita_pci_dss():
    return verifica(
        "Zona restrita — violação PCI DSS (C3)",
        {"user":"dba_pci","role":"DB Admin","mfa_enabled":False,
         "last_login_days":5,"environment":"production",
         "target_resource":"db-cartoes","framework":["PCI DSS"],
         "maturity_level":"LOW"},
        {"decision":"BLOCK_OR_ENFORCE_MFA","decision_basis":"restricao_regulatoria",
         "applied_zone":"restrita"},
    )

def teste_zona_condicionada_risco_critico():
    return verifica(
        "Zona condicionada — risco crítico sem violação regulatória",
        {"user":"dba_senior","role":"DB Admin","mfa_enabled":True,
         "last_login_days":35,"environment":"production",
         "target_resource":"db-producao","framework":[],
         "maturity_level":"LOW"},
        {"decision":"REQUIRE_ACTION","decision_basis":"score_de_risco",
         "applied_zone":"condicionada","risk_score":100},
    )

def teste_zona_dinamica_allow_with_restriction():
    return verifica(
        "Zona dinâmica — risco alto, MFA ativo, sem violação",
        {"user":"dba02","role":"DB Admin","mfa_enabled":True,
         "last_login_days":10,"environment":"production",
         "target_resource":"db-cluster","framework":["ISO27001"],
         "maturity_level":"LOW"},
        {"decision":"ALLOW_WITH_RESTRICTION","decision_basis":"score_de_risco",
         "applied_zone":"dinamica","risk_score":80},
    )

def teste_zona_dinamica_allow():
    return verifica(
        "Zona dinâmica — risco baixo, allow",
        {"user":"user99","role":"Viewer","mfa_enabled":True,
         "last_login_days":5,"environment":"staging",
         "target_resource":"dashboard","framework":["ISO27001"],
         "maturity_level":"LOW"},
        {"decision":"ALLOW","decision_basis":"score_de_risco",
         "applied_zone":"dinamica","risk_score":0,"risk_classification":"BAIXO"},
    )


# ─── Testes de maturidade ─────────────────────────────────────────────────────

BASE_CENARIO = {
    "user":"eng01","role":"DB Admin","mfa_enabled":True,
    "last_login_days":10,"environment":"production",
    "target_resource":"db-staging","framework":[],
}

def teste_maturidade_low():
    return verifica(
        "Maturidade LOW — não eleva decisão (risco alto, allow_with_restriction)",
        {**BASE_CENARIO, "maturity_level":"LOW"},
        {"decision":"ALLOW_WITH_RESTRICTION","decision_basis":"score_de_risco",
         "maturity_influence":None},
    )

def teste_maturidade_medium_sem_efeito():
    return verifica(
        "Maturidade MEDIUM — sem efeito (risco alto < 100)",
        {**BASE_CENARIO, "maturity_level":"MEDIUM"},
        {"decision":"ALLOW_WITH_RESTRICTION","maturity_influence":None},
    )

def teste_maturidade_high_eleva_decisao():
    return verifica(
        "Maturidade HIGH — eleva ALLOW_WITH_RESTRICTION para BLOCK (risco >= 50)",
        {**BASE_CENARIO, "maturity_level":"HIGH"},
        {"decision":"BLOCK_OR_ENFORCE_MFA","decision_basis":"maturidade_organizacional",
         "applied_zone":"restrita","maturity_influence":"escalamento_de_risco"},
    )

def teste_maturidade_medium_com_risco_critico():
    return verifica(
        "Maturidade MEDIUM — eleva para REQUIRE_ACTION (risco >= 100)",
        {"user":"dba_senior","role":"DB Admin","mfa_enabled":True,
         "last_login_days":35,"environment":"production",
         "target_resource":"db-producao","framework":[],
         "maturity_level":"MEDIUM"},
        {"decision":"REQUIRE_ACTION","decision_basis":"score_de_risco",
         "applied_zone":"condicionada"},
    )

def teste_restricao_sobrepos_maturidade():
    """Restrição regulatória deve dominar mesmo com maturidade LOW."""
    return verifica(
        "Restrição regulatória sobrepõe maturidade LOW",
        {"user":"admin_sox","role":"Global Admin","mfa_enabled":False,
         "last_login_days":2,"environment":"staging",
         "target_resource":"portal","framework":["SOX"],
         "maturity_level":"LOW"},
        {"decision":"BLOCK_OR_ENFORCE_MFA","decision_basis":"restricao_regulatoria",
         "applied_zone":"restrita"},
    )


# ─── Testes estruturais ───────────────────────────────────────────────────────

def teste_estrutura_decision_path():
    resultado = decide({"user":"x","role":"Viewer","mfa_enabled":True,
                        "last_login_days":1,"environment":"dev","framework":[]})
    path = resultado.get("decision_path", [])
    ok = path[0] == "risco_calculado" and path[-1] == "decisao_gerada"
    status = "OK  " if ok else "ERRO"
    print(f"  [{status}] Estrutura do decision_path")
    return ok

def teste_campos_completos():
    obrigatorios = [
        "event_id","timestamp","model_version","rule_version","user",
        "recurso_alvo","ambiente","frameworks_declarados","maturity_level",
        "risk_score","risk_classification","risk_factors","regulatory_violations",
        "decision","decision_basis","applied_zone","maturity_influence","decision_path",
    ]
    resultado = decide({"user":"x","role":"Viewer","mfa_enabled":True,
                        "last_login_days":1,"environment":"dev","framework":[]})
    faltando = [f for f in obrigatorios if f not in resultado]
    ok = not faltando
    status = "OK  " if ok else "ERRO"
    print(f"  [{status}] Completude dos campos de saída")
    if faltando:
        print(f"         campos ausentes: {faltando}")
    return ok

def teste_papel_privilegiado_lista():
    ok = all([
        is_privileged("Global Admin"),
        is_privileged("db admin"),
        is_privileged("root"),
        not is_privileged("Viewer"),
        not is_privileged("Analyst"),
    ])
    status = "OK  " if ok else "ERRO"
    print(f"  [{status}] Lista de papéis privilegiados")
    return ok


# ─── Testes de persistência ───────────────────────────────────────────────────

def teste_persistencia():
    tmp = Path(tempfile.mkdtemp())
    try:
        r1 = decide({"user":"u1","role":"Viewer","mfa_enabled":True,
                     "last_login_days":1,"environment":"dev","framework":[]})
        r2 = decide({"user":"u2","role":"Global Admin","mfa_enabled":False,
                     "last_login_days":40,"environment":"production","framework":["SOX"]})
        save(r1, tmp)
        save(r2, tmp)
        registros = load_all(tmp)
        ok = len(registros) == 2 and registros[0]["user"] == "u1"
        status = "OK  " if ok else "ERRO"
        print(f"  [{status}] Persistência — gravar e reler JSONL")
        return ok
    finally:
        shutil.rmtree(tmp)


# ─── Testes de correlação ─────────────────────────────────────────────────────

def teste_correlacao_sinais():
    casos = [
        {"user":"admin01","role":"Global Admin","mfa_enabled":False,
         "last_login_days":45,"environment":"production","framework":["SOX"]},
        {"user":"admin01","role":"Global Admin","mfa_enabled":False,
         "last_login_days":50,"environment":"production","framework":["SOX"]},
        {"user":"admin01","role":"Global Admin","mfa_enabled":False,
         "last_login_days":55,"environment":"production","framework":["SOX"]},
    ]
    registros = [decide(c) for c in casos]
    resultado = correlate(registros)
    sinais_admin = resultado["by_user"].get("admin01", [])
    tipos = {s["signal"] for s in sinais_admin}
    ok = "REPEATED_CRITICAL" in tipos and "REGULATORY_RECURRENCE" in tipos
    status = "OK  " if ok else "ERRO"
    print(f"  [{status}] Correlação — sinais REPEATED_CRITICAL e REGULATORY_RECURRENCE")
    return ok


# ─── Testes de maturidade (relatório) ────────────────────────────────────────

def teste_relatorio_maturidade():
    tmp = Path(tempfile.mkdtemp())
    try:
        casos = [
            {"user":"admin01","role":"Global Admin","mfa_enabled":False,
             "last_login_days":45,"environment":"production","framework":["SOX"]},
            {"user":"user99","role":"Viewer","mfa_enabled":True,
             "last_login_days":5,"environment":"staging","framework":[]},
        ]
        for c in casos:
            save(decide(c), tmp)
        relatorio = build_report(tmp)
        ok = (
            "maturity_state" in relatorio and
            "total_decisions" in relatorio and
            relatorio["total_decisions"] == 2
        )
        status = "OK  " if ok else "ERRO"
        print(f"  [{status}] Relatório de maturidade — campos e contagem")
        return ok
    finally:
        shutil.rmtree(tmp)


# ─── Runner ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    testes = [
        teste_zona_restrita_sox_iso,
        teste_zona_restrita_pci_dss,
        teste_zona_condicionada_risco_critico,
        teste_zona_dinamica_allow_with_restriction,
        teste_zona_dinamica_allow,
        teste_maturidade_low,
        teste_maturidade_medium_sem_efeito,
        teste_maturidade_high_eleva_decisao,
        teste_maturidade_medium_com_risco_critico,
        teste_restricao_sobrepos_maturidade,
        teste_estrutura_decision_path,
        teste_campos_completos,
        teste_papel_privilegiado_lista,
        teste_persistencia,
        teste_correlacao_sinais,
        teste_relatorio_maturidade,
    ]

    print("\nSuite de Testes — Motor de Decisão IAM")
    print("=" * 50)
    resultados = [t() for t in testes]
    total  = len(resultados)
    passou = sum(resultados)
    print("─" * 50)
    print(f"  {passou}/{total} passou\n")
    sys.exit(0 if passou == total else 1)
