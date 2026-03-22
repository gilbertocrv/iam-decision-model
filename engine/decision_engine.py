"""
Motor de Decisão IAM Adaptativo ao Risco
=========================================
Versão do modelo : 0.3.0
Versão das regras: 1.1.0

Fórmula central
---------------
Decisão = f(risco, regra_de_negócio, maturidade, restrição_regulatória)

Ordem de prioridade na decisão
-------------------------------
1. Restrição regulatória  — não pode ser relaxada por nenhum outro fator
2. Maturidade organizacional — eleva exigência quando HIGH
3. Score de risco         — define a zona dinâmica e condicionada

Zonas de decisão
----------------
  restrita     — restrição regulatória ou maturidade HIGH com risco elevado
  condicionada — risco crítico sem violação regulatória
  dinâmica     — risco baixo/alto sem constraint ativa
"""

from datetime import datetime, timezone
import json
import uuid

MODEL_VERSION = "0.3.0"
RULE_VERSION  = "1.1.0"

PRIVILEGED_ROLES = {
    "global admin", "db admin", "read admin", "system admin",
    "cloud admin", "security admin", "network admin", "domain admin",
    "root", "superuser", "sysadmin", "administrator",
}

MATURITY_LEVELS = {"LOW", "MEDIUM", "HIGH"}
MATURITY_CRITICAL_THRESHOLD = 0.40
MATURITY_UNSTABLE_THRESHOLD = 0.20


def is_privileged(role: str) -> bool:
    return role.strip().lower() in PRIVILEGED_ROLES


def calculate_risk(data: dict) -> tuple[int, list[dict]]:
    score = 0
    factors = []

    if is_privileged(data.get("role", "")):
        score += 50
        factors.append({"regra": "R1", "motivo": "papel privilegiado", "score": 50})

    if not data.get("mfa_enabled", True):
        score += 40
        factors.append({"regra": "R2", "motivo": "MFA desabilitado", "score": 40})

    inactive_days = data.get("last_login_days", 0)
    if inactive_days > 30:
        score += 20
        factors.append({"regra": "R3", "motivo": f"inativo há {inactive_days} dias", "score": 20})

    env = data.get("environment", "")
    if env in ("production", "producao"):
        score += 30
        factors.append({"regra": "R4", "motivo": "ambiente de produção", "score": 30})

    return score, factors


def classify_risk(score: int) -> str:
    if score >= 100: return "CRITICO"
    if score >= 50:  return "ALTO"
    if score >= 20:  return "MEDIO"
    return "BAIXO"


def check_regulatory_constraints(data: dict) -> list[dict]:
    violations = []
    frameworks = [f.upper().replace(" ", "") for f in data.get("framework", [])]

    if not data.get("mfa_enabled", True):
        if "SOX" in frameworks:
            violations.append({"constraint": "C1", "framework": "SOX",
                "motivo": "MFA obrigatório para acesso privilegiado (SOX)"})
        if "ISO27001" in frameworks:
            violations.append({"constraint": "C2", "framework": "ISO27001",
                "motivo": "autenticação forte obrigatória para acesso crítico (ISO 27001)"})
        if "PCIDSS" in frameworks:
            violations.append({"constraint": "C3", "framework": "PCI DSS",
                "motivo": "MFA obrigatório para acesso administrativo a ambientes de dados de cartão (PCI DSS)"})

    return violations


def validate_maturity(level: str) -> str:
    normalized = (level or "MEDIUM").strip().upper()
    return normalized if normalized in MATURITY_LEVELS else "MEDIUM"


def apply_maturity(risk_score: int, maturity_level: str, current_decision: str, path: list):
    if maturity_level == "HIGH" and risk_score >= 50:
        if current_decision in ("ALLOW", "ALLOW_WITH_RESTRICTION"):
            path.append("maturidade_high_aplicada")
            return "BLOCK_OR_ENFORCE_MFA", "restrita", "escalamento_de_risco"

    if maturity_level == "MEDIUM" and risk_score >= 100:
        if current_decision == "ALLOW_WITH_RESTRICTION":
            path.append("maturidade_medium_aplicada")
            return "REQUIRE_ACTION", "condicionada", "exigencia_de_mitigacao"

    return current_decision, None, None


def decide(data: dict) -> dict:
    path = ["risco_calculado"]

    maturity_level      = validate_maturity(data.get("maturity_level", "MEDIUM"))
    risk_score, factors = calculate_risk(data)
    risk_classification = classify_risk(risk_score)
    violations          = check_regulatory_constraints(data)
    maturity_influence  = None

    if violations:
        path += ["constraint_detectada", "zona_restrita_aplicada", "decisao_gerada"]
        decision = "BLOCK_OR_ENFORCE_MFA"
        decision_basis = "restricao_regulatoria"
        applied_zone = "restrita"

    elif risk_score >= 100:
        path += ["risco_critico_detectado", "zona_condicionada_aplicada"]
        decision = "REQUIRE_ACTION"
        decision_basis = "score_de_risco"
        applied_zone = "condicionada"
        _, zone_override, influence = apply_maturity(risk_score, maturity_level, decision, path)
        if zone_override:
            applied_zone = zone_override
            maturity_influence = influence
            decision_basis = "maturidade_organizacional"
        path.append("decisao_gerada")

    elif risk_score >= 50:
        path += ["risco_alto_detectado", "zona_dinamica_aplicada"]
        decision = "ALLOW_WITH_RESTRICTION"
        decision_basis = "score_de_risco"
        applied_zone = "dinamica"
        decision_upd, zone_override, influence = apply_maturity(risk_score, maturity_level, decision, path)
        if zone_override:
            decision = decision_upd
            applied_zone = zone_override
            maturity_influence = influence
            decision_basis = "maturidade_organizacional"
        path.append("decisao_gerada")

    else:
        path += ["risco_baixo_detectado", "zona_dinamica_aplicada"]
        decision = "ALLOW"
        decision_basis = "score_de_risco"
        applied_zone = "dinamica"
        decision_upd, zone_override, influence = apply_maturity(risk_score, maturity_level, decision, path)
        if zone_override:
            decision = decision_upd
            applied_zone = zone_override
            maturity_influence = influence
            decision_basis = "maturidade_organizacional"
        path.append("decisao_gerada")

    return {
        "event_id"              : f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp"             : datetime.now(timezone.utc).isoformat(),
        "model_version"         : MODEL_VERSION,
        "rule_version"          : RULE_VERSION,
        "user"                  : data.get("user"),
        "recurso_alvo"          : data.get("target_resource", "nao_especificado"),
        "ambiente"              : data.get("environment"),
        "frameworks_declarados" : data.get("framework", []),
        "maturity_level"        : maturity_level,
        "risk_score"            : risk_score,
        "risk_classification"   : risk_classification,
        "risk_factors"          : factors,
        "regulatory_violations" : violations,
        "decision"              : decision,
        "decision_basis"        : decision_basis,
        "applied_zone"          : applied_zone,
        "maturity_influence"    : maturity_influence,
        "decision_path"         : path,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            input_data = json.load(f)
        print(json.dumps(decide(input_data), indent=2, ensure_ascii=False))
    else:
        print("Uso: python decision_engine.py <input.json>")
        print("     Veja examples/ para exemplos de entrada.")
