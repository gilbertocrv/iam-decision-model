"""
Motor de Decisão IAM Adaptativo ao Risco
=========================================
Fórmula central:
  Decisão = f(risco, regra_de_negócio, maturidade, restrição_regulatória)

Ordem de prioridade
-------------------
  1. restrição_regulatória  — domina, não pode ser relaxada
  2. maturidade             — eleva exigência conforme capacidade operacional
  3. score_de_risco         — define zona dinâmica e condicionada

Zonas de decisão
----------------
  restrita     — restrição regulatória OU maturidade HIGH com risco elevado
  condicionada — risco crítico sem violação regulatória
  dinâmica     — demais casos

Valores de decision_basis
-------------------------
  restricao_regulatoria   — constraint de framework ativada
  maturidade_organizacional — maturidade HIGH ou MEDIUM interveio
  score_de_risco          — apenas o score determinou a decisão
"""

from datetime import datetime, timezone
import json
import uuid

from config import (
    MODEL_VERSION, RULE_VERSION,
    RISK_THRESHOLD_CRITICO, RISK_THRESHOLD_ALTO, RISK_THRESHOLD_MEDIO,
    PESO_R1_PAPEL_PRIVILEGIADO, PESO_R2_SEM_MFA,
    PESO_R3_INATIVIDADE, PESO_R4_PRODUCAO, INATIVIDADE_LIMITE_DIAS,
    MATURIDADE_HIGH_LIMIAR, MATURIDADE_MEDIUM_LIMIAR,
    BASIS_RESTRICAO_REGULATORIA, BASIS_MATURIDADE, BASIS_SCORE_DE_RISCO,
    PAPEIS_PRIVILEGIADOS,
)


# ─── Risco ────────────────────────────────────────────────────────────────────

def eh_privilegiado(papel: str) -> bool:
    """Verifica se o papel está na lista de papéis privilegiados conhecidos."""
    return papel.strip().lower() in PAPEIS_PRIVILEGIADOS


def calcular_risco(dados: dict) -> tuple[int, list[dict]]:
    """
    Aplica as regras de risco determinísticas.
    Retorna (score_total, fatores_ativados).
    """
    score   = 0
    fatores = []

    if eh_privilegiado(dados.get("role", "")):
        score += PESO_R1_PAPEL_PRIVILEGIADO
        fatores.append({"regra": "R1", "motivo": "papel privilegiado", "score": PESO_R1_PAPEL_PRIVILEGIADO})

    if not dados.get("mfa_enabled", True):
        score += PESO_R2_SEM_MFA
        fatores.append({"regra": "R2", "motivo": "MFA desabilitado", "score": PESO_R2_SEM_MFA})

    dias_inativo = dados.get("last_login_days", 0)
    if dias_inativo > INATIVIDADE_LIMITE_DIAS:
        score += PESO_R3_INATIVIDADE
        fatores.append({"regra": "R3", "motivo": f"inativo há {dias_inativo} dias", "score": PESO_R3_INATIVIDADE})

    if dados.get("environment") in ("production", "producao"):
        score += PESO_R4_PRODUCAO
        fatores.append({"regra": "R4", "motivo": "ambiente de produção", "score": PESO_R4_PRODUCAO})

    return score, fatores


def classificar_risco(score: int) -> str:
    if score >= RISK_THRESHOLD_CRITICO: return "CRITICO"
    if score >= RISK_THRESHOLD_ALTO:    return "ALTO"
    if score >= RISK_THRESHOLD_MEDIO:   return "MEDIO"
    return "BAIXO"


# ─── Restrições regulatórias ─────────────────────────────────────────────────

def verificar_constraints(dados: dict) -> list[dict]:
    """
    Verifica restrições rígidas de frameworks regulatórios.
    Violações não podem ser relaxadas por score de risco ou nível de maturidade.

    C1 (SOX)     — MFA obrigatório para acesso privilegiado
    C2 (ISO27001) — autenticação forte para acesso crítico
    C3 (PCI DSS) — MFA obrigatório para acesso a ambientes de dados de cartão
    """
    violacoes  = []
    frameworks = [f.upper().replace(" ", "") for f in dados.get("framework", [])]

    if not dados.get("mfa_enabled", True):
        if "SOX" in frameworks:
            violacoes.append({"constraint": "C1", "framework": "SOX",
                "motivo": "MFA obrigatório para acesso privilegiado (SOX)"})
        if "ISO27001" in frameworks:
            violacoes.append({"constraint": "C2", "framework": "ISO27001",
                "motivo": "autenticação forte obrigatória para acesso crítico (ISO 27001)"})
        if "PCIDSS" in frameworks:
            violacoes.append({"constraint": "C3", "framework": "PCI DSS",
                "motivo": "MFA obrigatório para acesso a ambientes de dados de cartão (PCI DSS)"})

    return violacoes


# ─── Maturidade como input de decisão ────────────────────────────────────────

NIVEIS_MATURIDADE = {"LOW", "MEDIUM", "HIGH"}

def validar_maturidade(nivel: str) -> str:
    """Valida e normaliza o nível de maturidade. Padrão: MEDIUM."""
    normalizado = (nivel or "MEDIUM").strip().upper()
    return normalizado if normalizado in NIVEIS_MATURIDADE else "MEDIUM"


def aplicar_maturidade(score: int, nivel: str, decisao_atual: str, caminho: list):
    """
    Aplica maturidade organizacional como limitador de decisão.

    HIGH   — bloqueia quando score >= MATURIDADE_HIGH_LIMIAR (padrão 50)
    MEDIUM — exige ação quando score >= MATURIDADE_MEDIUM_LIMIAR (padrão 100)
    LOW    — não altera a decisão

    Retorna (decisao, zona_override, influencia) — zona_override é None se sem efeito.
    """
    if nivel == "HIGH" and score >= MATURIDADE_HIGH_LIMIAR:
        if decisao_atual in ("ALLOW", "ALLOW_WITH_RESTRICTION"):
            caminho.append("maturidade_high_aplicada")
            return "BLOCK_OR_ENFORCE_MFA", "restrita", "escalamento_de_risco"

    if nivel == "MEDIUM" and score >= MATURIDADE_MEDIUM_LIMIAR:
        if decisao_atual == "ALLOW_WITH_RESTRICTION":
            caminho.append("maturidade_medium_aplicada")
            return "REQUIRE_ACTION", "condicionada", "exigencia_de_mitigacao"

    return decisao_atual, None, None


# ─── Motor de decisão ─────────────────────────────────────────────────────────

def decidir(dados: dict) -> dict:
    """
    Função central de decisão.

    Produz um decision trace completo respondendo quatro perguntas:
      1. O que aconteceu?        → risk_score, risk_classification, decision
      2. Por que aconteceu?      → risk_factors, regulatory_violations
      3. De onde veio a decisão? → decision_basis
      4. Em que zona do modelo?  → applied_zone, decision_path

    Campos esperados em `dados`
    ---------------------------
    user             str   — identificador do usuário
    role             str   — papel/perfil de acesso
    mfa_enabled      bool  — MFA habilitado
    last_login_days  int   — dias desde o último login
    environment      str   — "production" | "staging" | "dev"
    target_resource  str   — recurso alvo do acesso
    framework        list  — ["SOX", "ISO27001", "PCI DSS", "LGPD"]
    maturity_level   str   — "LOW" | "MEDIUM" | "HIGH"  (padrão: MEDIUM)
    """
    caminho     = ["risco_calculado"]
    maturidade  = validar_maturidade(dados.get("maturity_level", "MEDIUM"))
    score, fatores  = calcular_risco(dados)
    classificacao   = classificar_risco(score)
    violacoes       = verificar_constraints(dados)
    influencia_mat  = None

    # ── 1. Restrição regulatória domina ───────────────────────────────────────
    if violacoes:
        caminho += ["constraint_detectada", "zona_restrita_aplicada", "decisao_gerada"]
        decisao = "BLOCK_OR_ENFORCE_MFA"
        basis   = BASIS_RESTRICAO_REGULATORIA
        zona    = "restrita"

    # ── 2. Risco crítico → zona condicionada ──────────────────────────────────
    elif score >= RISK_THRESHOLD_CRITICO:
        caminho += ["risco_critico_detectado", "zona_condicionada_aplicada"]
        decisao = "REQUIRE_ACTION"
        basis   = BASIS_SCORE_DE_RISCO
        zona    = "condicionada"
        dec_up, zona_up, inf = aplicar_maturidade(score, maturidade, decisao, caminho)
        if zona_up:
            zona = zona_up; influencia_mat = inf; basis = BASIS_MATURIDADE
        caminho.append("decisao_gerada")

    # ── 3. Risco alto → zona dinâmica com restrição ───────────────────────────
    elif score >= RISK_THRESHOLD_ALTO:
        caminho += ["risco_alto_detectado", "zona_dinamica_aplicada"]
        decisao = "ALLOW_WITH_RESTRICTION"
        basis   = BASIS_SCORE_DE_RISCO
        zona    = "dinamica"
        dec_up, zona_up, inf = aplicar_maturidade(score, maturidade, decisao, caminho)
        if zona_up:
            decisao = dec_up; zona = zona_up; influencia_mat = inf; basis = BASIS_MATURIDADE
        caminho.append("decisao_gerada")

    # ── 4. Risco baixo → zona dinâmica, permitir ──────────────────────────────
    else:
        caminho += ["risco_baixo_detectado", "zona_dinamica_aplicada"]
        decisao = "ALLOW"
        basis   = BASIS_SCORE_DE_RISCO
        zona    = "dinamica"
        dec_up, zona_up, inf = aplicar_maturidade(score, maturidade, decisao, caminho)
        if zona_up:
            decisao = dec_up; zona = zona_up; influencia_mat = inf; basis = BASIS_MATURIDADE
        caminho.append("decisao_gerada")

    return {
        "event_id"              : f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp"             : datetime.now(timezone.utc).isoformat(),
        "model_version"         : MODEL_VERSION,
        "rule_version"          : RULE_VERSION,
        "user"                  : dados.get("user"),
        "recurso_alvo"          : dados.get("target_resource", "nao_especificado"),
        "ambiente"              : dados.get("environment"),
        "frameworks_declarados" : dados.get("framework", []),
        "maturity_level"        : maturidade,
        "risk_score"            : score,
        "risk_classification"   : classificacao,
        "risk_factors"          : fatores,
        "regulatory_violations" : violacoes,
        "decision"              : decisao,
        "decision_basis"        : basis,
        "applied_zone"          : zona,
        "maturity_influence"    : influencia_mat,
        "decision_path"         : caminho,
    }


# Alias em inglês para compatibilidade com testes e batch existentes
decide = decidir


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            entrada = json.load(f)
        print(json.dumps(decidir(entrada), indent=2, ensure_ascii=False))
    else:
        print("Uso: python decision_engine.py <entrada.json>")
        print("     Veja examples/ para exemplos de entrada.")
