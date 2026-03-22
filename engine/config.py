"""
Configuração do Motor de Decisão IAM
--------------------------------------
Centraliza thresholds, pesos de risco e níveis de maturidade.
Alterar aqui aplica automaticamente a todo o engine.
"""

# ─── Versão ───────────────────────────────────────────────────────────────────

MODEL_VERSION = "0.3.0"
RULE_VERSION  = "1.1.0"

# ─── Thresholds de score de risco ─────────────────────────────────────────────

RISK_THRESHOLD_CRITICO = 100   # score >= 100 → CRÍTICO
RISK_THRESHOLD_ALTO    = 50    # score >= 50  → ALTO
RISK_THRESHOLD_MEDIO   = 20    # score >= 20  → MÉDIO
                               # score < 20   → BAIXO

# ─── Pesos das regras de risco ────────────────────────────────────────────────

PESO_R1_PAPEL_PRIVILEGIADO  = 50   # papel privilegiado
PESO_R2_SEM_MFA             = 40   # MFA desabilitado
PESO_R3_INATIVIDADE         = 20   # inativo > INATIVIDADE_LIMITE_DIAS
PESO_R4_PRODUCAO            = 30   # ambiente de produção

INATIVIDADE_LIMITE_DIAS     = 30   # dias sem login para ativar R3

# ─── Thresholds de maturidade (relatório) ────────────────────────────────────
# Calculados sobre o percentual de decisões "fora da tolerância"
# (risk_classification == CRITICO ou decision == BLOCK/REQUIRE_ACTION)

MATURIDADE_THRESHOLD_CRITICO   = 0.40   # > 40% fora da tolerância → CRÍTICO
MATURIDADE_THRESHOLD_INSTAVEL  = 0.20   # > 20% fora da tolerância → INSTÁVEL
                                         # <= 20%                   → ESTÁVEL

# ─── Limites de maturidade como input de decisão ─────────────────────────────
# Definem em que score de risco cada nível de maturidade intervém

MATURIDADE_HIGH_LIMIAR   = 50    # HIGH bloqueia quando risk_score >= este valor
MATURIDADE_MEDIUM_LIMIAR = 100   # MEDIUM exige ação quando risk_score >= este valor

# ─── Nomenclatura padronizada de decision_basis ───────────────────────────────

BASIS_RESTRICAO_REGULATORIA  = "restricao_regulatoria"
BASIS_MATURIDADE             = "maturidade_organizacional"
BASIS_SCORE_DE_RISCO         = "score_de_risco"

# ─── Papéis privilegiados reconhecidos ───────────────────────────────────────

PAPEIS_PRIVILEGIADOS = {
    "global admin", "db admin", "read admin", "system admin",
    "cloud admin", "security admin", "network admin", "domain admin",
    "root", "superuser", "sysadmin", "administrator",
}
