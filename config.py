"""
Configuração centralizada do BTCFaucet
Carrega variáveis do .env ANTES de qualquer outro import
"""
import os
from dotenv import load_dotenv

# ── CRÍTICO: Carregar .env ANTES de tudo ─────────────────────────────────────
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# ── LNbits ────────────────────────────────────────────────────────────────────
LNBITS_URL = os.getenv("LNBITS_URL", "http://localhost:5000")
LNBITS_ADMIN_KEY = os.getenv("LNBITS_ADMIN_KEY", "")

# ── Phoenixd ──────────────────────────────────────────────────────────────────
PHOENIXD_URL = os.getenv("PHOENIXD_URL", "http://127.0.0.1:9740")
PHOENIXD_PASSWORD = os.getenv("PHOENIXD_PASSWORD", "")
PHOENIX_MAX_FEE_SAT = int(os.getenv("PHOENIX_MAX_FEE_SAT", "20"))

# ── Spark (carteira dedicada, via sidecar Node em spark-sidecar/) ─────────────
# Desligado por padrão — pagamentos continuam via LNbits até o wallet Spark
# ser fundado e testado com um pagamento real. Ver SPARK_FAUCET_WALLET_* pro
# mnemonic/passphrase (usados só pelo sidecar, main.py nunca lê os segredos
# da carteira diretamente — só fala HTTP com o sidecar).
SPARK_PAYOUTS_ENABLED = os.getenv("SPARK_PAYOUTS_ENABLED", "false").lower() == "true"
SPARK_SIDECAR_URL = os.getenv("SPARK_SIDECAR_URL", "http://127.0.0.1:8791")
SPARK_SIDECAR_TOKEN = os.getenv("SPARK_SIDECAR_TOKEN", "")
SPARK_MAX_FEE_SAT = int(os.getenv("SPARK_MAX_FEE_SAT", "10"))

# ── LN Address pública (LNURLp) pra RECEBER na carteira Spark ─────────────────
# Feature independente do SPARK_PAYOUTS_ENABLED: só recebe (sem risco de
# double-spend/dreno de carteira), então liga separado — não precisa esperar
# o cutover de pagamentos pra já dar pra fundar a carteira via LN Address.
LN_ADDRESS_ENABLED = os.getenv("LN_ADDRESS_ENABLED", "false").lower() == "true"
LN_ADDRESS_USERS = {u.strip().lower() for u in os.getenv("LN_ADDRESS_USERS", "doar,donate").split(",") if u.strip()}
LN_ADDRESS_MIN_SATS = int(os.getenv("LN_ADDRESS_MIN_SATS", "1"))
LN_ADDRESS_MAX_SATS = int(os.getenv("LN_ADDRESS_MAX_SATS", "1000000"))

# ── hCaptcha ──────────────────────────────────────────────────────────────────
HCAPTCHA_SECRET = os.getenv("HCAPTCHA_SECRET", "")
HCAPTCHA_SITEKEY = os.getenv("HCAPTCHA_SITEKEY", "")

# ── Anti-bot (assina PoW + token do /api/claim/fallback) ──────────────────────
# [FIX] Antes vivia só em main.py com um fallback hardcoded fraco
# ("bitcoinfaucet_secret_key_32chars!") se a env var estivesse ausente —
# um redeploy/clone sem .env voltava silenciosamente pra esse segredo
# público. Agora é obrigatório (ver validação no final deste arquivo).
BANNER_SECRET = os.getenv("BANNER_SECRET", "")

# ── Faucet Settings ───────────────────────────────────────────────────────────
FAUCET_AMOUNT_SAT = int(os.getenv("FAUCET_AMOUNT_SAT", "1"))
COOLDOWN_HOURS = int(os.getenv("COOLDOWN_HOURS", "24"))
IP_COOLDOWN_HOURS = int(os.getenv("IP_COOLDOWN_HOURS", "24"))
FP_COOLDOWN_HOURS = int(os.getenv("FP_COOLDOWN_HOURS", "24"))
SUBNET_LIMIT = int(os.getenv("SUBNET_LIMIT", "1"))
FP_LIMIT = int(os.getenv("FP_LIMIT", "1"))

# ── Progressive Rewards ───────────────────────────────────────────────────────
PROGRESSIVE_REWARDS = os.getenv("PROGRESSIVE_REWARDS", "true").lower() == "true"
REWARD_TIER_1 = int(os.getenv("REWARD_TIER_1", "1"))
REWARD_TIER_2 = int(os.getenv("REWARD_TIER_2", "12"))
REWARD_TIER_3 = int(os.getenv("REWARD_TIER_3", "21"))

# ── Fingerprint Settings ──────────────────────────────────────────────────────
FP_MIN_AGE_MINUTES = int(os.getenv("FP_MIN_AGE_MINUTES", "10"))
FP_BLOCK_STRICT = os.getenv("FP_BLOCK_STRICT", "false").lower() == "true"

# ── Database ──────────────────────────────────────────────────────────────────
DB_PATH = os.getenv("DB_PATH", "faucet.db")

# ── Whitelists ────────────────────────────────────────────────────────────────
WHITELIST_RAW = os.getenv("WHITELIST_ADDRESSES", "")
WHITELIST = {a.strip().lower() for a in WHITELIST_RAW.split(",") if a.strip()}

WHITELIST_ADM_RAW = os.getenv("WHITELIST_ADM", "")
WHITELIST_ADM = {a.strip().lower() for a in WHITELIST_ADM_RAW.split(",") if a.strip()}

# ── Suspect Domains ───────────────────────────────────────────────────────────
SUSPECT_DOMAINS_RAW = os.getenv("SUSPECT_DOMAINS", "walletofsatoshi.com,sats.mobi")
SUSPECT_DOMAINS = {d.strip().lower() for d in SUSPECT_DOMAINS_RAW.split(",") if d.strip()}

# ── Telegram Bot 1 (Admin/Commands) ───────────────────────────────────────────
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
TELEGRAM_ENABLED = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)

# ── Telegram Admin allowlist (user IDs autorizados a executar comandos) ───────
# Sem isto, qualquer membro do grupo TELEGRAM_CHAT_ID controla o serviço.
# Descubra seu ID enviando /whoami ao bot. Múltiplos IDs separados por vírgula.
TELEGRAM_ADMIN_IDS_RAW = os.getenv("TELEGRAM_ADMIN_IDS", "")
TELEGRAM_ADMIN_IDS = {i.strip() for i in TELEGRAM_ADMIN_IDS_RAW.split(",") if i.strip()}

# ── Telegram Bot 2 (Status Monitor) ───────────────────────────────────────────
TELEGRAM_BOT2_TOKEN = os.getenv("TELEGRAM_BOT2_TOKEN", "")
TELEGRAM_BOT2_ENABLED = bool(TELEGRAM_BOT2_TOKEN)

# ── Service Control ───────────────────────────────────────────────────────────
SERVICE_NAME = os.getenv("SERVICE_NAME", "ln-faucet")
SUDO_PASS = os.getenv("SUDO_PASS", "")

# ── Security ──────────────────────────────────────────────────────────────────
ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "https://bitcoinfaucet.st")

# ── Função para recarregar whitelists (sem restart) ───────────────────────────
def reload_whitelist():
    """Recarrega whitelists do .env sem reiniciar o serviço"""
    global WHITELIST, WHITELIST_ADM
    load_dotenv(override=True)
    
    WHITELIST_RAW = os.getenv("WHITELIST_ADDRESSES", "")
    WHITELIST = {a.strip().lower() for a in WHITELIST_RAW.split(",") if a.strip()}
    
    WHITELIST_ADM_RAW = os.getenv("WHITELIST_ADM", "")
    WHITELIST_ADM = {a.strip().lower() for a in WHITELIST_ADM_RAW.split(",") if a.strip()}
    
    return len(WHITELIST), len(WHITELIST_ADM)

# ── Telegram Admin ID (Bot 2 Monitor) ─────────────────────────────────────────
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

# ── Faucet URL ────────────────────────────────────────────────────────────────
FAUCET_URL = os.getenv("FAUCET_URL", "https://bitcoinfaucet.st")
SITE_URL = os.getenv("SITE_URL", "https://bitcoinfaucet.st")

# ── Validação fail-fast ────────────────────────────────────────────────────────
# [FIX] Antes, segredos ausentes (.env incompleto) deixavam o serviço subir
# "saudável" e só falhar nas primeiras requisições reais (hCaptcha sempre
# rejeitando, LNbits 401) — foi exatamente o tipo de causa por trás do bug
# de limite de token do captcha já visto neste projeto. Falha no boot, com
# mensagem clara, em vez de falhar silenciosamente em produção depois.
_REQUIRED_SECRETS = {
    "LNBITS_ADMIN_KEY": LNBITS_ADMIN_KEY,
    "HCAPTCHA_SECRET": HCAPTCHA_SECRET,
    "BANNER_SECRET": BANNER_SECRET,
}
_missing = [name for name, value in _REQUIRED_SECRETS.items() if not value]
if _missing:
    raise RuntimeError(
        f"Variáveis de ambiente obrigatórias ausentes no .env: {', '.join(_missing)}. "
        f"Veja .env.example."
    )

# [FIX] Secret de teste oficial do hCaptcha (sempre aprova qualquer token) —
# se ficar configurado em produção por engano (cópia de ambiente de staging,
# etc.), toda a validação de captcha é pulada silenciosamente. Falha o boot
# por padrão — só segue com ALLOW_TEST_HCAPTCHA=true (ambiente de teste real).
if HCAPTCHA_SECRET == "0x0000000000000000000000000000000000000000":
    if os.getenv("ALLOW_TEST_HCAPTCHA", "false").lower() != "true":
        raise RuntimeError(
            "HCAPTCHA_SECRET está com o valor de TESTE oficial do hCaptcha — "
            "captcha seria aprovado sem verificação real. Troque HCAPTCHA_SECRET, "
            "ou defina ALLOW_TEST_HCAPTCHA=true no .env se isto for intencional "
            "(ambiente de teste)."
        )
    import logging as _logging
    _logging.getLogger("faucet").critical(
        "HCAPTCHA_SECRET está com o valor de TESTE oficial do hCaptcha — "
        "captcha está sendo aprovado sem verificação real (ALLOW_TEST_HCAPTCHA=true)."
    )

if (SPARK_PAYOUTS_ENABLED or LN_ADDRESS_ENABLED) and not SPARK_SIDECAR_TOKEN:
    raise RuntimeError(
        "SPARK_PAYOUTS_ENABLED ou LN_ADDRESS_ENABLED=true mas SPARK_SIDECAR_TOKEN "
        "não configurado — sem o token o main.py não consegue autenticar no sidecar Spark."
    )
