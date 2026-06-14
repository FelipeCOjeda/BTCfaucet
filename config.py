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

# ── hCaptcha ──────────────────────────────────────────────────────────────────
HCAPTCHA_SECRET = os.getenv("HCAPTCHA_SECRET", "")
HCAPTCHA_SITEKEY = os.getenv("HCAPTCHA_SITEKEY", "")

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
