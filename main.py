import os
import re
import asyncio
import hmac
import hashlib
import logging
import sqlite3
import ipaddress
import httpx
import time as _time
from datetime import datetime, timedelta
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager, contextmanager
from typing import Optional

# ── CRÍTICO: Importar config como módulo (variáveis mutáveis acessadas via config.X) ──
import config
from config import (
    LNBITS_URL, LNBITS_ADMIN_KEY, HCAPTCHA_SECRET, HCAPTCHA_SITEKEY,
    FAUCET_AMOUNT_SAT, COOLDOWN_HOURS, IP_COOLDOWN_HOURS, FP_COOLDOWN_HOURS,
    SUBNET_LIMIT, FP_LIMIT, PROGRESSIVE_REWARDS,
    REWARD_TIER_1, REWARD_TIER_2, REWARD_TIER_3,
    FP_MIN_AGE_MINUTES, FP_BLOCK_STRICT,
    DB_PATH, SUSPECT_DOMAINS,
    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_ENABLED,
    SERVICE_NAME, SUDO_PASS, ALLOWED_ORIGIN,
)

from telegram_bot import run_monitor, send_alert, poll_commands

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("faucet")

# ── Config ────────────────────────────────────────────────────────────────────
# WHITELIST_ADM     → ignora cooldowns + todos os bloqueios (admin/teste)
# WHITELIST         → ignora bloqueios mas respeita cooldowns

# ── Reward Progressivo (Anti-Farm) ────────────────────────────────────────────
# Sistema de recompensa crescente incentiva usuários legítimos e penaliza farms
# FP_BLOCK_STRICT=true  → FP nunca visto = bloqueado imediatamente (anti-bot agressivo)
# FP_BLOCK_STRICT=false → FP nunca visto = permite 1ª tentativa (amigável a troca de device)
#                          Bloqueia se mesmo FP tentar 2+ vezes em 5min sem nunca pagar

# ── CGNAT ─────────────────────────────────────────────────────────────────────
# Para IPs CGNAT, cooldown por IP é desabilitado — múltiplos usuários legítimos
# compartilham o mesmo IP público. Proteção recai sobre LN address + fingerprint.
CGNAT_SUBNETS = [
    ipaddress.ip_network("100.64.0.0/10"),  # RFC 6598 — CGNAT oficial das operadoras
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# ── ASN + hextet blocklist (farm móvel IPv6) ──────────────────────────────────
BLOCKED_ASN_HEXTETS: set[tuple[str, str]] = {
    ("28573", "18ab"),  # Claro NXT BR — farm móvel identificado
    ("22085", "18ab"),  # Claro S/A
    ("26599", "18ab"),  # Telefônica BR
}

def is_blocked_asn_hextet(ip: str, asn: Optional[str]) -> bool:
    """Bloqueia clusters móveis por ASN + hextet recorrente."""
    if not asn:
        return False
    hextet = get_ipv6_hextet(ip)
    if not hextet:
        return False
    return (asn, hextet) in BLOCKED_ASN_HEXTETS


def is_cgnat_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return False
        return any(addr in net for net in CGNAT_SUBNETS)
    except ValueError:
        return False

# ── In-memory rate limiter para endpoints públicos ────────────────────────────
_rate_store: dict[str, list[float]] = {}
_rate_lock = asyncio.Lock()

def get_client_ip(request: Request) -> str:
    """Extrai IP real do cliente via Cloudflare ou X-Forwarded-For."""
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def get_ja3(request: Request) -> str:
    """Extrai JA3 fingerprint do header Cloudflare (se disponível)."""
    return request.headers.get("CF-ray", "")[:16]

def get_fp(request: Request) -> Optional[str]:
    """Extrai fp_hash do header customizado (legado)."""
    return request.headers.get("X-FP-Hash")

def is_dynamically_blocked(ip: str, fp: Optional[str], ln: str) -> bool:
    """Verifica se IP, FP ou LN address estão na blacklist dinâmica do DB."""
    with get_db() as conn:
        if ip:
            row = conn.execute(
                "SELECT 1 FROM blocked_entities WHERE entity_type='ip' AND entity_value=? LIMIT 1",
                (ip,)
            ).fetchone()
            if row:
                return True
        if fp:
            row = conn.execute(
                "SELECT 1 FROM blocked_entities WHERE entity_type='fp' AND entity_value=? LIMIT 1",
                (fp,)
            ).fetchone()
            if row:
                return True
        if ln:
            row = conn.execute(
                "SELECT 1 FROM blocked_entities WHERE entity_type='ln' AND entity_value=? LIMIT 1",
                (ln.lower(),)
            ).fetchone()
            if row:
                return True
    return False

def midnight_today() -> datetime:
    """Retorna datetime de hoje à meia-noite (00:00:00 UTC)."""
    now = datetime.utcnow()
    return now.replace(hour=0, minute=0, second=0, microsecond=0)

def seconds_until_midnight() -> int:
    """Segundos restantes até a próxima meia-noite UTC."""
    now = datetime.utcnow()
    tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int((tomorrow - now).total_seconds())


# ── Bolt11 decoder com coincurve — extrai node pubkey real ──────────────────
_BOLT11_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

def _bolt11_bech32_decode(bech: str):
    """Decodifica bech32 retornando (hrp, data_5bit)."""
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1:
        return None, None
    hrp = bech[:pos]
    try:
        data = [_BOLT11_CHARSET.index(x) for x in bech[pos+1:]]
    except ValueError:
        return None, None
    return hrp, data[:-6]  # remove checksum

def _bolt11_convertbits(data, frombits, tobits, pad=True):
    """Converte entre representações de bits."""
    acc = 0; bits = 0; ret = []; maxv = (1 << tobits) - 1
    for value in data:
        acc = ((acc << frombits) | value) & 0xFFFFFF
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret

def decode_bolt11_pubkey(bolt11: str) -> str:
    """
    Extrai o node pubkey de destino de um bolt11 usando coincurve.
    
    Estratégia:
    1. Verificar campo 'n' (tag=19) — pubkey explícito (presente em alguns wallets)
    2. Recuperar via ECDSA recovery da assinatura (funciona com qualquer bolt11)
    
    Retorna hex do pubkey comprimido (66 chars) ou '' se falhar.
    """
    try:
        hrp, data5 = _bolt11_bech32_decode(bolt11.lower())
        if not hrp or not data5 or len(data5) < 110:
            return ""

        # ── Estratégia 1: campo 'n' (tag=19) ─────────────────────────────────
        i = 7  # pular timestamp (7 grupos de 5-bit)
        while i < len(data5) - 104:
            if i + 2 >= len(data5) - 104:
                break
            tag = data5[i]
            dlen = (data5[i+1] << 5) | data5[i+2]
            i += 3
            if i + dlen > len(data5) - 104:
                break
            if tag == 19 and dlen == 53:  # 'n' = node pubkey
                pk_bytes = _bolt11_convertbits(data5[i:i+dlen], 5, 8, False)
                if pk_bytes and len(pk_bytes) == 33:
                    return bytes(pk_bytes).hex()
            i += dlen

        # ── Estratégia 2: ECDSA recovery via coincurve ───────────────────────
        try:
            import coincurve
        except ImportError:
            logger.warning("coincurve não instalado — pubkey recovery indisponível")
            return ""

        # Assinatura: últimos 104 grupos de 5-bit = 65 bytes (64 sig + 1 recovery)
        sig_data5 = data5[-104:]
        sig_bytes = _bolt11_convertbits(sig_data5, 5, 8, False)
        if not sig_bytes or len(sig_bytes) < 65:
            return ""

        recovery_flag = sig_bytes[64] & 0x03
        sig_der = bytes(sig_bytes[:64])

        # Mensagem assinada = SHA256(SHA256(hrp_bytes + data_bytes_sem_sig))
        hrp_bytes = hrp.encode('ascii')
        # Converter data sem assinatura para bytes
        data_no_sig = data5[:-104]
        data_bytes = bytes(_bolt11_convertbits(data_no_sig, 5, 8, False) or [])
        
        import hashlib
        msg_preimage = hrp_bytes + data_bytes
        msg_hash = hashlib.sha256(hashlib.sha256(msg_preimage).digest()).digest()

        # Recuperar pubkey
        try:
            pubkey = coincurve.PublicKey.from_signature_and_message(
                sig_der + bytes([recovery_flag]),
                msg_hash,
                hasher=None  # já fizemos o hash manualmente
            )
            return pubkey.format(compressed=True).hex()
        except Exception as e:
            logger.debug(f"coincurve recovery falhou: {e}")
            return ""

    except Exception as e:
        logger.debug(f"decode_bolt11_pubkey error: {e}")
        return ""

# ─────────────────────────────────────────────────────────────────────────────

# ── IP helpers ────────────────────────────────────────────────────────────────
def get_cf_asn(request: Request) -> str:
    return request.headers.get("CF-IPCountry", "") + ":" + request.headers.get("CF-ray", "")[:8]

def get_ipv6_hextet(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 6:
            return format(addr).split(":")[-1]
    except Exception:
        pass
    return ""

def normalize_ip_prefix(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    except Exception:
        return ip


def get_broad_prefix(ip: str) -> str:
    """
    Retorna prefixo amplo para detecção de farms:
    IPv4 → /24
    IPv6 → /40 (sweet spot: captura farms que rotacionam /48 e /64,
                 sem afetar clientes diferentes do mesmo ISP /32)
    Como a penalidade é apenas decay para 1 sat (não bloqueia),
    falsos positivos são aceitáveis.
    """
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        return str(ipaddress.ip_network(f"{ip}/40", strict=False))
    except Exception:
        return ip

# ── Banner / CSS Token ────────────────────────────────────────────────────────

BANNER_SECRET        = os.getenv("BANNER_SECRET", "bitcoinfaucet_secret_key_32chars!")
BANNER_TOKEN_MIN_AGE = 10
BANNER_TOKEN_MAX_AGE = 900  # 15 minutos



def verify_pow(seed: str, nonce: int, difficulty: int = 4) -> bool:
    if not seed or nonce is None or nonce < 0 or nonce > 10_000_000:
        return False
    return hashlib.sha256(f"{seed}:{nonce}".encode()).hexdigest().startswith("0" * difficulty)

# ── Desafio Anti-Bot ──────────────────────────────────────────────────────────
CHALLENGE_PHRASES = {
    "bitcoin é liberdade","sats para todos","eu sou humano","chave sua bitcoin",
    "não confie verifique","lightning é rápido","sem banco sem fronteira",
    "compre bitcoin","hold your keys","descentralize já","bitcoin é dinheiro",
    "21 milhões de btc","satoshi nakamoto","faucet bitcoin","receba sats grátis",
    "bitcoin para todos","sem inflação","código é lei","run your node",
    "peer to peer","abra sua wallet","bitcoin é neutro","sem intermediários",
    "sua chave sua moeda","bitcoin não dorme","sats são frações",
    "lightning network","bitcoin é escasso","mineradores validam",
    "blocos de bitcoin","transação confirmada","endereço lightning",
    "bitcoin é global","sem fronteiras","pague com sats","hodl significa segurar",
    "bitcoin é aberto","sem censura possível","carteira de bitcoin",
    "bitcoin é seguro","chave privada sagrada","multisig protege",
    "bitcoin é imutável","consenso distribuído","hash rate alto",
    "dificuldade ajustável","bloco genesis","halving bitcoin",
    "recompensa de bloco","tx sem permissão","bitcoin é livre",
    "nós verificam tudo","sem ponto central","proof of work",
    "bitcoin é honesto","satoshi inventou","eu uso bitcoin",
    "sats toda hora","acumule sats","bitcoin cresce","valor digital",
    "dinheiro do povo","bitcoin resiste","rede incensurável","código aberto",
    "bitcoin é raro","moeda digital","fora do sistema","bitcoin sem banco",
    "seu próprio banco","verifica por ti","sem permissão","descentralizado sim",
    "rede bitcoin vive","hashpower global","nó completo sempre",
    "bitcoin é justo","todos podem usar","sem inflação aqui","limite de 21mi",
    "satoshi é anônimo","bitcoin é paz","sats na carteira","receba agora",
    "bitcoin real","dinheiro soberano","tx é irreversível","bloco confirmado",
    "rede p2p global","bitcoin é ouro","digital e escasso","use sua wallet",
    "sats são divisíveis","bitcoin não para","mineração prova","hash é seguro",
    "livre e aberto","bitcoin é futuro","eu amo bitcoin",
}

# ── Cooldowns ─────────────────────────────────────────────────────────────────
def is_address_blocked(ln_address: str) -> tuple[bool, int]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT claimed_at FROM claims WHERE ln_address=? AND status='paid' ORDER BY claimed_at DESC LIMIT 1",
            (ln_address.lower(),)
        ).fetchone()
    if not row:
        return False, 0
    last = datetime.fromisoformat(row["claimed_at"])
    if last >= midnight_today():
        return True, seconds_until_midnight()
    return False, 0

def is_ip_blocked(ip: str) -> tuple[bool, int]:
    if is_cgnat_ip(ip):
        return False, 0
    prefix = normalize_ip_prefix(ip)
    if not prefix:
        return False, 0
    with get_db() as conn:
        row = conn.execute(
            "SELECT claimed_at FROM claims WHERE ip_prefix=? AND status='paid' ORDER BY claimed_at DESC LIMIT 1",
            (prefix,)
        ).fetchone()
    if not row:
        return False, 0
    last = datetime.fromisoformat(row["claimed_at"])
    if last >= midnight_today():
        return True, seconds_until_midnight()
    return False, 0

def is_subnet_blocked(ip: str) -> tuple[bool, int]:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            like_pattern = ".".join(str(addr).split(".")[:3]) + ".%"
        else:
            like_pattern = ":".join(format(addr).split(":")[:4]) + "%"
    except Exception:
        return False, 0
    since = midnight_today().isoformat()
    with get_db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM claims WHERE ip_address LIKE ? AND status='paid' AND claimed_at > ?",
            (like_pattern, since)
        ).fetchone()[0]
    if count >= SUBNET_LIMIT:
        return True, seconds_until_midnight()
    return False, 0

# ── FP checks ─────────────────────────────────────────────────────────────────

def is_fp_blocked(fp_hash: str) -> tuple[bool, int]:
    if not fp_hash:
        return False, 0
    since = midnight_today().isoformat()
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) as c FROM claims WHERE fp_hash=? AND status='paid' AND claimed_at>?",
            (fp_hash, since)
        ).fetchone()
    if not row or row["c"] == 0:
        return False, 0
    if row["c"] >= FP_LIMIT:
        return True, seconds_until_midnight()
    return False, 0

def is_fp_too_new(fp_hash: Optional[str], ip: str, ln: str) -> bool:
    if not fp_hash or FP_MIN_AGE_MINUTES == 0:
        return False
    with get_db() as conn:
        first_seen = conn.execute(
            "SELECT MIN(claimed_at) FROM claims WHERE fp_hash=?", (fp_hash,)
        ).fetchone()[0]
    if not first_seen:
        if FP_BLOCK_STRICT:
            logger.warning(f"FP recém-criado bloqueado: fp={fp_hash[:12]}… age=0min ip={ip} ln={ln}")
            return True
        else:
            since_5min = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
            with get_db() as conn:
                attempts = conn.execute(
                    "SELECT COUNT(*) FROM claims WHERE fp_hash=? AND claimed_at>?",
                    (fp_hash, since_5min)
                ).fetchone()[0]
            if attempts >= 2:
                logger.warning(f"FP multi-tentativa bloqueado: fp={fp_hash[:12]}… ip={ip} ln={ln}")
                return True
            return False
    first_dt = datetime.fromisoformat(first_seen.replace("Z", ""))
    age_minutes = (datetime.utcnow() - first_dt).total_seconds() / 60
    if age_minutes < FP_MIN_AGE_MINUTES:
        logger.warning(f"FP muito novo: fp={fp_hash[:12]}… age={age_minutes:.1f}min ip={ip} ln={ln}")
        return True
    return False

def is_ja3_blocked(ja3: str) -> tuple[bool, int]:
    if not ja3:
        return False, 0
    with get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM blocked_entities WHERE entity_type='ja3' AND entity_value=? LIMIT 1",
            (ja3,)
        ).fetchone()
    return (True, 0) if row else (False, 0)

# ── Node pubkey fingerprint ───────────────────────────────────────────────────
def is_node_blocked(pubkey: str) -> bool:
    """Verifica se node pubkey está bloqueado."""
    if not pubkey:
        return False
    with get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM node_blacklist WHERE pubkey=? LIMIT 1", (pubkey,)
        ).fetchone()
    return bool(row)

def check_node_fingerprint(pubkey: str, ln_address: str) -> tuple[bool, str]:
    """
    Verifica se node pubkey já foi usado com outro LN address.
    Retorna (bloqueado, ln_address_original).
    """
    if not pubkey:
        return False, ""
    with get_db() as conn:
        row = conn.execute(
            """SELECT ln_address FROM claims 
               WHERE destination_pubkey=? AND ln_address!=? AND status='paid'
               LIMIT 1""",
            (pubkey, ln_address.lower())
        ).fetchone()
    if row:
        return True, row["ln_address"]
    return False, ""

def register_node_pubkey(claim_id: int, pubkey: str):
    """Grava destination_pubkey no claim."""
    if not pubkey or not claim_id:
        return
    with get_db() as conn:
        conn.execute(
            "UPDATE claims SET destination_pubkey=? WHERE id=?",
            (pubkey, claim_id)
        )
        conn.commit()

# ─────────────────────────────────────────────────────────────────────────────

# ── Reward progressivo ────────────────────────────────────────────────────────

def get_progressive_reward(ln_address: str) -> int:
    if not PROGRESSIVE_REWARDS:
        return FAUCET_AMOUNT_SAT
    with get_db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM claims WHERE ln_address=? AND status='paid'",
            (ln_address.lower(),)
        ).fetchone()[0]
    if count == 0:
        return REWARD_TIER_1
    elif count == 1:
        return REWARD_TIER_2
    return REWARD_TIER_3


def check_subnet_farm(ip: str, ln_address: str) -> bool:
    """
    Detecta farms por subnet: se o prefixo amplo (/48 IPv6, /24 IPv4)
    já tem 2+ LN addresses DISTINTOS pagos nas últimas 24h, retorna True.
    O usuário atual não é contado (pode ser ele mesmo repetindo).
    """
    try:
        broad = get_broad_prefix(ip)
        with get_db() as conn:
            # Pegar IPs + LN distintos das últimas 24h
            rows = conn.execute("""
                SELECT DISTINCT ip_address, ln_address
                FROM claims
                WHERE status = 'paid'
                AND ln_address != ?
                AND datetime(claimed_at) >= datetime('now', '-24 hours')
            """, (ln_address.lower(),)).fetchall()

        # Filtrar IPs que pertencem ao mesmo broad prefix
        other_lns = set()
        for row in rows:
            try:
                if get_broad_prefix(row[0]) == broad:
                    other_lns.add(row[1].lower())
            except Exception:
                continue

        return len(other_lns) >= 2
    except Exception as e:
        logger.error(f"check_subnet_farm error: {e}")
        return False


def check_fp_farm(fp: str, ln_address: str) -> bool:
    """
    Detecta farms por fingerprint: se o FP já foi usado com outro
    LN address (pago) nas últimas 24h, retorna True.
    """
    if not fp:
        return False
    try:
        with get_db() as conn:
            row = conn.execute("""
                SELECT COUNT(DISTINCT ln_address) as unique_lns
                FROM claims
                WHERE fp_hash = ?
                AND status = 'paid'
                AND ln_address != ?
                AND datetime(claimed_at) >= datetime('now', '-24 hours')
            """, (fp, ln_address.lower())).fetchone()
        return (row["unique_lns"] or 0) >= 1
    except Exception as e:
        logger.error(f"check_fp_farm error: {e}")
        return False

# ─────────────────────────────────────────────────────────────────────────────

def reload_whitelist():
    """Relê WHITELIST do .env e atualiza em memória sem restart."""
    # Atualiza diretamente no módulo config
    try:
        from dotenv import dotenv_values
        env_path = os.getenv("ENV_PATH", "/home/felipe/Bots/BTCfaucet/.env")
        vals = dotenv_values(env_path)
        wl_raw = vals.get("WHITELIST_ADDRESSES", "")
        config.WHITELIST = {a.strip().lower() for a in wl_raw.split(",") if a.strip()}
        adm_raw = vals.get("WHITELIST_ADM", "")
        config.WHITELIST_ADM = {a.strip().lower() for a in adm_raw.split(",") if a.strip()}
        logger.info(f"Whitelist recarregada: {len(config.WHITELIST)} endereços, {len(config.WHITELIST_ADM)} ADM")
    except Exception as e:
        logger.warning(f"reload_whitelist erro: {e}")


async def check_rate_limit(ip: str, max_req: int = 60, window: int = 60) -> bool:
    import time
    now = _time.time()
    async with _rate_lock:
        ts = _rate_store.get(ip, [])
        ts = [t for t in ts if now - t < window]
        if len(ts) >= max_req:
            return False
        ts.append(now)
        _rate_store[ip] = ts
        return True

# ── Claim locks — previne race condition / duplo gasto ────────────────────────
_claim_locks: dict[str, asyncio.Lock] = {}
_claim_locks_ts: dict[str, float] = {}
_claim_registry = asyncio.Lock()

async def acquire_claim_lock(ln: str) -> bool:
    import time
    async with _claim_registry:
        now = _time.time()
        stale = [k for k, t in _claim_locks_ts.items() if now - t > 120]
        for k in stale:
            _claim_locks.pop(k, None)
            _claim_locks_ts.pop(k, None)
        if ln in _claim_locks:
            return False
        lk = asyncio.Lock()
        await lk.acquire()
        _claim_locks[ln] = lk
        _claim_locks_ts[ln] = now
        return True

def release_claim_lock(ln: str):
    lk = _claim_locks.pop(ln, None)
    _claim_locks_ts.pop(ln, None)
    if lk and lk.locked():
        lk.release()

# ── Database ──────────────────────────────────────────────────────────────────
@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS claims (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ln_address   TEXT NOT NULL,
                ip_address   TEXT,
                ip_prefix    TEXT,
                fp_hash      TEXT,
                ja3_hash     TEXT,
                claimed_at   TEXT NOT NULL,
                amount_sat   INTEGER NOT NULL,
                payment_hash TEXT,
                status       TEXT DEFAULT 'pending'
            )
        """)
        for col, typedef in [
            ("ip_prefix",          "TEXT"),
            ("fp_hash",            "TEXT"),
            ("ja3_hash",           "TEXT"),
            ("destination_pubkey", "TEXT"),
        ]:
            try:
                conn.execute(f"ALTER TABLE claims ADD COLUMN {col} {typedef}")
            except Exception:
                pass
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ln_address ON claims(ln_address)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_address ON claims(ip_address)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_prefix  ON claims(ip_prefix)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_fp_hash    ON claims(fp_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ja3_hash   ON claims(ja3_hash)")
        # Tabela de bloqueios dinâmicos
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_entities (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type  TEXT NOT NULL,
                entity_value TEXT NOT NULL,
                reason       TEXT,
                blocked_at   TEXT DEFAULT (datetime('now')),
                UNIQUE(entity_type, entity_value)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_blocked ON blocked_entities(entity_type, entity_value)")
        # Tabela de wallet fingerprints
        conn.execute("""
            CREATE TABLE IF NOT EXISTS wallet_fingerprints (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_hash TEXT NOT NULL,
                ln_address  TEXT NOT NULL,
                first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(wallet_hash, ln_address)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_wallet_hash ON wallet_fingerprints(wallet_hash)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS node_blacklist (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                pubkey      TEXT NOT NULL UNIQUE,
                reason      TEXT,
                blocked_at  TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_node_pubkey ON node_blacklist(pubkey)")
        conn.commit()

def cleanup_stale_pending():
    """Expira claims pending com mais de 5 minutos.

    Linhas com payment_hash preenchido tiveram o pagamento enviado mas o UPDATE
    falhou — não expirar para não liberar double-claim. São marcadas 'orphan'
    para revisão manual.
    """
    with get_db() as conn:
        orphans = conn.execute("""
            UPDATE claims SET status='orphan'
            WHERE status='pending'
            AND payment_hash IS NOT NULL AND payment_hash != ''
            AND claimed_at < datetime('now', '-5 minutes')
        """).rowcount
        n = conn.execute("""
            UPDATE claims SET status='failed'
            WHERE status='pending'
            AND (payment_hash IS NULL OR payment_hash = '')
            AND claimed_at < datetime('now', '-5 minutes')
        """).rowcount
        conn.commit()
    if orphans:
        logger.critical(f"Cleanup: {orphans} claim(s) 'orphan' — pagamento enviado mas DB não foi atualizado!")
    if n:
        logger.info(f"Cleanup: {n} pending(s) expirado(s)")

# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    cleanup_stale_pending()

    # Cliente HTTP compartilhado com timeouts granulares e sem seguir redirects
    app.state.http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=2.0),
        follow_redirects=False,
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    )
    app.state.last_archive = 0.0  # timestamp do último archive de claims antigos

    async def _periodic():
        while True:
            await asyncio.sleep(300)
            try:
                cleanup_stale_pending()
                # Limpar IPs inativos do rate limiter (previne memory leak)
                now = _time.time()
                async with _rate_lock:
                    stale_ips = [ip for ip, ts in _rate_store.items() if not ts or now - max(ts) > 300]
                    for ip in stale_ips:
                        del _rate_store[ip]
                    if stale_ips:
                        logger.debug(f"Rate limiter cleanup: {len(stale_ips)} IPs removidos")
                # Arquiva claims > 60 dias — uma vez por dia
                if _time.time() - app.state.last_archive > 86400:
                    with get_db() as conn:
                        n = conn.execute("""
                            DELETE FROM claims
                            WHERE status IN ('failed','paid')
                            AND claimed_at < datetime('now', '-60 days')
                        """).rowcount
                        conn.commit()
                    if n:
                        logger.info(f"Archive: {n} claim(s) antigos removidos")
                    app.state.last_archive = _time.time()
            except Exception as e:
                logger.error(f"Cleanup error: {e}")

    task = asyncio.create_task(_periodic())
    tg_task = asyncio.create_task(run_monitor(interval_hours=1))
    cmd_task = asyncio.create_task(poll_commands())  # Bot de comandos
    logger.info("BTCFaucet iniciado ✓")
    yield
    task.cancel()
    tg_task.cancel()
    cmd_task.cancel()
    await app.state.http_client.aclose()
    logger.info("BTCFaucet encerrado")

app = FastAPI(title="LN Faucet", lifespan=lifespan)

# [FIX #3] CORS restrito ao domínio próprio
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    allow_credentials=False,
)

# ── User Agent Blacklist ──────────────────────────────────────────────────────
BOT_UA_PATTERNS = [
    "curl/", "python-requests", "python-httpx", "python/", "python3",
    "wget/", "scrapy",
    "go-http-client", "java/", "libwww", "okhttp", "axios/",
    "ruby", "php/", "perl/", "bot", "spider", "crawler",
    "aiohttp", "httpie", "insomnia", "postman", "libcurl", "node-fetch",
]

def is_bot_ua(request: Request) -> bool:
    ua = request.headers.get("user-agent", "").lower()
    if not ua:
        return True
    return any(p in ua for p in BOT_UA_PATTERNS)

# ── IPv6 Bot Farm Blocker ─────────────────────────────────────────────────────
# Bloqueia padrão identificado: xxxx:xxxx:xxxx:xxxx:18ab:xxxx:xxxx:xxxx
# (bot farm Claro BR — segmento :18ab: constante em todos os IPs do farm)
_IPV6_BOT_PATTERN = re.compile(
    r'^[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}:18ab:',
    re.IGNORECASE
)

def is_blocked_ipv6_pattern(ip: str) -> bool:
    """Retorna True se o IP bate em padrão de bot farm IPv6 conhecido."""
    if ":" not in ip:
        return False
    # Normaliza para formato expandido comparável
    try:
        expanded = str(ipaddress.ip_address(ip).exploded)
        # Verifica segmento 18ab no 5o grupo (índices 5 e 6 da exploded = "18ab")
        parts = expanded.split(":")
        if len(parts) == 8 and parts[4].lower() == "18ab":
            return True
    except ValueError:
        pass
    return False

# ── LN Address Validator ──────────────────────────────────────────────────────
LN_ADDRESS_RE = re.compile(r'^[a-zA-Z0-9._+\-]{1,64}@[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,}$')

EMAIL_DOMAINS_BLACKLIST = {
    "gmail.com", "hotmail.com", "yahoo.com", "outlook.com", "icloud.com",
    "proton.me", "pm.me", "bol.com.br", "terra.com.br", "uol.com.br",
    "live.com", "msn.com", "me.com", "mac.com", "googlemail.com",
    "yandex.com", "yandex.ru", "mail.ru", "inbox.ru",
}

INVOICE_PREFIXES = ("lnbc", "lntb", "lnurl", "lightning:", "lnbcrt", "00020126")

def is_valid_ln_address(address: str) -> tuple[bool, str]:
    if not address:
        return False, "LN Address não informado"
    if len(address) > 120:
        return False, "Endereço muito longo — use um Lightning Address (ex: voce@wallet.com)"
    if any(c in address for c in (" ", "\t", "\n", "\r")):
        return False, "LN Address não pode conter espaços"
    lower = address.lower()
    if any(lower.startswith(p) for p in INVOICE_PREFIXES):
        return False, "Cole um Lightning Address (ex: voce@wallet.com), não uma invoice ou LNURL"
    if "@" not in address:
        return False, "Formato inválido — use algo@wallet.com"
    if address.count("@") > 1:
        return False, "Formato inválido — use algo@wallet.com"
    if not LN_ADDRESS_RE.match(address):
        return False, "Formato inválido — use algo@wallet.com (apenas letras, números, . _ + -)"
    domain = address.split("@", 1)[1].lower()
    if domain in EMAIL_DOMAINS_BLACKLIST:
        return False, f"'{domain}' não é uma wallet Lightning. Use Wallet of Satoshi, Blink, Alby, etc."
    return True, ""

# ── [FIX #5] Sanitização do fp_hash ──────────────────────────────────────────
def sanitize_fp_hash(fp: Optional[str]) -> Optional[str]:
    """Valida que é SHA-256 hex (64 chars). Rejeita silenciosamente qualquer outra coisa."""
    if not fp:
        return None
    fp = fp.strip().lower()
    if len(fp) == 64 and re.match(r'^[a-f0-9]{64}$', fp):
        return fp
    return None

# ── Models ────────────────────────────────────────────────────────────────────
class ClaimRequest(BaseModel):
    ln_address:       str
    captcha_token:    str
    fp_hash:          Optional[str] = None
    canvas_hash:      Optional[str] = None
    challenge_phrase: Optional[str] = None
    pow_nonce:        Optional[int] = None
    pow_seed:         Optional[str] = None

async def verify_hcaptcha(token: str) -> bool:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://hcaptcha.com/siteverify",
            data={"secret": HCAPTCHA_SECRET, "response": token},
            timeout=10,
        )
        return resp.json().get("success", False)

# ── Wallet Fingerprint (identifica carteira real independente do LN address) ──
import hashlib as _hashlib

def compute_wallet_hash(callback_url: str, metadata: str = "") -> str:
    """
    Gera hash permanente da wallet a partir do callback URL do LNURL.
    O callback contém o node/wallet ID — não muda ao trocar o username.
    Ex: https://walletofsatoshi.com/lnurlp/callback/abc123
        → hash de "walletofsatoshi.com/lnurlp/callback/abc123"
    """
    # Normalizar: remover protocolo e query params
    url = callback_url.split("?")[0].replace("https://", "").replace("http://", "")
    raw = url + "|" + metadata
    return _hashlib.sha256(raw.encode()).hexdigest()

def check_wallet_fingerprint(wallet_hash: str, ln_address: str) -> tuple[bool, str]:
    """
    Verifica se wallet_hash já foi usado com outro LN address.
    Retorna (bloqueado, ln_address_original).
    """
    with get_db() as conn:
        row = conn.execute(
            "SELECT ln_address FROM wallet_fingerprints WHERE wallet_hash = ? AND ln_address != ? LIMIT 1",
            (wallet_hash, ln_address.lower())
        ).fetchone()
    if row:
        return True, row["ln_address"]
    return False, ""

def register_wallet_fingerprint(wallet_hash: str, ln_address: str):
    """Registra ou atualiza a associação wallet_hash → ln_address."""
    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO wallet_fingerprints (wallet_hash, ln_address) VALUES (?, ?)",
            (wallet_hash, ln_address.lower())
        )
        conn.commit()


async def resolve_ln_address(address: str, amount_sat: int, http_client: httpx.AsyncClient = None) -> tuple[str, str]:
    """Retorna (bolt11, wallet_hash). wallet_hash identifica a carteira real."""
    if "@" not in address:
        raise HTTPException(400, "LN Address inválido")
    user, domain = address.split("@", 1)
    # [FIX #7] Sanitizar user/domain — previne path traversal / SSRF
    if not re.match(r'^[a-zA-Z0-9._+\-]{1,64}$', user):
        raise HTTPException(400, "LN Address inválido")
    if not re.match(r'^[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,}$', domain):
        raise HTTPException(400, "LN Address inválido")
    url = f"https://{domain}/.well-known/lnurlp/{user}"
    try:
        client = http_client or httpx.AsyncClient(timeout=10)
        _owns_client = http_client is None
        try:
            r1 = await client.get(url, timeout=10)
            if r1.status_code != 200:
                raise HTTPException(400, "LN Address não encontrado ou indisponível")
            meta = r1.json()
            if meta.get("status") == "ERROR":
                raise HTTPException(400, meta.get("reason", "Erro no LN Address"))
            min_sat = meta.get("minSendable", 1000) // 1000
            max_sat = meta.get("maxSendable", 1_000_000) // 1000
            if not (min_sat <= amount_sat <= max_sat):
                raise HTTPException(400, f"Valor {amount_sat} sats fora do range [{min_sat}–{max_sat}]")
            callback = meta.get("callback", "")
            # Validar que callback pertence ao mesmo domínio (previne SSRF)
            try:
                cb_host = urlparse(callback).hostname or ""
            except Exception:
                cb_host = ""
            if cb_host != domain:
                raise HTTPException(400, "LN Address inválido: callback em domínio diferente")
            metadata = str(meta.get("metadata", ""))
            wallet_hash = compute_wallet_hash(callback, metadata)
            r2 = await client.get(callback, params={"amount": amount_sat * 1000}, timeout=10)
            data2 = r2.json()
            if data2.get("status") == "ERROR":
                raise HTTPException(400, data2.get("reason", "Erro ao gerar invoice"))
            return data2["pr"], wallet_hash
        finally:
            if _owns_client:
                await client.aclose()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"resolve_ln_address error [{address}]: {e}")
        raise HTTPException(400, "Não foi possível contatar a wallet. Verifique o LN Address.")

async def pay_invoice(bolt11: str, http_client: httpx.AsyncClient = None) -> dict:
    headers = {"X-Api-Key": LNBITS_ADMIN_KEY, "Content-Type": "application/json"}
    try:
        client = http_client or httpx.AsyncClient(timeout=30)
        _owns_client = http_client is None
        try:
            r = await client.post(
                f"{LNBITS_URL}/api/v1/payments",
                json={"out": True, "bolt11": bolt11},
                headers=headers,
                timeout=30,
            )
            if r.status_code not in (200, 201):
                logger.error(f"LNbits error {r.status_code}: {r.text[:500]}")
                raise HTTPException(500, "Erro ao processar pagamento. Tente novamente.")
            return r.json()
        finally:
            if _owns_client:
                await client.aclose()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"pay_invoice unexpected error: {e}")
        raise HTTPException(500, "Erro interno. Tente novamente.")

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/api/status")
async def api_status(request: Request):
    ip = get_client_ip(request)
    if not await check_rate_limit(ip, max_req=60, window=60):
        raise HTTPException(429, "Muitas requisições.")
    return {"amount_sat": FAUCET_AMOUNT_SAT, "cooldown_hours": COOLDOWN_HOURS, "cooldown_type": "midnight", "online": True}

@app.get("/api/config")
async def api_config(request: Request):
    ip = get_client_ip(request)
    if not await check_rate_limit(ip, max_req=30, window=60):
        raise HTTPException(429, "Muitas requisições.")
    return {"hcaptcha_sitekey": HCAPTCHA_SITEKEY, "amount_sat": FAUCET_AMOUNT_SAT, "cooldown_hours": COOLDOWN_HOURS, "cooldown_type": "midnight"}

@app.post("/api/check-suspect")
async def check_suspect(body: dict, request: Request):
    """Retorna se LN address pertence a domínio suspeito (dose dupla)."""
    ln = (body.get("ln_address") or "").strip().lower()
    if "@" not in ln:
        return {"suspect": False}
    domain = ln.split("@")[1]
    return {"suspect": domain in SUSPECT_DOMAINS, "domain": domain}


@app.get("/api/stats")
async def api_stats(request: Request):
    ip = get_client_ip(request)
    if not await check_rate_limit(ip, max_req=20, window=60):
        raise HTTPException(429, "Muitas requisições.")
    with get_db() as conn:
        total = conn.execute(
            "SELECT COUNT(*) as c, SUM(amount_sat) as s FROM claims WHERE status='paid'"
        ).fetchone()
    
    stats = {
        "total_claims": total["c"] or 0, 
        "total_sats_paid": total["s"] or 0
    }
    
    # Adiciona info de rewards progressivos se habilitado
    if PROGRESSIVE_REWARDS:
        stats["progressive_rewards"] = {
            "enabled": True,
            "tier_1": REWARD_TIER_1,
            "tier_2": REWARD_TIER_2,
            "tier_3": REWARD_TIER_3
        }
    else:
        stats["progressive_rewards"] = {
            "enabled": False,
            "fixed_amount": FAUCET_AMOUNT_SAT
        }
    
    return stats

@app.post("/api/check")
async def check_address(body: dict, request: Request):
    ip = get_client_ip(request)
    if not await check_rate_limit(ip, max_req=20, window=60):
        raise HTTPException(429, "Muitas requisições.")

    ln = body.get("ln_address", "").strip().lower()
    fp = sanitize_fp_hash(body.get("fp_hash"))
    asn = get_cf_asn(request)

    if not ln:
        raise HTTPException(400, "Informe um LN Address")

    valid, err_msg = is_valid_ln_address(ln)
    if not valid:
        return {"blocked": True, "wait_seconds": 0, "reason": "invalid_address", "message": err_msg}

    # Blacklist check (via security module)
    if is_dynamically_blocked(ip=ip, fp=fp, ln=ln):
        return {"blocked": True, "wait_seconds": 0, "reason": "blacklist",
                "message": "Este endereço não está autorizado a receber sats."}

    if is_bot_ua(request):
        raise HTTPException(403, "Acesso negado")

    # IPv6 bot farm pattern
    if is_blocked_ipv6_pattern(ip):
        raise HTTPException(403, "Acesso negado")

    if is_blocked_asn_hextet(ip, asn):
        logger.warning(f"ASN+hextet bloqueado [check]: asn={asn} ip={ip}")
        raise HTTPException(403, "Acesso negado")

    # Fingerprint blacklist
    # FP check agora está em is_dynamically_blocked()

    # WHITELIST_ADM: ignora tudo (cooldowns + bloqueios)
    # WHITELIST:     ignora bloqueios mas respeita cooldowns
    if ln not in config.WHITELIST_ADM:
        # Cooldowns — WHITELIST_ADM ignora, todos os outros respeitam
        blocked, secs = is_address_blocked(ln)
        if blocked:
            return {"blocked": True, "wait_seconds": secs, "reason": "address",
                    "message": "Você já recebeu sats hoje. Volte amanhã após a meia-noite (00:00 UTC)."}

        ip_blocked, ip_secs = is_ip_blocked(ip)
        if ip_blocked:
            m2 = ip_secs // 60
            return {"blocked": True, "wait_seconds": ip_secs, "reason": "ip",
                    "message": f"Este IP já recebeu sats recentemente. Aguarde {m2} minutos."}

        subnet_blocked, _ = is_subnet_blocked(ip)
        if subnet_blocked:
            return {"blocked": True, "wait_seconds": 86400, "reason": "subnet",
                    "message": "Muitas requisições desta rede. Tente mais tarde."}

        fp_blocked, fp_secs = is_fp_blocked(fp)
        if fp_blocked:
            h2, m2 = fp_secs // 3600, (fp_secs % 3600) // 60
            return {"blocked": True, "wait_seconds": fp_secs, "reason": "fingerprint",
                    "message": "Limite de claims deste dispositivo atingido hoje. Volte após a meia-noite (00:00 UTC)."}
        
        # Bloqueios de segurança — WHITELIST ignora
        if ln not in config.WHITELIST:
            if is_fp_too_new(fp, ip, ln):
                raise HTTPException(403, "Seu navegador está limpando os cookies. Por segurança, o sistema bloqueou o acesso. Tente novamente por outro navegador ou desative a limpeza automática de cookies e tente novamente após 10 minutos.")

            ja3 = get_ja3(request)
            asn = get_cf_asn(request)
            ja3_blocked, ja3_secs = is_ja3_blocked(ja3)
            if ja3_blocked:
                h3, m3 = ja3_secs // 3600, (ja3_secs % 3600) // 60
                return {"blocked": True, "wait_seconds": ja3_secs, "reason": "tls",
                        "message": "Limite de claims deste endereço atingido hoje. Volte após a meia-noite (00:00 UTC)."}

    return {"blocked": False}

@app.post("/api/claim")
async def claim(req: ClaimRequest, request: Request):
    ln  = req.ln_address.strip().lower()
    ip  = get_client_ip(request)
    fp  = sanitize_fp_hash(req.fp_hash)
    ja3 = get_ja3(request)
    ip_prefix = normalize_ip_prefix(ip)

    # [FIX #6] Rate limit: 5 claims/min por IP
    if not await check_rate_limit(ip, max_req=5, window=60):
        raise HTTPException(429, "Muitas requisições. Tente novamente.")

    # 0 – Validação de formato
    valid, err_msg = is_valid_ln_address(ln)
    if not valid:
        raise HTTPException(400, err_msg)

    # WHITELIST_ADM — fura todos os bloqueios e cooldowns
    _is_adm = ln in config.WHITELIST_ADM

    # WHITELIST_ADM e WHITELIST ignoram todos os bloqueios de segurança
    _is_whitelisted = ln in config.WHITELIST_ADM or ln in config.WHITELIST

    if not _is_whitelisted:
        # 1 – Blacklist check (via security module)
        if is_dynamically_blocked(ip=ip, fp=fp, ln=ln):
            raise HTTPException(403, "Acesso negado")

        # 2 – User Agent check
        if is_bot_ua(request):
            raise HTTPException(403, "Acesso negado")

        # 2b – IPv6 bot farm pattern check
        if is_blocked_ipv6_pattern(ip):
            logger.warning(f"IPv6 bot farm bloqueado: {ip} tentou {ln}")
            raise HTTPException(403, "Acesso negado")

        # 2c – Fingerprint obrigatório para IPs não-CGNAT
        if not fp and not is_cgnat_ip(ip):
            logger.warning(f"Claim sem fingerprint bloqueado: ip={ip} ln={ln}")
            raise HTTPException(400, "Requisição inválida. Use o site oficial.")

    # Captcha antes dos rate limit checks — evita timing oracle
    if HCAPTCHA_SECRET != "0x0000000000000000000000000000000000000000":
        import re as _re_cap
        ct = (req.captcha_token or "").strip()
        if not ct or len(ct) > 2048 or not _re_cap.match(r'^[A-Za-z0-9_.\-]+$', ct):
            raise HTTPException(400, "Captcha inválido.")
        ok = await verify_hcaptcha(ct)
        if not ok:
            raise HTTPException(400, "Captcha inválido")

    # banner token e CSS token removidos — verificação pelo desafio de texto

    # 2a3 – Registrar canvas hash (identificação de browser real)
    canvas_hash = (req.canvas_hash or "").strip()
    if canvas_hash:
        logger.debug(f"Canvas hash: {canvas_hash[:16]}… ip={ip} ln={ln}")

    # 2b – Verificar frase(s) de desafio anti-bot
    raw_phrase = (req.challenge_phrase or "").strip().lower()
    if not raw_phrase:
        logger.warning(f"Challenge vazio ip={ip} ln={ln}")
        raise HTTPException(403, "Desafio de verificação inválido. Recarregue a página e tente novamente.")
    if "|" in raw_phrase:
        phrases = [p.strip() for p in raw_phrase.split("|", 1)]
        if len(phrases) < 2 or any(p not in CHALLENGE_PHRASES for p in phrases):
            logger.warning(f"Challenge duplo inválido: '{raw_phrase[:40]}' ip={ip} ln={ln}")
            raise HTTPException(403, "Desafio de verificação inválido. Recarregue a página e tente novamente.")
    else:
        if raw_phrase not in CHALLENGE_PHRASES:
            logger.warning(f"Challenge inválido: '{raw_phrase[:30]}' ip={ip} ln={ln}")
            raise HTTPException(403, "Desafio de verificação inválido. Recarregue a página e tente novamente.")

    # 2c – Verificar Proof of Work
    pow_seed  = (req.pow_seed or "").strip()
    pow_nonce = req.pow_nonce
    if not pow_seed or pow_nonce is None or not verify_pow(pow_seed, pow_nonce):
        logger.warning(f"PoW inválido: seed={pow_seed[:20]} nonce={pow_nonce} ip={ip} ln={ln}")
        raise HTTPException(403, "Verificação de segurança falhou. Recarregue a página e tente novamente.")

    # 3 – Rate limits (pós-captcha)
    # WHITELIST_ADM: ignora tudo | WHITELIST: respeita cooldowns | normal: respeita tudo
    if ln not in config.WHITELIST_ADM:
        blocked, secs = is_address_blocked(ln)
        if blocked:
            raise HTTPException(429, "Você já recebeu sats hoje. Volte amanhã após a meia-noite (00:00 UTC).")

        ip_blocked, ip_secs = is_ip_blocked(ip)
        if ip_blocked:
            m2 = ip_secs // 60
            raise HTTPException(429, f"Este IP já recebeu sats recentemente. Aguarde {m2} minutos.")

        subnet_blocked, _ = is_subnet_blocked(ip)
        if subnet_blocked:
            raise HTTPException(429, "Muitas requisições desta rede. Tente mais tarde.")

        fp_blocked, fp_secs = is_fp_blocked(fp)
        if fp_blocked:
            h2, m2 = fp_secs // 3600, (fp_secs % 3600) // 60
            raise HTTPException(429, "Limite de claims deste dispositivo atingido hoje. Volte após a meia-noite (00:00 UTC).")
        
        # FP age check - bloqueia fingerprints muito novos (< FP_MIN_AGE_MINUTES)
        # CRÍTICO: Verificar ANTES do INSERT para evitar poluir DB com farms
        if ln not in config.WHITELIST and is_fp_too_new(fp, ip, ln):
            logger.warning(f"FP muito novo bloqueado em /api/claim: fp={fp[:12] if fp else 'None'}… ip={ip} ln={ln}")
            raise HTTPException(403, "Seu navegador está limpando os cookies. Por segurança, o sistema bloqueou o acesso. Tente novamente por outro navegador ou desative a limpeza automática de cookies e tente novamente após 10 minutos.")

        ja3_blocked, ja3_secs = is_ja3_blocked(ja3)
        if ja3_blocked:
            h3, m3 = ja3_secs // 3600, (ja3_secs % 3600) // 60
            raise HTTPException(429, "Limite de claims deste endereço atingido hoje. Volte após a meia-noite (00:00 UTC).")

    # 4 – [FIX #1] Lock exclusivo por LN address — previne race condition / duplo gasto
    acquired = await acquire_claim_lock(ln)
    if not acquired:
        raise HTTPException(429, "Requisição em andamento para este endereço. Aguarde.")

    try:
        # Double-check pós-lock (TOCTOU): re-verifica todos os cooldowns após adquirir lock
        if ln not in config.WHITELIST_ADM:
            blocked, secs = is_address_blocked(ln)
            if blocked:
                raise HTTPException(429, "Você já recebeu sats hoje. Volte amanhã após a meia-noite (00:00 UTC).")

            # Bloquear segundo request para o mesmo LN address enquanto o primeiro está pendente
            with get_db() as conn:
                pending_row = conn.execute(
                    "SELECT id FROM claims WHERE ln_address=? AND status='pending' LIMIT 1",
                    (ln.lower(),)
                ).fetchone()
            if pending_row:
                raise HTTPException(429, "Pagamento em andamento para este endereço. Aguarde.")

            # Re-verificar IP e subnet dentro do lock (TOCTOU completo)
            ip_blocked_inner, _ = is_ip_blocked(ip)
            if ip_blocked_inner:
                raise HTTPException(429, "Este IP já recebeu sats recentemente. Tente mais tarde.")

            subnet_blocked_inner, _ = is_subnet_blocked(ip)
            if subnet_blocked_inner:
                raise HTTPException(429, "Muitas requisições desta rede. Tente mais tarde.")

            # Verifica se outro claim do mesmo ip_prefix foi pago nos últimos 5 segundos
            if ip_prefix and not is_cgnat_ip(ip):
                since_5s = (datetime.utcnow() - timedelta(seconds=5)).isoformat()
                with get_db() as conn:
                    recent = conn.execute(
                        """SELECT ln_address FROM claims
                           WHERE ip_prefix = ? AND status = 'paid'
                           AND claimed_at > ? AND ln_address != ?
                           LIMIT 1""",
                        (ip_prefix, since_5s, ln)
                    ).fetchone()
                if recent:
                    logger.warning(
                        f"Race condition bloqueada: {ln} e {recent['ln_address']} "
                        f"no mesmo ip_prefix {ip_prefix} em <5s"
                    )
                    raise HTTPException(429, "Muitas requisições simultâneas desta rede. Tente novamente em instantes.")

        # 3 – Calcular reward progressivo baseado em histórico do LN ADDRESS
        reward_amount = get_progressive_reward(ln)
        
        # FP penalty: FP novo (age=0) → sempre 1 sat, independente do tier
        # Educa o usuário sem bloquear, penaliza bots com FPs descartáveis
        # WHITELIST_ADM está isento — nunca sofre penalty
        fp_penalty = False
        if fp and FP_MIN_AGE_MINUTES > 0 and ln not in config.WHITELIST_ADM:
            with get_db() as conn:
                fp_first = conn.execute(
                    "SELECT MIN(claimed_at) FROM claims WHERE fp_hash=?", (fp,)
                ).fetchone()[0]
            if not fp_first:
                # FP nunca visto antes — age efetivamente 0
                fp_penalty = True
            else:
                from datetime import timezone
                fp_dt = datetime.fromisoformat(fp_first.replace("Z",""))
                fp_age = (datetime.utcnow() - fp_dt).total_seconds() / 60
                if fp_age < FP_MIN_AGE_MINUTES:
                    fp_penalty = True
        
        if fp_penalty and reward_amount > 1:
            logger.info(f"FP penalty aplicado: {reward_amount}→1 sat | fp={fp[:12] if fp else 'None'}… ln={ln}")
            reward_amount = 1
        
        # Farm decay: reduz reward para 1 sat se detectar padrão de farm
        # Não bloqueia ninguém — usuários legítimos que caiam por azar ainda recebem 1 sat
        farm_decay = False
        if reward_amount > 1 and ln not in config.WHITELIST_ADM:
            # Decay por subnet: /48 IPv6 ou /24 IPv4 com 2+ LN addresses distintos (24h)
            if check_subnet_farm(ip, ln):
                farm_decay = True
                logger.info(f"Subnet farm decay: {reward_amount}→1 sat | ip={ip} ln={ln} prefix={get_broad_prefix(ip)}")
            
            # Decay por FP: mesmo fingerprint usado com outro LN address (24h)
            if not farm_decay and check_fp_farm(fp, ln):
                farm_decay = True
                logger.info(f"FP farm decay: {reward_amount}→1 sat | fp={fp[:12] if fp else 'None'}… ln={ln}")
            
            if farm_decay:
                reward_amount = 1
        
        logger.info(f"Reward calculado: {reward_amount} sats para ln={ln} (fp_penalty={fp_penalty}, farm_decay={farm_decay})")
        
        # 4 – Registrar claim pending
        now = datetime.utcnow().isoformat()
        with get_db() as conn:
            cur = conn.execute(
                """INSERT INTO claims
                   (ln_address, ip_address, ip_prefix, fp_hash, ja3_hash, claimed_at, amount_sat, status)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (ln, ip, ip_prefix, fp, ja3, now, reward_amount, "pending")
            )
            claim_id = cur.lastrowid
            conn.commit()

        # 5 – Resolver LN Address → invoice + wallet fingerprint
        http = request.app.state.http_client
        try:
            bolt11, wallet_hash = await resolve_ln_address(ln, reward_amount, http_client=http)
            # Verificar se carteira já foi vista com outro LN address
            if ln not in config.WHITELIST_ADM and ln not in config.WHITELIST:
                wh_blocked, wh_original = check_wallet_fingerprint(wallet_hash, ln)
                if wh_blocked:
                    logger.warning(
                        f"Wallet duplicada bloqueada: {ln} → wallet_hash já usado por {wh_original}"
                    )
                    with get_db() as conn:
                        conn.execute("UPDATE claims SET status='failed' WHERE id=?", (claim_id,))
                        conn.commit()
                    raise HTTPException(403, "Esta carteira já foi utilizada com outro endereço Lightning. Acesso negado.")
            # Registrar associação wallet_hash → ln_address
            register_wallet_fingerprint(wallet_hash, ln)
        except HTTPException:
            with get_db() as conn:
                conn.execute("UPDATE claims SET status='failed' WHERE id=?", (claim_id,))
                conn.commit()
            raise

        # 5 – Pagar via LNbits
        try:
            result = await pay_invoice(bolt11, http_client=http)
            payment_hash = result.get("payment_hash", "")
            dest_pubkey = decode_bolt11_pubkey(bolt11)

            # Persistir status='paid' com retry — se falhar, o registro fica com
            # payment_hash preenchido e cleanup_stale_pending o marca 'orphan'
            # (não 'failed'), impedindo double-claim.
            db_ok = False
            for attempt in range(3):
                try:
                    with get_db() as conn:
                        conn.execute(
                            "UPDATE claims SET status='paid', payment_hash=?, destination_pubkey=? WHERE id=?",
                            (payment_hash, dest_pubkey, claim_id)
                        )
                        conn.commit()
                    db_ok = True
                    break
                except Exception as db_err:
                    logger.error(f"DB update attempt {attempt+1}/3 failed for claim {claim_id}: {db_err}")
                    if attempt < 2:
                        await asyncio.sleep(0.3)
            if not db_ok:
                # Pré-marcar payment_hash para que cleanup não libere double-claim
                try:
                    with get_db() as conn:
                        conn.execute(
                            "UPDATE claims SET payment_hash=? WHERE id=?",
                            (payment_hash, claim_id)
                        )
                        conn.commit()
                except Exception:
                    pass
                logger.critical(
                    f"CRITICAL: sats enviados mas status não persistido! "
                    f"claim_id={claim_id} ln={ln} hash={payment_hash}"
                )

            if dest_pubkey:
                pk_blocked, pk_original = check_node_fingerprint(dest_pubkey, ln)
                if pk_blocked:
                    logger.warning(
                        f"Node pubkey reutilizado: {ln} → pubkey já usado por {pk_original} "
                        f"| pubkey={dest_pubkey[:16]}…"
                    )
            logger.info(f"Claim OK: {ln} | ip={ip} | hash={payment_hash[:16]}...")
            if fp_penalty:
                success_msg = (
                    f"⚡ {reward_amount} sat recebido! "
                    "Seu navegador está limpando os cookies, então o pagamento foi reduzido por segurança. "
                    "Na próxima vez, tente usar um navegador diferente ou desative a limpeza automática de cookies "
                    "para receber o valor completo."
                )
            else:
                success_msg = f"⚡ {reward_amount} sats!"
            return {"success": True, "message": success_msg, "payment_hash": payment_hash, "amount_sat": reward_amount, "fp_penalty": fp_penalty, "farm_decay": farm_decay}
        except HTTPException:
            with get_db() as conn:
                conn.execute("UPDATE claims SET status='failed' WHERE id=?", (claim_id,))
                conn.commit()
            raise
        except BaseException as e:
            # Captura CancelledError, TimeoutError, etc. — garante que a linha não
            # fique stuck como 'pending' sem ser marcada 'failed'
            logger.error(f"Erro inesperado em pay_invoice para claim {claim_id}: {type(e).__name__}: {e}")
            try:
                with get_db() as conn:
                    conn.execute("UPDATE claims SET status='failed' WHERE id=?", (claim_id,))
                    conn.commit()
            except Exception:
                pass
            raise

    finally:
        # Sempre libera o lock, mesmo em exceção
        release_claim_lock(ln)


# [FIX #7] Proxy LNURL com sanitização de username e cb_id
@app.api_route("/.well-known/lnurlp/{username}", methods=["GET"])
async def lnurlp_proxy(username: str, request: Request):
    if not re.match(r'^[a-zA-Z0-9._+\-]{1,64}$', username):
        raise HTTPException(400, "Username inválido")
    ALLOWED_QP = {"amount", "comment", "nostr"}
    params = {k: v for k, v in request.query_params.items() if k in ALLOWED_QP}
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{LNBITS_URL}/.well-known/lnurlp/{username}", params=params, timeout=10)
        data = r.json()
        if "callback" in data:
            data["callback"] = data["callback"].replace(
                "http://localhost:5001", "https://bitcoinfaucet.st"
            ).replace("http://127.0.0.1:5001", "https://bitcoinfaucet.st")
        return data

@app.api_route("/lnurlp/api/v1/lnurl/cb/{cb_id}", methods=["GET"])
async def lnurlp_callback_proxy(cb_id: str, request: Request):
    if not re.match(r'^[a-zA-Z0-9_\-]{1,128}$', cb_id):
        raise HTTPException(400, "Callback ID inválido")
    ALLOWED_QP = {"amount", "comment", "nostr"}
    params = {k: v for k, v in request.query_params.items() if k in ALLOWED_QP}
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{LNBITS_URL}/lnurlp/api/v1/lnurl/cb/{cb_id}", params=params, timeout=10)
        return r.json()


# ── Health check ──────────────────────────────────────────────────────────────


@app.post("/api/verify-canvas")
async def verify_canvas_hash(body: dict, request: Request):
    """Aceita canvas hash — registrado mas não bloqueante por ora."""
    return {"ok": True}

@app.get("/health")
async def health():
    """Health check para monitoramento externo e systemd watchdog."""
    from fastapi.responses import JSONResponse
    try:
        with get_db() as conn:
            conn.execute("SELECT 1").fetchone()
        return JSONResponse({"ok": True, "db": True}, status_code=200)
    except Exception:
        return JSONResponse({"ok": False, "db": False}, status_code=503)


@app.get("/api/balance")
async def api_balance(request: Request):
    """
    Saldo disponível na wallet LNbits.
    Exibido no frontend — rate limitado, sem dados sensíveis.
    """
    ip = get_client_ip(request)
    if not await check_rate_limit(ip, max_req=10, window=60):
        raise HTTPException(429, "Muitas requisições.")
    try:
        http = request.app.state.http_client
        r = await http.get(
            f"{LNBITS_URL}/api/v1/wallet",
            headers={"X-Api-Key": LNBITS_ADMIN_KEY},
            timeout=5.0,
        )
        if r.status_code == 200:
            balance_sat = r.json().get("balance", 0) // 1000
            return {"balance_sat": balance_sat, "ok": True}
        return {"balance_sat": None, "ok": False}
    except Exception:
        return {"balance_sat": None, "ok": False}


# Serve frontend
app.mount("/", StaticFiles(directory="static", html=True), name="static")
