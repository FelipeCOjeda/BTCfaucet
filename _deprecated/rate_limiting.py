import asyncio
import time
import logging
from datetime import datetime, timedelta
from typing import Optional

from config import (
    COOLDOWN_HOURS, IP_COOLDOWN_HOURS, SUBNET_LIMIT,
    FP_COOLDOWN_HOURS, FP_LIMIT, WHITELIST,
)
from database import get_db
from validators import is_cgnat_ip, normalize_ip_prefix

logger = logging.getLogger("faucet.rate")

# ── In-memory rate limiter (endpoints públicos) ───────────────────────────────
_rate_store: dict[str, list[float]] = {}
_rate_lock = asyncio.Lock()


async def check_rate_limit(ip: str, max_req: int = 60, window: int = 60) -> bool:
    """
    Sliding window rate limiter em memória.
    Retorna True se a requisição é permitida, False se excedeu o limite.
    """
    now = time.time()
    async with _rate_lock:
        ts = _rate_store.get(ip, [])
        ts = [t for t in ts if now - t < window]
        if len(ts) >= max_req:
            return False
        ts.append(now)
        _rate_store[ip] = ts
        return True


async def purge_rate_store() -> int:
    """Remove entradas inativas do rate store (chamado pelo cleanup periódico)."""
    now = time.time()
    async with _rate_lock:
        stale = [ip for ip, ts in _rate_store.items()
                 if not ts or now - max(ts) > 3600]
        for ip in stale:
            del _rate_store[ip]
    return len(stale)


# ── Claim locks (previne race condition / duplo gasto) ────────────────────────
_claim_locks: dict[str, asyncio.Lock] = {}
_claim_locks_ts: dict[str, float] = {}
_claim_registry = asyncio.Lock()


async def acquire_claim_lock(ln: str) -> bool:
    """
    Tenta adquirir lock exclusivo para o LN address.
    Retorna True se adquiriu (pode prosseguir), False se já está em processamento.
    Um lock com mais de 2 minutos é considerado stale e removido automaticamente.
    """
    async with _claim_registry:
        now = time.time()
        # Cleanup de locks stale (TTL 2 minutos)
        stale = [k for k, t in _claim_locks_ts.items() if now - t > 120]
        for k in stale:
            lk = _claim_locks.pop(k, None)
            _claim_locks_ts.pop(k, None)
            if lk and lk.locked():
                lk.release()

        if ln in _claim_locks:
            return False

        lk = asyncio.Lock()
        await lk.acquire()
        _claim_locks[ln] = lk
        _claim_locks_ts[ln] = now
        return True


def release_claim_lock(ln: str) -> None:
    """Libera o lock do LN address. Sempre chamado no finally do claim."""
    lk = _claim_locks.pop(ln, None)
    _claim_locks_ts.pop(ln, None)
    if lk and lk.locked():
        lk.release()


# ── Checks de cooldown ────────────────────────────────────────────────────────

def is_address_blocked(ln_address: str) -> tuple[bool, int]:
    """
    Verifica cooldown de 24h por LN address.
    Retorna (bloqueado, segundos_restantes).
    """
    with get_db() as conn:
        row = conn.execute(
            """SELECT claimed_at FROM claims
               WHERE ln_address = ? AND status = 'paid'
               ORDER BY claimed_at DESC LIMIT 1""",
            (ln_address.lower(),)
        ).fetchone()
    if not row:
        return False, 0
    last = datetime.fromisoformat(row["claimed_at"])
    delta = timedelta(hours=COOLDOWN_HOURS) - (datetime.utcnow() - last)
    if delta.total_seconds() > 0:
        return True, int(delta.total_seconds())
    return False, 0


def is_ip_blocked(ip: str) -> tuple[bool, int]:
    """
    Verifica cooldown de 1h por prefixo de IP (/24 IPv4 ou /64 IPv6).
    CGNAT: retorna sempre False — múltiplos usuários legítimos compartilham o IP.
    """
    if is_cgnat_ip(ip):
        return False, 0
    prefix = normalize_ip_prefix(ip)
    if not prefix:
        return False, 0
    with get_db() as conn:
        row = conn.execute(
            """SELECT claimed_at FROM claims
               WHERE ip_prefix = ? AND status = 'paid'
               ORDER BY claimed_at DESC LIMIT 1""",
            (prefix,)
        ).fetchone()
    if not row:
        return False, 0
    last = datetime.fromisoformat(row["claimed_at"])
    delta = timedelta(hours=IP_COOLDOWN_HOURS) - (datetime.utcnow() - last)
    if delta.total_seconds() > 0:
        return True, int(delta.total_seconds())
    return False, 0


def is_subnet_blocked(ip: str) -> tuple[bool, int]:
    """
    Bloqueia subnet inteira se exceder SUBNET_LIMIT claims em 24h.
    CGNAT: nunca bloqueia — evita falso positivo em massa.
    """
    if is_cgnat_ip(ip):
        return False, 0
    try:
        import ipaddress as _ip
        addr = _ip.ip_address(ip)
        if addr.version == 6:
            prefix = ":".join(ip.split(":")[:4])
            like_pattern = f"{prefix}:%"
        else:
            prefix = ".".join(ip.split(".")[:3])
            like_pattern = f"{prefix}.%"
    except ValueError:
        return False, 0

    since = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    with get_db() as conn:
        row = conn.execute(
            """SELECT COUNT(*) as c FROM claims
               WHERE ip_address LIKE ? AND status = 'paid' AND claimed_at > ?""",
            (like_pattern, since)
        ).fetchone()
    count = row["c"] if row else 0
    if count >= SUBNET_LIMIT:
        return True, count
    return False, 0


def is_fp_blocked(fp_hash: Optional[str]) -> tuple[bool, int]:
    """
    Verifica cooldown por browser fingerprint (SHA-256).
    Bloqueia o mesmo dispositivo mesmo que troque de IP ou LN address.
    """
    if not fp_hash:
        return False, 0
    since = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    with get_db() as conn:
        row = conn.execute(
            """SELECT COUNT(*) as c, MAX(claimed_at) as last
               FROM claims WHERE fp_hash = ? AND status = 'paid' AND claimed_at > ?""",
            (fp_hash, since)
        ).fetchone()
    if not row or row["c"] == 0:
        return False, 0
    if row["c"] >= FP_LIMIT:
        last = datetime.fromisoformat(row["last"])
        delta = timedelta(hours=FP_COOLDOWN_HOURS) - (datetime.utcnow() - last)
        secs = int(delta.total_seconds()) if delta.total_seconds() > 0 else 0
        return True, secs
    return False, 0


def is_ja3_blocked(ja3: Optional[str]) -> tuple[bool, int]:
    """
    Verifica cooldown por JA3 hash (TLS fingerprint injetado pelo Cloudflare Worker).
    Bloqueia o mesmo cliente TLS mesmo que troque de IP/LN address.
    """
    if not ja3:
        return False, 0
    since = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    with get_db() as conn:
        row = conn.execute(
            """SELECT COUNT(*) as c, MAX(claimed_at) as last
               FROM claims WHERE ja3_hash = ? AND status = 'paid' AND claimed_at > ?""",
            (ja3, since)
        ).fetchone()
    if not row or row["c"] == 0:
        return False, 0
    if row["c"] >= FP_LIMIT:
        last = datetime.fromisoformat(row["last"])
        delta = timedelta(hours=FP_COOLDOWN_HOURS) - (datetime.utcnow() - last)
        secs = int(delta.total_seconds()) if delta.total_seconds() > 0 else 0
        return True, secs
    return False, 0


def get_block_reason(
    ln: str,
    ip: str,
    fp: Optional[str],
    ja3: Optional[str],
) -> Optional[dict]:
    """
    Consolida todos os checks de bloqueio em uma única chamada.
    Retorna dict com motivo detalhado ou None se liberado.
    Usado no /api/check para retornar mensagem informativa ao usuário.
    """
    if ln in WHITELIST:
        return None

    blocked, secs = is_address_blocked(ln)
    if blocked:
        h, m = secs // 3600, (secs % 3600) // 60
        return {
            "blocked": True,
            "reason": "address",
            "wait_seconds": secs,
            "message": f"⏳ Este Lightning Address já recebeu sats recentemente. Aguarde {h}h {m}m para o próximo claim.",
        }

    ip_blocked, ip_secs = is_ip_blocked(ip)
    if ip_blocked:
        m2 = ip_secs // 60
        return {
            "blocked": True,
            "reason": "ip",
            "wait_seconds": ip_secs,
            "message": f"⏳ Outro usuário nesta rede já recebeu sats recentemente. Aguarde {m2} minuto(s).",
        }

    subnet_blocked, _ = is_subnet_blocked(ip)
    if subnet_blocked:
        return {
            "blocked": True,
            "reason": "subnet",
            "wait_seconds": 86400,
            "message": "🚫 Muitas requisições foram feitas a partir desta rede nas últimas 24h. Tente novamente mais tarde.",
        }

    fp_blocked, fp_secs = is_fp_blocked(fp)
    if fp_blocked:
        h2, m2 = fp_secs // 3600, (fp_secs % 3600) // 60
        return {
            "blocked": True,
            "reason": "fingerprint",
            "wait_seconds": fp_secs,
            "message": f"⏳ Este dispositivo já atingiu o limite de claims. Aguarde {h2}h {m2}m.",
        }

    ja3_blocked, ja3_secs = is_ja3_blocked(ja3)
    if ja3_blocked:
        h3, m3 = ja3_secs // 3600, (ja3_secs % 3600) // 60
        return {
            "blocked": True,
            "reason": "tls",
            "wait_seconds": ja3_secs,
            "message": f"⏳ Este cliente atingiu o limite de claims. Aguarde {h3}h {m3}m.",
        }

    return None
