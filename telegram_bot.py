#!/usr/bin/env python3
"""
Telegram Bot para controle do BTCFaucet
Comandos de admin, bloqueios, whitelist, restart, etc.
"""
import asyncio
import logging
import os
import re
import subprocess
import time as _time
from datetime import datetime
from typing import Optional, Tuple

import httpx

from config import (
    DB_PATH,
    LNBITS_ADMIN_KEY,
    LNBITS_URL,
    SERVICE_NAME,
    SUDO_PASS,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    TELEGRAM_ENABLED,
    WHITELIST_ADM,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("faucet.telegram")

if not TELEGRAM_ENABLED:
    logger.warning("Bot do Telegram desabilitado (token ou chat_id ausente)")

# ============================================================================
# HELPERS
# ============================================================================

def get_db():
    """Context manager para conexão SQLite."""
    import sqlite3
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


async def send_telegram(chat_id: str, text: str, parse_mode: str = "HTML"):
    """Envia mensagem via Telegram."""
    if not TELEGRAM_BOT_TOKEN:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(url, json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": parse_mode
            })
    except Exception as e:
        logger.error(f"Erro ao enviar Telegram: {e}")


# ============================================================================
# BLOQUEIOS DINÂMICOS
# ============================================================================

def _block_entity(entity_type: str, value: str, reason: str = "manual") -> Tuple[bool, str]:
    """Adiciona à blocked_entities (DB) — sem restart necessário."""
    try:
        from security.blocklist import block_entity

        if entity_type not in ["ip", "fp", "ln"]:
            return False, f"❌ Tipo inválido: {entity_type}"

        value = value.strip().lower()
        if not value:
            return False, "❌ Valor vazio"

        if entity_type == "ip" and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
            return False, f"❌ IP inválido: {value}"

        if entity_type == "ln" and "@" not in value:
            return False, f"❌ LN address inválido: {value}"

        success = block_entity(entity_type, value)

        if success:
            return True, f"✅ Bloqueado: <code>{value}</code>\n⚡ Ativo imediatamente (sem restart)"
        else:
            return False, "❌ Já estava bloqueado"

    except Exception as e:
        return False, f"❌ Erro: {e}"


def _unblock_entity(entity_type: str, value: str) -> Tuple[bool, str]:
    """Remove da blocked_entities (DB) — sem restart necessário."""
    try:
        from security.blocklist import unblock_entity

        if entity_type not in ["ip", "fp", "ln"]:
            return False, f"❌ Tipo inválido: {entity_type}"

        value = value.strip().lower()
        removed = unblock_entity(entity_type, value)

        if removed:
            return True, f"✅ Desbloqueado: {removed}\n⚡ Ativo imediatamente (sem restart)"
        else:
            return False, "❌ Não estava bloqueado"

    except Exception as e:
        return False, f"❌ Erro: {e}"


# ============================================================================
# WHITELIST (runtime + .env)
# ============================================================================

def _whitelist_add(ln_address: str) -> Tuple[bool, str]:
    """Adiciona LN address à WHITELIST_ADDRESSES sem restart."""
    try:
        from config import reload_whitelist
        from pathlib import Path

        ln = ln_address.strip().lower()
        if "@" not in ln:
            return False, f"❌ LN address inválido: {ln}"

        env_path = Path(__file__).parent / ".env"

        with open(env_path, "r") as f:
            content = f.read()

        if "WHITELIST_ADDRESSES=" not in content:
            content += f"\nWHITELIST_ADDRESSES={ln}\n"
        else:
            pattern = r'^WHITELIST_ADDRESSES=(.*)$'
            match = re.search(pattern, content, re.MULTILINE)
            if match:
                current = match.group(1).strip()
                addresses = [a.strip() for a in current.split(",") if a.strip()]

                if ln in addresses:
                    return False, f"❌ Já está na whitelist: {ln}"

                addresses.append(ln)
                new_line = f"WHITELIST_ADDRESSES={','.join(addresses)}"
                content = re.sub(pattern, new_line, content, flags=re.MULTILINE)

        with open(env_path, "w") as f:
            f.write(content)

        reload_whitelist()

        return True, (
            f"✅ Adicionado à whitelist: <code>{ln}</code>\n"
            f"⚡ Ativo imediatamente (sem restart)"
        )

    except Exception as e:
        return False, f"❌ Erro: {e}"


def _whitelist_remove(ln_address: str) -> Tuple[bool, str]:
    """Remove LN address da WHITELIST_ADDRESSES sem restart."""
    try:
        from config import reload_whitelist
        from pathlib import Path

        ln = ln_address.strip().lower()
        env_path = Path(__file__).parent / ".env"

        with open(env_path, "r") as f:
            content = f.read()

        pattern = r'^WHITELIST_ADDRESSES=(.*)$'
        match = re.search(pattern, content, re.MULTILINE)

        if not match:
            return False, "❌ WHITELIST_ADDRESSES não encontrado no .env"

        current = match.group(1).strip()
        addresses = [a.strip() for a in current.split(",") if a.strip()]

        if ln not in addresses:
            return False, f"❌ Não está na whitelist: {ln}"

        addresses.remove(ln)
        new_line = f"WHITELIST_ADDRESSES={','.join(addresses)}"
        content = re.sub(pattern, new_line, content, flags=re.MULTILINE)

        with open(env_path, "w") as f:
            f.write(content)

        reload_whitelist()

        return True, f"✅ Removido da whitelist: <code>{ln}</code>\n⚡ Ativo imediatamente (sem restart)"

    except Exception as e:
        return False, f"❌ Erro: {e}"


def _whitelist_list() -> str:
    """Lista endereços na whitelist."""
    try:
        from config import WHITELIST

        if not WHITELIST:
            return "📭 Whitelist vazia"

        items = "\n".join([f"• <code>{addr}</code>" for addr in sorted(WHITELIST)])
        return f"✅ <b>Whitelist ({len(WHITELIST)}):</b>\n{items}"

    except Exception as e:
        return f"❌ Erro: {e}"


# ============================================================================
# SYSTEMCTL (restart/stop/start)
# ============================================================================

def _systemctl(action: str) -> Tuple[bool, str]:
    """Executa comando systemctl no serviço do faucet usando sudo -S com senha do .env."""
    try:
        labels = {
            "restart": ("🔄", "reiniciado"),
            "stop": ("🛑", "parado"),
            "start": ("▶️", "iniciado"),
            "status": ("📊", "status")
        }

        icon, verb = labels.get(action, ("⚙️", action))

        cmd = ["sudo", "-S", "systemctl", action, SERVICE_NAME]
        stdin_input = (SUDO_PASS + "\n") if SUDO_PASS else None

        result = subprocess.run(
            cmd,
            input=stdin_input,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            return True, f"{icon} <b>Serviço {verb} com sucesso</b>"
        else:
            err = result.stderr.replace(SUDO_PASS, "***") if SUDO_PASS else result.stderr
            return False, f"❌ Erro ({result.returncode}):\n<pre>{err[:500]}</pre>"

    except subprocess.TimeoutExpired:
        return False, f"❌ Timeout ao executar {action}"
    except Exception as e:
        return False, f"❌ Erro: {e}"


# ============================================================================
# WALLET & INVOICE
# ============================================================================

async def _wallet_balance() -> str:
    """Consulta saldo da wallet LNbits."""
    try:
        url = f"{LNBITS_URL}/api/v1/wallet"
        headers = {"X-Api-Key": LNBITS_ADMIN_KEY}

        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url, headers=headers)
            r.raise_for_status()
            data = r.json()

        balance_msats = data.get("balance", 0)
        balance_sats = balance_msats / 1000

        return f"💰 <b>Saldo:</b> {balance_sats:,.0f} sats"

    except Exception as e:
        return f"❌ Erro ao consultar saldo: {e}"


async def _generate_invoice(amount_sats: int = 2000) -> str:
    """Gera invoice LNbits."""
    try:
        url = f"{LNBITS_URL}/api/v1/payments"
        headers = {"X-Api-Key": LNBITS_ADMIN_KEY, "Content-Type": "application/json"}
        payload = {
            "out": False,
            "amount": amount_sats,
            "memo": f"Reposição faucet - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC"
        }

        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, headers=headers, json=payload)
            r.raise_for_status()
            data = r.json()

        payment_request = data.get("payment_request", "")

        return f"⚡ <b>Invoice gerada:</b>\n<code>{payment_request}</code>\n\n💰 Valor: {amount_sats} sats"

    except Exception as e:
        return f"❌ Erro ao gerar invoice: {e}"


# ============================================================================
# MONITORAMENTO  (schema: claims.amount_sat, claims.claimed_at, claims.ip_address)
# ============================================================================

def _abuse_stats() -> str:
    """Estatísticas de abusos nas últimas 6h (claims com status=failed)."""
    try:
        import sqlite3
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row

        # Total de tentativas bloqueadas nas últimas 6h
        total = conn.execute("""
            SELECT COUNT(*) as c FROM claims
            WHERE status = 'failed'
            AND datetime(claimed_at) >= datetime('now', '-6 hours')
        """).fetchone()["c"] or 0

        # Top 3 IPs abusivos (6h)
        top_ips = conn.execute("""
            SELECT ip_address, COUNT(*) as c FROM claims
            WHERE status = 'failed'
            AND datetime(claimed_at) >= datetime('now', '-6 hours')
            AND ip_address IS NOT NULL
            GROUP BY ip_address ORDER BY c DESC LIMIT 3
        """).fetchall()

        # Top 3 LN addresses bloqueados (6h)
        top_lns = conn.execute("""
            SELECT ln_address, COUNT(*) as c FROM claims
            WHERE status = 'failed'
            AND datetime(claimed_at) >= datetime('now', '-6 hours')
            GROUP BY ln_address ORDER BY c DESC LIMIT 3
        """).fetchall()

        # Taxa de abuse (failed vs total 6h)
        total_all = conn.execute("""
            SELECT COUNT(*) as c FROM claims
            WHERE datetime(claimed_at) >= datetime('now', '-6 hours')
        """).fetchone()["c"] or 1

        conn.close()

        rate = (total / total_all * 100) if total_all > 0 else 0

        lines = [f"🚨 <b>Abusos (6h):</b> {total} bloqueados ({rate:.0f}%)\n"]

        if top_ips:
            lines.append("<b>Top IPs:</b>")
            for row in top_ips:
                ip = row["ip_address"] or "N/A"
                lines.append(f"• <code>{ip[:20]}</code> — {row['c']}x")

        if top_lns:
            lines.append("\n<b>Top LN:</b>")
            for row in top_lns:
                ln = row["ln_address"][:25] + "..." if len(row["ln_address"]) > 25 else row["ln_address"]
                lines.append(f"• <code>{ln}</code> — {row['c']}x")

        return "\n".join(lines)

    except Exception as e:
        return f"❌ Erro: {e}"


def _recent_claims() -> str:
    """Últimos 10 claims."""
    try:
        import sqlite3
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row

        query = """
            SELECT ln_address, amount_sat, claimed_at
            FROM claims
            ORDER BY claimed_at DESC
            LIMIT 10
        """
        rows = conn.execute(query).fetchall()
        conn.close()

        if not rows:
            return "📭 Nenhum claim recente"

        lines = ["📊 <b>Últimos 10 claims:</b>\n"]
        for row in rows:
            ln = row["ln_address"][:20] + "..." if len(row["ln_address"]) > 20 else row["ln_address"]
            amount = row["amount_sat"]
            ts = row["claimed_at"][:16]
            lines.append(f"• {ln} — {amount} sats ({ts})")

        return "\n".join(lines)

    except Exception as e:
        return f"❌ Erro: {e}"


def _hour_stats() -> str:
    """Stats da última hora."""
    try:
        import sqlite3
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row

        query = """
            SELECT
                COUNT(*) as total,
                COALESCE(SUM(amount_sat), 0) as sats,
                COUNT(DISTINCT ip_address) as unique_ips,
                COUNT(DISTINCT fp_hash) as unique_fps
            FROM claims
            WHERE datetime(claimed_at) >= datetime('now', '-1 hour')
        """
        row = conn.execute(query).fetchone()
        conn.close()

        total = row["total"] or 0
        sats = row["sats"] or 0
        ips = row["unique_ips"] or 0
        fps = row["unique_fps"] or 0

        return (
            f"📈 <b>Última hora:</b>\n"
            f"• Claims: {total}\n"
            f"• Sats distribuídos: {sats}\n"
            f"• IPs únicos: {ips}\n"
            f"• FPs únicos: {fps}"
        )

    except Exception as e:
        return f"❌ Erro: {e}"


def _motivo24() -> str:
    """Bloqueios dinâmicos (claims failed) nas últimas 24h + bloqueios manuais recentes."""
    try:
        import sqlite3
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row

        total = conn.execute("""
            SELECT COUNT(*) as c FROM claims
            WHERE status = 'failed'
            AND datetime(claimed_at) >= datetime('now', '-24 hours')
        """).fetchone()["c"] or 0

        top_lns = conn.execute("""
            SELECT ln_address, COUNT(*) as c FROM claims
            WHERE status = 'failed'
            AND datetime(claimed_at) >= datetime('now', '-24 hours')
            GROUP BY ln_address ORDER BY c DESC LIMIT 8
        """).fetchall()

        top_fps = conn.execute("""
            SELECT fp_hash, COUNT(*) as c FROM claims
            WHERE status = 'failed'
            AND datetime(claimed_at) >= datetime('now', '-24 hours')
            AND fp_hash IS NOT NULL
            GROUP BY fp_hash ORDER BY c DESC LIMIT 8
        """).fetchall()

        top_ja3 = conn.execute("""
            SELECT ja3_hash, COUNT(*) as c FROM claims
            WHERE status = 'failed'
            AND datetime(claimed_at) >= datetime('now', '-24 hours')
            AND ja3_hash IS NOT NULL
            GROUP BY ja3_hash ORDER BY c DESC LIMIT 5
        """).fetchall()

        top_ips = conn.execute("""
            SELECT ip_address, COUNT(*) as c FROM claims
            WHERE status = 'failed'
            AND datetime(claimed_at) >= datetime('now', '-24 hours')
            AND ip_address IS NOT NULL
            GROUP BY ip_address ORDER BY c DESC LIMIT 8
        """).fetchall()

        manual_blocks = conn.execute("""
            SELECT entity_type, entity_value, reason, blocked_at
            FROM blocked_entities
            WHERE datetime(blocked_at) >= datetime('now', '-24 hours')
            ORDER BY blocked_at DESC
        """).fetchall()

        conn.close()

        if total == 0 and not manual_blocks:
            return "✅ <b>Nenhum bloqueio nas últimas 24h</b>"

        lines = [f"🚫 <b>Bloqueios 24h — {total} tentativas negadas</b>\n"]

        if top_lns:
            lines.append("🔗 <b>LN Address bloqueados:</b>")
            for r in top_lns:
                ln = r["ln_address"]
                ln_t = ln[:28] + "…" if len(ln) > 28 else ln
                lines.append(f"  • <code>{ln_t}</code> — {r['c']}x")
            lines.append("")

        if top_fps:
            lines.append("🖥️ <b>FP (Browser):</b>")
            for r in top_fps:
                fp = (r["fp_hash"] or "")[:20] + "…"
                lines.append(f"  • <code>{fp}</code> — {r['c']}x")
            lines.append("")

        if top_ja3:
            lines.append("🔐 <b>FP Agent (JA3/TLS):</b>")
            for r in top_ja3:
                j = (r["ja3_hash"] or "")[:20] + "…"
                lines.append(f"  • <code>{j}</code> — {r['c']}x")
            lines.append("")

        if top_ips:
            lines.append("🌐 <b>IPs:</b>")
            for r in top_ips:
                lines.append(f"  • <code>{r['ip_address']}</code> — {r['c']}x")
            lines.append("")

        if manual_blocks:
            lines.append(f"🔒 <b>Bloqueios manuais ({len(manual_blocks)}):</b>")
            for r in manual_blocks[:10]:
                val = r["entity_value"][:28] + "…" if len(r["entity_value"]) > 28 else r["entity_value"]
                reason = r["reason"] or "—"
                lines.append(f"  • [{r['entity_type']}] <code>{val}</code> — {reason}")

        return "\n".join(lines).rstrip()

    except Exception as e:
        return f"❌ Erro: {e}"


# ============================================================================
# CONSULTA DE PAGAMENTO ORPHAN
# ============================================================================

async def _check_lnbits_status(payment_hash: str) -> Tuple[Optional[bool], str]:
    """Consulta o LNbits para um payment_hash.

    Retorna (ln_paid, ln_status_line):
      ln_paid=True  -> pago e confirmado (preimage presente)
      ln_paid=False -> não encontrado ou falhou (conclusivo, não saiu)
      ln_paid=None  -> status incerto, precisa revisão manual
    """
    try:
        headers = {"X-Api-Key": LNBITS_ADMIN_KEY}
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"{LNBITS_URL}/api/v1/payment/{payment_hash}",
                headers=headers,
            )
        if r.status_code == 404:
            return False, "❌ <b>NÃO encontrado no LNbits</b> — pagamento nunca foi iniciado ou já expirou."
        elif r.status_code != 200:
            return None, f"⚠️ LNbits retornou HTTP {r.status_code}"

        data = r.json()
        paid = data.get("paid") or (data.get("status") == "complete")
        preimage = data.get("preimage") or data.get("payment_preimage") or ""
        amount_msat = abs(data.get("amount") or data.get("details", {}).get("amount", 0))
        amount_sat = amount_msat // 1000

        if paid and preimage:
            return True, (
                f"✅ <b>PAGO e confirmado no LNbits</b>\n"
                f"  Preimage: <code>{preimage[:32]}…</code>\n"
                f"  Valor: <b>{amount_sat} sats</b>"
            )
        elif data.get("status") == "failed":
            return False, "❌ <b>FALHOU no LNbits</b> — roteamento não concluído."
        else:
            return None, f"⏳ <b>Status incerto no LNbits:</b> <code>{data.get('status','?')}</code>"
    except Exception as e:
        return None, f"❌ Erro ao consultar LNbits: {e}"


async def _consultar_pagamento(payment_hash: str) -> str:
    """Consulta no LNbits se o pagamento foi realizado e mostra o claim no DB."""
    payment_hash = payment_hash.strip().lower()
    if not re.match(r'^[a-f0-9]{64}$', payment_hash):
        return "❌ Hash inválido. Deve ter 64 caracteres hexadecimais."

    # Busca o claim no banco
    try:
        import sqlite3
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        claim = conn.execute(
            "SELECT id, ln_address, amount_sat, status, claimed_at, ip_address FROM claims WHERE payment_hash=? LIMIT 1",
            (payment_hash,)
        ).fetchone()
        conn.close()
    except Exception as e:
        return f"❌ Erro ao consultar DB: {e}"

    db_lines = []
    if claim:
        db_lines = [
            f"📋 <b>Claim no DB:</b>",
            f"  ID: <code>{claim['id']}</code>",
            f"  Status: <code>{claim['status']}</code>",
            f"  LN: <code>{claim['ln_address']}</code>",
            f"  Valor: <b>{claim['amount_sat']} sats</b>",
            f"  Data: {(claim['claimed_at'] or '')[:16]}",
            f"  IP: <code>{claim['ip_address'] or 'N/A'}</code>",
        ]
    else:
        db_lines = ["⚠️ Claim não encontrado no DB para este hash."]

    ln_paid, ln_status = await _check_lnbits_status(payment_hash)

    # Sugestão de ação
    if ln_paid is True:
        acao = (
            f"\n💡 <b>Ação sugerida:</b> pagamento confirmado — marcar como paid:\n"
            f"<code>/confirmar {payment_hash}</code>"
        )
    elif ln_paid is False:
        acao = (
            f"\n💡 <b>Ação sugerida:</b> pagamento não saiu — liberar re-claim:\n"
            f"<code>/liberar {payment_hash}</code>"
        )
    else:
        acao = (
            f"\n💡 Status incerto. Use:\n"
            f"<code>/confirmar {payment_hash}</code> — se os sats foram enviados\n"
            f"<code>/liberar {payment_hash}</code> — para liberar re-claim"
        )

    lines = [f"🔍 <b>Consulta de pagamento</b>\n<code>{payment_hash[:32]}…</code>\n"]
    lines += db_lines
    lines += [f"\n{ln_status}", acao]
    return "\n".join(lines)


def _confirmar_pagamento(payment_hash: str) -> str:
    """Marca o claim como 'paid' — sats foram enviados e confirmados."""
    payment_hash = payment_hash.strip().lower()
    if not re.match(r'^[a-f0-9]{64}$', payment_hash):
        return "❌ Hash inválido."
    try:
        import sqlite3
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        claim = conn.execute(
            "SELECT id, ln_address, amount_sat, status FROM claims WHERE payment_hash=? LIMIT 1",
            (payment_hash,)
        ).fetchone()
        if not claim:
            conn.close()
            return "❌ Claim não encontrado para este hash."
        if claim["status"] == "paid":
            conn.close()
            return f"ℹ️ Claim <code>{claim['id']}</code> já está marcado como <code>paid</code>."
        conn.execute("UPDATE claims SET status='paid' WHERE payment_hash=?", (payment_hash,))
        conn.commit()
        conn.close()
        return (
            f"✅ <b>Claim {claim['id']} marcado como paid</b>\n"
            f"LN: <code>{claim['ln_address']}</code>\n"
            f"Valor: {claim['amount_sat']} sats\n"
            f"Usuário bloqueado de re-claim pelo resto do dia."
        )
    except Exception as e:
        return f"❌ Erro: {e}"


def _liberar_claim(payment_hash: str) -> str:
    """Marca o claim como 'failed' — sats não saíram, libera re-claim."""
    payment_hash = payment_hash.strip().lower()
    if not re.match(r'^[a-f0-9]{64}$', payment_hash):
        return "❌ Hash inválido."
    try:
        import sqlite3
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        claim = conn.execute(
            "SELECT id, ln_address, amount_sat, status FROM claims WHERE payment_hash=? LIMIT 1",
            (payment_hash,)
        ).fetchone()
        if not claim:
            conn.close()
            return "❌ Claim não encontrado para este hash."
        if claim["status"] == "failed":
            conn.close()
            return f"ℹ️ Claim <code>{claim['id']}</code> já está marcado como <code>failed</code>."
        conn.execute("UPDATE claims SET status='failed' WHERE payment_hash=?", (payment_hash,))
        conn.commit()
        conn.close()
        return (
            f"🔓 <b>Claim {claim['id']} liberado para re-claim</b>\n"
            f"LN: <code>{claim['ln_address']}</code>\n"
            f"Usuário pode tentar novamente agora."
        )
    except Exception as e:
        return f"❌ Erro: {e}"


# ============================================================================
# RESOLUÇÃO AUTOMÁTICA DE CLAIMS ORPHAN
# ============================================================================

_orphan_uncertain_alerted: dict = {}  # payment_hash -> timestamp do último alerta
_ORPHAN_ALERT_COOLDOWN = 3600  # não repete alerta de status incerto por 1h


async def _auto_resolve_orphans() -> None:
    """Roda a cada N minutos: consulta o LNbits para cada claim 'orphan' e
    resolve automaticamente quando o status for conclusivo.

    - Pago e confirmado (preimage)      -> marca 'paid'
    - Não encontrado / falhou no LNbits -> marca 'failed' (libera re-claim)
    - Status incerto                    -> mantém 'orphan', alerta manual (com cooldown)
    """
    try:
        import sqlite3
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        orphans = conn.execute(
            "SELECT id, payment_hash, ln_address, amount_sat FROM claims "
            "WHERE status='orphan' AND payment_hash IS NOT NULL AND payment_hash != ''"
        ).fetchall()
        conn.close()
    except Exception as e:
        logger.error(f"Auto-resolve orphans: erro ao consultar DB: {e}")
        return

    if not orphans:
        return

    resolved = []
    still_uncertain = []

    for row in orphans:
        payment_hash = row["payment_hash"]
        ln_paid, _ln_status = await _check_lnbits_status(payment_hash)

        if ln_paid is True:
            _confirmar_pagamento(payment_hash)
            resolved.append(
                f"✅ <b>Claim {row['id']}</b> auto-confirmado (paid)\n"
                f"LN: <code>{row['ln_address']}</code> — {row['amount_sat']} sats"
            )
            logger.info(f"Auto-resolve: claim {row['id']} marcado paid (hash={payment_hash[:16]}...)")
        elif ln_paid is False:
            _liberar_claim(payment_hash)
            resolved.append(
                f"🔓 <b>Claim {row['id']}</b> auto-liberado (failed)\n"
                f"LN: <code>{row['ln_address']}</code>"
            )
            logger.info(f"Auto-resolve: claim {row['id']} marcado failed (hash={payment_hash[:16]}...)")
        else:
            last_alert = _orphan_uncertain_alerted.get(payment_hash, 0)
            if _time.time() - last_alert > _ORPHAN_ALERT_COOLDOWN:
                _orphan_uncertain_alerted[payment_hash] = _time.time()
                still_uncertain.append(
                    f"⏳ <b>Claim {row['id']}</b> status incerto — revisar manualmente:\n"
                    f"LN: <code>{row['ln_address']}</code>\n"
                    f"<code>/consulta {payment_hash}</code>"
                )

    if resolved or still_uncertain:
        parts = ["🔍 <b>Análise automática de claims orphan</b>"]
        parts += resolved
        parts += still_uncertain
        await send_telegram(TELEGRAM_CHAT_ID, "\n\n".join(parts))


async def run_orphan_check(interval_seconds: int = 300):
    """Loop periódico — analisa e resolve claims orphan automaticamente (default: 5min)."""
    while True:
        try:
            await asyncio.sleep(interval_seconds)
            await _auto_resolve_orphans()
        except Exception as e:
            logger.error(f"Erro no orphan check: {e}")


# ============================================================================
# TOGGLE .ENV (PROGRESSIVE & FP_BLOCK_STRICT)
# ============================================================================

def _toggle_env(key: str, current_value: str) -> Tuple[bool, str]:
    """
    Alterna valor true/false no .env sem restart.
    Retorna: (sucesso, mensagem)
    """
    try:
        from pathlib import Path

        env_path = Path(__file__).parent / ".env"

        with open(env_path, "r") as f:
            content = f.read()

        new_value = "false" if current_value.lower() == "true" else "true"

        pattern = rf'^{key}=.*$'
        replacement = f'{key}={new_value}'

        new_content = re.sub(pattern, replacement, content, flags=re.MULTILINE)

        with open(env_path, "w") as f:
            f.write(new_content)

        # Recarregar variável no config (runtime)
        if key == "PROGRESSIVE_REWARDS":
            import config
            config.PROGRESSIVE_REWARDS = (new_value.lower() == "true")
        elif key == "FP_BLOCK_STRICT":
            import config
            config.FP_BLOCK_STRICT = (new_value.lower() == "true")

        status_icon = "✅" if new_value == "true" else "❌"
        return True, f"{status_icon} <b>{key}</b> alterado para: <code>{new_value}</code>\n⚡ Ativo imediatamente (sem restart)"

    except Exception as e:
        return False, f"❌ Erro ao alterar {key}: {e}"


# ============================================================================
# HANDLE MESSAGE
# ============================================================================

async def handle_message(update: dict) -> Optional[str]:
    """Processa comandos do Telegram."""
    msg = update.get("message", {})
    text = (msg.get("text") or "").strip()
    chat_id = str(msg.get("chat", {}).get("id", ""))
    username = msg.get("from", {}).get("username", "unknown")

    if not text or chat_id != TELEGRAM_CHAT_ID:
        return None

    cmd = text.split()[0].lower()
    args = text.split()[1:] if len(text.split()) > 1 else []

    # ─── BLOQUEIOS ────────────────────────────────────────────────────────
    if cmd == "/block_ip":
        if not args:
            return "❌ Uso: /block_ip 1.2.3.4"
        ok, msg = _block_entity("ip", args[0])
        return msg

    elif cmd == "/block_fp":
        if not args:
            return "❌ Uso: /block_fp <hash>"
        ok, msg = _block_entity("fp", args[0])
        return msg

    elif cmd == "/block_ln":
        if not args:
            return "❌ Uso: /block_ln user@domain.com"
        ok, msg = _block_entity("ln", args[0])
        return msg

    elif cmd == "/unblock_ip":
        if not args:
            return "❌ Uso: /unblock_ip 1.2.3.4"
        ok, msg = _unblock_entity("ip", args[0])
        return msg

    elif cmd == "/unblock_fp":
        if not args:
            return "❌ Uso: /unblock_fp <hash>"
        ok, msg = _unblock_entity("fp", args[0])
        return msg

    elif cmd == "/unblock_ln":
        if not args:
            return "❌ Uso: /unblock_ln user@domain.com"
        ok, msg = _unblock_entity("ln", args[0])
        return msg

    # ─── WHITELIST ────────────────────────────────────────────────────────
    elif cmd == "/whitelist_add":
        if not args:
            return "❌ Uso: /whitelist_add user@wallet.com"
        ok, msg = _whitelist_add(args[0])
        return msg

    elif cmd == "/whitelist_remove":
        if not args:
            return "❌ Uso: /whitelist_remove user@wallet.com"
        ok, msg = _whitelist_remove(args[0])
        return msg

    elif cmd == "/whitelist_list":
        return _whitelist_list()

    # ─── SERVIÇO ──────────────────────────────────────────────────────────
    elif cmd == "/restart":
        ok, msg = _systemctl("restart")
        return msg

    elif cmd == "/down":
        ok, msg = _systemctl("stop")
        return msg

    elif cmd == "/up":
        ok, msg = _systemctl("start")
        return msg

    # ─── WALLET ───────────────────────────────────────────────────────────
    elif cmd == "/saldo":
        return await _wallet_balance()

    elif cmd == "/invoice":
        amount = int(args[0]) if args and args[0].isdigit() else 2000
        return await _generate_invoice(amount)

    # ─── MONITORAMENTO ────────────────────────────────────────────────────
    elif cmd == "/abuse":
        return _abuse_stats()

    elif cmd == "/recent":
        return _recent_claims()

    elif cmd == "/status":
        return _hour_stats()

    elif cmd == "/motivo24":
        return _motivo24()

    # ─── CONSULTA ORPHAN ──────────────────────────────────────────────────────
    elif cmd == "/consulta":
        if not args:
            return "❌ Uso: /consulta <payment_hash>"
        return await _consultar_pagamento(args[0])

    elif cmd == "/confirmar":
        if not args:
            return "❌ Uso: /confirmar <payment_hash>"
        return _confirmar_pagamento(args[0])

    elif cmd == "/liberar":
        if not args:
            return "❌ Uso: /liberar <payment_hash>"
        return _liberar_claim(args[0])

    # ─── TOGGLE CONFIG ────────────────────────────────────────────────────
    elif cmd == "/progressive":
        from config import PROGRESSIVE_REWARDS
        current = "true" if PROGRESSIVE_REWARDS else "false"
        ok, msg = _toggle_env("PROGRESSIVE_REWARDS", current)
        return msg

    elif cmd == "/fpblock":
        from config import FP_BLOCK_STRICT
        current = "true" if FP_BLOCK_STRICT else "false"
        ok, msg = _toggle_env("FP_BLOCK_STRICT", current)
        return msg

    # ─── HELP ─────────────────────────────────────────────────────────────
    elif cmd == "/help":
        response = (
            "🤖 <b>BTCFaucet Bot</b>\n\n"
            "<b>🔒 Bloqueios (sem restart):</b>\n"
            "/block_ip &lt;ip&gt; - Bloqueia IP\n"
            "/block_fp &lt;hash&gt; - Bloqueia fingerprint\n"
            "/block_ln &lt;addr&gt; - Bloqueia LN address\n"
            "/unblock_ip, /unblock_fp, /unblock_ln\n\n"
            "<b>✅ Whitelist (sem restart):</b>\n"
            "/whitelist_add &lt;addr&gt; - Adiciona\n"
            "/whitelist_remove &lt;addr&gt; - Remove\n"
            "/whitelist_list - Lista whitelists\n\n"
            "<b>⚙️ Serviço:</b>\n"
            "/restart - Reinicia o faucet\n"
            "/down - Derruba o faucet\n"
            "/up - Sobe o faucet\n\n"
            "<b>💰 Wallet:</b>\n"
            "/saldo - Consulta saldo da wallet\n"
            "/invoice [sats] - Gera invoice (padrão 2000 sats)\n\n"
            "<b>📊 Monitoramento:</b>\n"
            "/abuse - Abusos nas últimas 6h\n"
            "/recent - Últimos 10 claims\n"
            "/status - Stats da última hora\n"
            "/motivo24 - Motivos dos bloqueios (24h)\n\n"
            "<b>🔍 Pagamentos orphan:</b>\n"
            "/consulta &lt;hash&gt; - Verifica no LNbits se foi pago\n"
            "/confirmar &lt;hash&gt; - Marca como paid (sats enviados)\n"
            "/liberar &lt;hash&gt; - Marca como failed (libera re-claim)\n\n"
            "<b>🎛️ Configuração (sem restart):</b>\n"
            "/progressive - Toggle rewards progressivos\n"
            "/fpblock - Toggle FP strict mode\n\n"
            "/help - Esta mensagem"
        )
        return response

    return None


# ============================================================================
# FUNÇÕES CHAMADAS PELO MAIN.PY
# ============================================================================

async def run_monitor(interval_hours: int = 1):
    """
    Monitor periódico — executa a cada X horas.
    Envia relatório automático para o Telegram.
    """
    while True:
        try:
            await asyncio.sleep(interval_hours * 3600)

            stats_msg = _hour_stats()
            abuse_msg = _abuse_stats()

            report = f"📊 <b>Relatório Automático</b>\n\n{stats_msg}\n\n{abuse_msg}"
            await send_telegram(TELEGRAM_CHAT_ID, report)

        except Exception as e:
            logger.error(f"Erro no monitor: {e}")


async def send_alert(message: str):
    """
    Envia alerta urgente para o Telegram.
    Chamado pelo main.py quando detecta algo crítico.
    """
    try:
        await send_telegram(TELEGRAM_CHAT_ID, f"🚨 <b>ALERTA</b>\n\n{message}")
    except Exception as e:
        logger.error(f"Erro ao enviar alerta: {e}")


async def poll_commands():
    """
    Loop de polling para comandos do Telegram.
    Processa comandos enviados para o bot.
    """
    if not TELEGRAM_ENABLED:
        logger.warning("Bot desabilitado")
        return

    logger.info("🤖 Bot de comandos iniciado")
    offset = 0

    # Flush da fila de startup: avança o offset até o update mais recente sem
    # executar nenhum comando pendente (evita replay de /restart, /down, etc.)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates",
                params={"timeout": 0},
            )
            data = r.json()
            if data.get("ok") and data.get("result"):
                offset = data["result"][-1]["update_id"] + 1
                logger.info(f"Bot: fila inicial limpa — {len(data['result'])} update(s) ignorado(s) (offset={offset})")
    except Exception as e:
        logger.warning(f"Bot: falha ao limpar fila inicial: {e}")

    while True:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
            params = {"offset": offset, "timeout": 5}

            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, params=params)
                data = r.json()

            if not data.get("ok"):
                await asyncio.sleep(5)
                continue

            for update in data.get("result", []):
                offset = update["update_id"] + 1

                response = await handle_message(update)

                if response:
                    msg = update.get("message", {})
                    chat_id = str(msg.get("chat", {}).get("id", ""))
                    if chat_id:
                        await send_telegram(chat_id, response)

        except Exception as e:
            logger.error(f"Erro no polling: {e}")
            await asyncio.sleep(5)


# ============================================================================
# STANDALONE
# ============================================================================

if __name__ == "__main__":
    asyncio.run(poll_commands())
