"""
Bot de Monitoramento de Status - BTCFaucet
Verifica se o site está ONLINE/OFFLINE e notifica assinantes
"""

import asyncio
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional, Set

import httpx

from config import (
    FAUCET_URL,
    TELEGRAM_BOT2_TOKEN,
    TELEGRAM_BOT2_ENABLED,
    TELEGRAM_CHAT_ID,
    DB_PATH
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("faucet.monitor")

HEALTH_URL = "http://127.0.0.1:8420/health"
CHECK_INTERVAL = 30
BR_TZ = timezone(timedelta(hours=-3))


def now_br_str() -> str:
    return datetime.now(BR_TZ).strftime('%H:%M:%S')

BOT_TOKEN = TELEGRAM_BOT2_TOKEN
GROUP_CHAT_ID = TELEGRAM_CHAT_ID

current_status: Optional[bool] = None
subscribers: Set[str] = set()


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_subscribers_table():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitor_subscribers (
                chat_id TEXT PRIMARY KEY,
                subscribed_at TEXT NOT NULL,
                username TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitor_groups (
                chat_id TEXT PRIMARY KEY,
                group_name TEXT,
                added_at TEXT NOT NULL,
                added_by TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitor_last_message (
                chat_id TEXT PRIMARY KEY,
                message_id INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()


def get_last_message_id(chat_id: str) -> Optional[int]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT message_id FROM monitor_last_message WHERE chat_id=?", (chat_id,)
        ).fetchone()
        return row["message_id"] if row else None


def set_last_message_id(chat_id: str, message_id: int):
    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO monitor_last_message (chat_id, message_id, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(chat_id) DO UPDATE SET message_id=excluded.message_id, updated_at=excluded.updated_at",
            (chat_id, message_id, now)
        )
        conn.commit()


def load_subscribers():
    global subscribers
    with get_db() as conn:
        rows = conn.execute("SELECT chat_id FROM monitor_subscribers").fetchall()
        subscribers = {row['chat_id'] for row in rows}
    logger.info(f"Carregados {len(subscribers)} assinantes")


def add_subscriber(chat_id: str, username: Optional[str] = None) -> bool:
    try:
        now = datetime.utcnow().isoformat()
        with get_db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO monitor_subscribers (chat_id, subscribed_at, username) VALUES (?,?,?)",
                (chat_id, now, username)
            )
            conn.commit()
        subscribers.add(chat_id)
        return True
    except Exception as e:
        logger.error(f"Erro ao adicionar assinante: {e}")
        return False


def remove_subscriber(chat_id: str) -> bool:
    try:
        with get_db() as conn:
            conn.execute("DELETE FROM monitor_subscribers WHERE chat_id=?", (chat_id,))
            conn.commit()
        subscribers.discard(chat_id)
        return True
    except Exception as e:
        logger.error(f"Erro ao remover assinante: {e}")
        return False



def add_group(chat_id: str, group_name: str = None, added_by: str = None) -> bool:
    try:
        now = datetime.utcnow().isoformat()
        with get_db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO monitor_groups (chat_id, group_name, added_at, added_by) VALUES (?,?,?,?)",
                (chat_id, group_name, now, added_by)
            )
            conn.commit()
        return True
    except Exception as e:
        logger.error(f"Erro ao adicionar grupo: {e}")
        return False


def remove_group(chat_id: str) -> bool:
    try:
        with get_db() as conn:
            conn.execute("DELETE FROM monitor_groups WHERE chat_id=?", (chat_id,))
            conn.commit()
        return True
    except Exception as e:
        logger.error(f"Erro ao remover grupo: {e}")
        return False


def list_groups() -> list:
    try:
        with get_db() as conn:
            rows = conn.execute("SELECT chat_id, group_name, added_at FROM monitor_groups").fetchall()
            return [{"chat_id": r["chat_id"], "name": r["group_name"], "added_at": r["added_at"]} for r in rows]
    except Exception as e:
        logger.error(f"Erro ao listar grupos: {e}")
        return []


async def send_telegram(chat_id: str, text: str) -> Optional[int]:
    if not TELEGRAM_BOT2_ENABLED:
        return None

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                }
            )
            if r.status_code != 200:
                return None
            return r.json().get("result", {}).get("message_id")
    except Exception as e:
        logger.error(f"Erro ao enviar para {chat_id}: {e}")
        return None


async def delete_telegram(chat_id: str, message_id: int) -> bool:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/deleteMessage",
                json={"chat_id": chat_id, "message_id": message_id}
            )
            return r.status_code == 200
    except Exception as e:
        logger.warning(f"Erro ao apagar mensagem anterior em {chat_id}: {e}")
        return False


async def send_status_update(chat_id: str, text: str):
    """Envia uma mensagem de status apagando a anterior enviada para o mesmo chat."""
    last_id = get_last_message_id(chat_id)
    if last_id:
        await delete_telegram(chat_id, last_id)

    new_id = await send_telegram(chat_id, text)
    if new_id:
        set_last_message_id(chat_id, new_id)


async def broadcast_status(message: str):
    # Enviar para o grupo configurado no .env (se houver)
    if GROUP_CHAT_ID:
        await send_status_update(GROUP_CHAT_ID, message)

    # Enviar para grupos cadastrados dinamicamente
    groups = list_groups()
    for group in groups:
        await send_status_update(group["chat_id"], message)

    # Enviar para assinantes individuais
    for chat_id in list(subscribers):
        await send_status_update(chat_id, message)


async def check_health() -> bool:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(HEALTH_URL)
            return r.status_code == 200
    except:
        return False


async def monitor_loop():
    global current_status
    
    logger.info("🔍 Monitor iniciado")
    _online_since: float = 0  # timestamp de quando detectou online pela 1a vez
    _online_confirmed: bool = False  # se já confirmou os 120s
    
    while True:
        try:
            is_online = await check_health()
            
            if current_status is None:
                current_status = is_online
                status = "ONLINE" if is_online else "OFFLINE"
                await broadcast_status(
                    f"{'✅' if is_online else '❌'} <b>Monitor Iniciado</b>\n\n"
                    f"Status: <b>{status}</b>\n"
                    f"Verificação a cada {CHECK_INTERVAL}s"
                )
            
            elif current_status != is_online:
                if is_online:
                    # Site voltou — iniciar contagem de confirmação
                    import time
                    if _online_since == 0:
                        _online_since = time.time()
                        logger.warning("🟢 Site ONLINE — aguardando 120s para confirmar...")
                    elif time.time() - _online_since >= 120:
                        # Confirmar que está online há 120s+
                        still_online = await check_health()
                        if still_online:
                            logger.info("✅ Site confirmado ONLINE após 120s")
                            current_status = True
                            _online_since = 0
                            _online_confirmed = True
                            await broadcast_status(
                                "🟢 <b>SITE VOLTOU ONLINE</b>\n\n"
                                f"✅ BTCFaucet acessível\n"
                                f"🌐 URL: {FAUCET_URL}\n"
                                f"🕐 {now_br_str()} (Brasília)"
                            )
                        else:
                            logger.warning("⚠️ Site caiu novamente antes da confirmação")
                            _online_since = 0
                else:
                    # Site caiu
                    _online_since = 0
                    current_status = False
                    logger.error("🔴 Site OFFLINE")
                    await broadcast_status(
                        "❌ <b>Status: OFFLINE</b>\n\n"
                        f"🌐 URL: {FAUCET_URL}\n"
                        f"🕐 Última verificação: {now_br_str()} (Brasília)"
                    )
            else:
                # Status não mudou — resetar contagem se estava esperando confirmação
                if is_online:
                    _online_since = 0
        
        except Exception as e:
            logger.error(f"Erro no monitor: {e}")
        
        await asyncio.sleep(CHECK_INTERVAL)


async def handle_command(update: dict) -> Optional[str]:
    msg = update.get("message", {})
    chat_id = str(msg.get("chat", {}).get("id", ""))
    text = msg.get("text", "").strip()
    username = msg.get("from", {}).get("username", "")
    
    if not text.startswith("/"):
        return None
    
    cmd = text.split()[0].lower()
    
    if cmd == "/status":
        if current_status is None:
            return "⏳ <b>Status: VERIFICANDO...</b>"
        
        status = "ONLINE" if current_status else "OFFLINE"
        emoji = "✅" if current_status else "❌"
        
        return (
            f"{emoji} <b>Status: {status}</b>\n\n"
            f"URL: https://bitcoinfaucet.st\n"
            f"Última verificação: {now_br_str()} (Brasília)"
        )
    
    elif cmd == "/subscribe":
        if chat_id in subscribers:
            return "✅ Você já está inscrito!"
        
        if add_subscriber(chat_id, username):
            return (
                "✅ <b>Inscrição confirmada!</b>\n\n"
                "Você receberá notificações quando:\n"
                "• Site ficar OFFLINE\n"
                "• Site voltar ONLINE\n\n"
                "Use /unsubscribe para cancelar."
            )
        return "❌ Erro ao processar inscrição."
    
    elif cmd == "/unsubscribe":
        if chat_id not in subscribers:
            return "⚠️ Você não está inscrito."
        
        if remove_subscriber(chat_id):
            return "✅ <b>Inscrição cancelada</b>"
        return "❌ Erro ao cancelar inscrição."
    
    elif cmd == "/help":
        base_help = (
            "🤖 <b>BTCFaucet Monitor Bot</b>\n\n"
            "<b>Comandos:</b>\n"
            "/status - Status atual\n"
            "/subscribe - Receber notificações\n"
            "/unsubscribe - Cancelar\n"
            "/help - Esta mensagem"
        )
        
        # Comandos admin (apenas para ADMIN_TOKEN)
        from_id = str(msg.get("from", {}).get("id", ""))
        from config import ADMIN_TOKEN
        if from_id == str(ADMIN_TOKEN):
            base_help += (
                "\n\n<b>Comandos Admin:</b>\n"
                "/add_group - Adicionar este grupo aos alertas\n"
                "/remove_group - Remover grupo\n"
                "/list_groups - Listar grupos cadastrados"
            )
        
        return base_help
    
    elif cmd == "/add_group":
        from config import ADMIN_TOKEN
        from_id = str(msg.get("from", {}).get("id", ""))
        
        if from_id != str(ADMIN_TOKEN):
            return "❌ Comando restrito ao administrador"
        
        chat_type = msg.get("chat", {}).get("type", "private")
        if chat_type == "private":
            return "⚠️ Use este comando dentro de um grupo"
        
        group_name = msg.get("chat", {}).get("title", "Grupo sem nome")
        
        if add_group(chat_id, group_name, username):
            return f"✅ <b>Grupo adicionado!</b>\n\n{group_name} receberá alertas de status."
        return "❌ Erro ao adicionar grupo"
    
    elif cmd == "/remove_group":
        from config import ADMIN_TOKEN
        from_id = str(msg.get("from", {}).get("id", ""))
        
        if from_id != str(ADMIN_TOKEN):
            return "❌ Comando restrito ao administrador"
        
        if remove_group(chat_id):
            return "✅ <b>Grupo removido</b>"
        return "❌ Erro ao remover grupo"
    
    elif cmd == "/list_groups":
        from config import ADMIN_TOKEN
        from_id = str(msg.get("from", {}).get("id", ""))
        
        if from_id != str(ADMIN_TOKEN):
            return "❌ Comando restrito ao administrador"
        
        groups = list_groups()
        if not groups:
            return "📭 Nenhum grupo cadastrado"
        
        lines = ["📋 <b>Grupos Cadastrados</b>\n"]
        for g in groups:
            name = g["name"] or "Sem nome"
            date = g["added_at"][:10]
            lines.append(f"• {name} (desde {date})")
        
        return "\n".join(lines)
    
    return None


async def poll_commands():
    if not TELEGRAM_BOT2_ENABLED:
        logger.warning("Bot 2 desabilitado (TELEGRAM_BOT2_TOKEN vazio)")
        return
    
    logger.info("🤖 Bot de comandos iniciado")
    
    # Limpar fila
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates",
                params={"offset": -1, "timeout": 0}
            )
            data = r.json()
            if data.get("ok") and data.get("result"):
                last_id = data["result"][-1]["update_id"]
                await client.get(
                    f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates",
                    params={"offset": last_id + 1, "timeout": 0}
                )
    except:
        pass
    
    offset = 0
    
    while True:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(
                    f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates",
                    params={"offset": offset, "timeout": 10}
                )
                
                if r.status_code == 200:
                    data = r.json()
                    if data.get("ok") and data.get("result"):
                        for update in data["result"]:
                            offset = update["update_id"] + 1
                            
                            response = await handle_command(update)
                            if response:
                                chat_id = str(update.get("message", {}).get("chat", {}).get("id", ""))
                                await send_telegram(chat_id, response)
        
        except Exception as e:
            logger.error(f"Erro no polling: {e}")
        
        await asyncio.sleep(3)


async def main():
    if not TELEGRAM_BOT2_ENABLED:
        logger.error("❌ TELEGRAM_BOT2_TOKEN não configurado")
        return
    
    logger.info("=" * 60)
    logger.info("BTCFaucet Status Monitor Bot")
    logger.info("=" * 60)
    
    init_subscribers_table()
    load_subscribers()
    
    await asyncio.gather(
        monitor_loop(),
        poll_commands()
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Monitor encerrado")
