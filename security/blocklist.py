"""
Módulo de gerenciamento de bloqueios dinâmicos
Consolida verificação de IP, FP, LN address e node pubkey
"""
import sqlite3
from typing import Optional, Tuple
from config import DB_PATH, WHITELIST, WHITELIST_ADM


def get_db():
    """Conexão com SQLite"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def block_entity(entity_type: str, entity_value: str) -> Tuple[bool, str]:
    """
    Bloqueia IP, LN address ou fingerprint dinamicamente.
    
    Args:
        entity_type: 'ip', 'ln', 'fp', ou 'ja3'
        entity_value: Valor a ser bloqueado
    
    Returns:
        (success, message)
    """
    ALLOWED_ENTITY_TYPES = {"ip", "ln", "fp", "ja3"}
    
    if entity_type not in ALLOWED_ENTITY_TYPES:
        return False, f"❌ Tipo inválido. Use: {', '.join(ALLOWED_ENTITY_TYPES)}"
    
    try:
        from datetime import datetime
        now = datetime.utcnow().isoformat()
        
        with get_db() as conn:
            # Verificar se já existe
            existing = conn.execute(
                "SELECT 1 FROM blocked_entities WHERE entity_type=? AND entity_value=? LIMIT 1",
                (entity_type, entity_value)
            ).fetchone()
            
            if existing:
                return False, f"⚠️ {entity_type.upper()} já está bloqueado: {entity_value}"
            
            # Inserir bloqueio
            conn.execute(
                "INSERT INTO blocked_entities (entity_type, entity_value, blocked_at) VALUES (?,?,?)",
                (entity_type, entity_value, now)
            )
            conn.commit()
            
        return True, f"✅ Bloqueado: {entity_type.upper()} = {entity_value}"
    
    except Exception as e:
        return False, f"❌ Erro ao bloquear: {e}"


def unblock_entity(entity_type: str, entity_value: str) -> Tuple[bool, str]:
    """
    Remove bloqueio de IP, LN address ou fingerprint.
    
    Returns:
        (success, message)
    """
    ALLOWED_ENTITY_TYPES = {"ip", "ln", "fp", "ja3"}
    
    if entity_type not in ALLOWED_ENTITY_TYPES:
        return False, f"❌ Tipo inválido. Use: {', '.join(ALLOWED_ENTITY_TYPES)}"
    
    try:
        with get_db() as conn:
            result = conn.execute(
                "DELETE FROM blocked_entities WHERE entity_type=? AND entity_value=?",
                (entity_type, entity_value)
            )
            conn.commit()
            
            if result.rowcount == 0:
                return False, f"⚠️ {entity_type.upper()} não estava bloqueado: {entity_value}"
            
        return True, f"✅ Desbloqueado: {entity_type.upper()} = {entity_value}"
    
    except Exception as e:
        return False, f"❌ Erro ao desbloquear: {e}"


def list_blocks(limit: int = 20) -> str:
    """Lista bloqueios ativos (últimos N)"""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT entity_type, entity_value, blocked_at
            FROM blocked_entities
            ORDER BY blocked_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
    
    if not rows:
        return "📭 Nenhum bloqueio ativo"
    
    lines = [f"🔒 <b>Bloqueios Ativos ({len(rows)})</b>", ""]
    
    for r in rows:
        ts = r['blocked_at'][5:16] if r['blocked_at'] else "?"
        lines.append(f"<code>{r['entity_type']:3}</code> {r['entity_value'][:40]} <i>({ts})</i>")
    
    return "\n".join(lines)


def is_whitelisted(ln: str) -> Tuple[bool, str]:
    """
    Verifica se LN address está na whitelist.
    
    Returns:
        (is_whitelisted, level) onde level = 'admin' ou 'normal'
    """
    ln_lower = ln.lower()
    
    if ln_lower in WHITELIST_ADM:
        return True, "admin"
    
    if ln_lower in WHITELIST:
        return True, "normal"
    
    return False, "none"
