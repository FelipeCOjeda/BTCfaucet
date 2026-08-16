import sqlite3
import logging
from config import DB_PATH

logger = logging.getLogger("faucet.db")


def get_db() -> sqlite3.Connection:
    """Abre conexão SQLite com WAL mode e configurações de performance."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA cache_size=-8000")   # 8MB de cache
    return conn


def init_db() -> None:
    """Cria tabelas e índices compostos. Migra colunas novas se necessário."""
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
                status       TEXT NOT NULL DEFAULT 'pending'
            )
        """)

        # Migração suave: adiciona colunas novas sem recriar a tabela
        existing = {row[1] for row in conn.execute("PRAGMA table_info(claims)")}
        for col, typedef in [("ip_prefix", "TEXT"), ("fp_hash", "TEXT"), ("ja3_hash", "TEXT")]:
            if col not in existing:
                conn.execute(f"ALTER TABLE claims ADD COLUMN {col} {typedef}")
                logger.info(f"Migração: coluna '{col}' adicionada")

        # Índices simples (retrocompatibilidade)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_address ON claims(ip_address)")

        # Índices compostos — consultas de cooldown muito mais rápidas
        conn.execute("""CREATE INDEX IF NOT EXISTS idx_ln_status_at
                        ON claims(ln_address, status, claimed_at DESC)""")
        conn.execute("""CREATE INDEX IF NOT EXISTS idx_prefix_status_at
                        ON claims(ip_prefix, status, claimed_at DESC)""")
        conn.execute("""CREATE INDEX IF NOT EXISTS idx_fp_status_at
                        ON claims(fp_hash, status, claimed_at DESC)""")
        conn.execute("""CREATE INDEX IF NOT EXISTS idx_ja3_status_at
                        ON claims(ja3_hash, status, claimed_at DESC)""")
        conn.execute("""CREATE INDEX IF NOT EXISTS idx_status_at
                        ON claims(status, claimed_at DESC)""")

        conn.commit()
    logger.info("Database inicializado")


def cleanup_stale_pending() -> int:
    """Expira claims pending com mais de 5 minutos. Retorna quantidade afetada."""
    with get_db() as conn:
        n = conn.execute("""
            UPDATE claims SET status = 'failed'
            WHERE status = 'pending'
            AND claimed_at < datetime('now', '-5 minutes')
        """).rowcount
        conn.commit()
    if n:
        logger.info(f"Cleanup: {n} pending(s) expirado(s) → failed")
    return n


def archive_old_claims(days: int = 60) -> int:
    """Remove claims com mais de X dias para controlar crescimento do banco."""
    with get_db() as conn:
        n = conn.execute(f"""
            DELETE FROM claims
            WHERE status IN ('failed', 'paid')
            AND claimed_at < datetime('now', '-{days} days')
        """).rowcount
        conn.commit()
    if n:
        logger.info(f"Arquivo: {n} claim(s) antigos removidos (>{days} dias)")
    return n
