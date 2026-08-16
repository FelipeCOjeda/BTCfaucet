"""
Fixtures compartilhadas. Importante: NUNCA aponta para o faucet.db real —
todo teste que precisa de banco usa um SQLite temporário isolado, criado com
o mesmo schema de main.init_db().
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import main  # noqa: E402


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """Substitui main.DB_PATH por um SQLite temporário e cria o schema real
    (mesmo init_db() usado em produção), pra qualquer função testada que use
    get_db() operar isolada, sem tocar no faucet.db de verdade."""
    db_path = str(tmp_path / "test_faucet.db")
    monkeypatch.setattr(main, "DB_PATH", db_path)
    main.init_db()
    return db_path


def insert_claim(db_path, **fields):
    """Helper pra inserir uma linha em claims com valores default sensatos,
    sobrescrevendo só o que o teste precisar."""
    import sqlite3
    defaults = dict(
        ln_address="test@example.com",
        ip_address="1.2.3.4",
        ip_prefix="1.2.3.0/24",
        fp_hash=None,
        ja3_hash=None,
        claimed_at="2026-08-16T12:00:00.000000",
        amount_sat=21,
        payment_hash=None,
        status="paid",
        destination_pubkey=None,
    )
    defaults.update(fields)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """INSERT INTO claims
           (ln_address, ip_address, ip_prefix, fp_hash, ja3_hash, claimed_at,
            amount_sat, payment_hash, status, destination_pubkey)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            defaults["ln_address"], defaults["ip_address"], defaults["ip_prefix"],
            defaults["fp_hash"], defaults["ja3_hash"], defaults["claimed_at"],
            defaults["amount_sat"], defaults["payment_hash"], defaults["status"],
            defaults["destination_pubkey"],
        ),
    )
    conn.commit()
    conn.close()
