"""
Testa evaluate_cooldown_block() — função compartilhada entre /api/check e
/api/claim (extraída da duplicação que existia antes). O teste mais
importante aqui é a divergência de comportamento entre os dois endpoints
que foi preservada de propósito: /api/claim checa is_ja3_blocked mesmo pra
LN address em WHITELIST, /api/check não.
"""
import asyncio

import main
from conftest import insert_claim


def test_no_blocks_returns_none(test_db):
    result = asyncio.run(main.evaluate_cooldown_block(
        "novo@example.com", "9.9.9.9", "fp-novo", "ja3-novo",
        check_ja3_even_if_whitelisted=True,
    ))
    assert result is None


def test_address_blocked_today_returns_reason_address(test_db):
    insert_claim(
        test_db, ln_address="vitima@example.com", status="paid",
        claimed_at=main.datetime.utcnow().isoformat(),
    )
    result = asyncio.run(main.evaluate_cooldown_block(
        "vitima@example.com", "1.1.1.1", None, "",
        check_ja3_even_if_whitelisted=True,
    ))
    assert result is not None
    assert result["reason"] == "address"


def test_ja3_check_diverges_by_whitelist_flag(test_db, monkeypatch):
    # ln em WHITELIST (não ADM) + ja3 bloqueado
    ln = "vip@example.com"
    monkeypatch.setattr(main.config, "WHITELIST", {ln})
    monkeypatch.setattr(main.config, "WHITELIST_ADM", set())

    import sqlite3
    conn = sqlite3.connect(test_db)
    conn.execute(
        "INSERT INTO blocked_entities (entity_type, entity_value) VALUES ('ja3', 'ja3-ruim')"
    )
    conn.commit()
    conn.close()

    # /api/claim: checa ja3 mesmo pra WHITELIST -> deve bloquear
    result_claim = asyncio.run(main.evaluate_cooldown_block(
        ln, "2.2.2.2", None, "ja3-ruim", check_ja3_even_if_whitelisted=True,
    ))
    assert result_claim is not None
    assert result_claim["reason"] == "tls"

    # /api/check: pula ja3 pra WHITELIST -> não deve bloquear
    result_check = asyncio.run(main.evaluate_cooldown_block(
        ln, "2.2.2.2", None, "ja3-ruim", check_ja3_even_if_whitelisted=False,
    ))
    assert result_check is None
