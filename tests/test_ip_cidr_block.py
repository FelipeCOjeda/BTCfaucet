"""
Testa o bloqueio de IP por faixa CIDR em is_dynamically_blocked() — antes só
existia match exato de string, então uma faixa bloqueada nunca batia de
verdade mesmo se alguém conseguisse inserir uma entrada CIDR.
"""
import sqlite3

import main


def _insert_blocked_ip(db_path, value):
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO blocked_entities (entity_type, entity_value) VALUES ('ip', ?)",
        (value,),
    )
    conn.commit()
    conn.close()


def test_exact_ip_still_blocks(test_db):
    _insert_blocked_ip(test_db, "9.9.9.9")
    assert main.is_dynamically_blocked(ip="9.9.9.9", fp=None, ln="x@example.com") is True


def test_cidr_v4_blocks_ip_inside_range(test_db):
    _insert_blocked_ip(test_db, "45.189.71.0/24")
    assert main.is_dynamically_blocked(ip="45.189.71.212", fp=None, ln="x@example.com") is True


def test_cidr_v4_does_not_block_ip_outside_range(test_db):
    _insert_blocked_ip(test_db, "45.189.71.0/24")
    assert main.is_dynamically_blocked(ip="45.189.72.1", fp=None, ln="x@example.com") is False


def test_cidr_v6_blocks_ip_inside_range(test_db):
    _insert_blocked_ip(test_db, "2804:880:1740::/48")
    assert main.is_dynamically_blocked(ip="2804:880:1740:af00::1", fp=None, ln="x@example.com") is True


def test_no_block_returns_false(test_db):
    assert main.is_dynamically_blocked(ip="1.2.3.4", fp=None, ln="ninguem@example.com") is False
