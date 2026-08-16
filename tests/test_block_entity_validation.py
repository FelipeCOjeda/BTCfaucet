"""
Testa a validação de IP em telegram_bot._block_entity() — antes só aceitava
IPv4 exato via regex, rejeitando IPv6 e CIDR.
"""
import security.blocklist
import telegram_bot


def _patch_db(monkeypatch, test_db):
    # _block_entity delega pra security.blocklist.block_entity(), que tem
    # sua própria referência a DB_PATH (import separado) — precisa patchar
    # os dois módulos.
    monkeypatch.setattr(telegram_bot, "DB_PATH", test_db)
    monkeypatch.setattr(security.blocklist, "DB_PATH", test_db)


def test_ipv4_exact_accepted(test_db, monkeypatch):
    _patch_db(monkeypatch, test_db)
    ok, msg = telegram_bot._block_entity("ip", "45.189.71.212")
    assert ok is True, msg


def test_ipv4_cidr_accepted(test_db, monkeypatch):
    _patch_db(monkeypatch, test_db)
    ok, msg = telegram_bot._block_entity("ip", "45.189.71.0/24")
    assert ok is True, msg


def test_ipv6_exact_accepted(test_db, monkeypatch):
    _patch_db(monkeypatch, test_db)
    ok, msg = telegram_bot._block_entity("ip", "2804:880:1740:af00::1")
    assert ok is True, msg


def test_ipv6_cidr_accepted(test_db, monkeypatch):
    _patch_db(monkeypatch, test_db)
    ok, msg = telegram_bot._block_entity("ip", "2804:880:1740::/48")
    assert ok is True, msg


def test_garbage_rejected(test_db, monkeypatch):
    _patch_db(monkeypatch, test_db)
    ok, msg = telegram_bot._block_entity("ip", "nao-e-um-ip")
    assert ok is False
    assert "inválido" in msg.lower()
