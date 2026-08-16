"""
check_subnet_farm/check_fp_farm devem falhar FECHADO (tratar como farm,
aplicando o decay de reward) quando a própria checagem falha — nunca abrir
mão da defesa silenciosamente por causa de um erro de banco.
"""
from contextlib import contextmanager

import main


def _raise_get_db():
    @contextmanager
    def _boom():
        raise RuntimeError("DB indisponível (simulado)")
        yield  # pragma: no cover
    return _boom


def test_check_subnet_farm_fails_closed_on_db_error(monkeypatch):
    monkeypatch.setattr(main, "get_db", _raise_get_db())
    assert main.check_subnet_farm("1.2.3.4", "vitima@example.com") is True


def test_check_fp_farm_fails_closed_on_db_error(monkeypatch):
    monkeypatch.setattr(main, "get_db", _raise_get_db())
    assert main.check_fp_farm("algum-fp-hash", "vitima@example.com") is True


def test_check_fp_farm_no_fp_returns_false_without_touching_db(monkeypatch):
    # Sem fp_hash não há o que checar — não deve nem chamar get_db.
    def _boom_if_called():
        raise AssertionError("não deveria chamar get_db sem fp_hash")
    monkeypatch.setattr(main, "get_db", _boom_if_called)
    assert main.check_fp_farm("", "vitima@example.com") is False
