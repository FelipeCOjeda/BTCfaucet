"""Catálogo de parceiros (rodízio de banners + gate de clique) e estado ativo/inativo.

O catálogo é fixo aqui; o que o bot do Telegram controla (/partners,
/activebanner, /inactivebanner) é só o flag ativo/inativo, guardado na tabela
partner_status do faucet.db. Sem linha na tabela vale o `default_active`.
Os arquivos de banner ficam em static/partners/<slug>-<WxH>.html.
"""
import re
import sqlite3
from typing import Optional

from config import DB_PATH

CATALOG = [
    {"slug": "partner_moshe",  "name": "Moshe Internacional", "url": "https://mosheinternacional.com",   "default_active": True},
    {"slug": "dig",            "name": "DIG P2P",             "url": "https://vempradig.com/ref/OJEDA",  "default_active": True},
    {"slug": "depix_cachorro", "name": "Depix do Cachorro",   "url": "https://cachorrodepix.com/",       "default_active": False},
    {"slug": "depix-banner",   "name": "depix.st",            "url": "https://depix.st",                 "default_active": True},
    {"slug": "prohash",        "name": "ProHash",             "url": "https://prohash.com.br/ojeda",     "default_active": True},
    {"slug": "ojedabot",       "name": "Ojedabot",            "url": "https://www.t.me/ojedabot",        "default_active": False},
    {"slug": "redotpay",       "name": "RedotPay",            "url": "https://url.hk/i/pt/zitqi",        "default_active": True},
    {"slug": "amulets",        "name": "Amulets",             "url": "https://www.amulets.io/",          "default_active": False},
    {"slug": "pixgo",          "name": "PixGo",               "url": "https://pixgo.org/register.php?refer=felipecojeda", "default_active": False},
    {"slug": "satsfaction",    "name": "Satsfaction",         "url": "https://t.me/SATSfaction_bot?start=ref_159770042", "default_active": False},
    {"slug": "spike",          "name": "Spike",               "url": "http://spiketospike.com/?referral=OJEDA", "default_active": False},
    {"slug": "tangem",         "name": "Tangem",              "url": "https://prohash.com.br/ojeda",     "default_active": False},
]
BY_SLUG = {p["slug"]: p for p in CATALOG}


def _conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE IF NOT EXISTS partner_status (slug TEXT PRIMARY KEY, active INTEGER NOT NULL)")
    return conn


def _overrides() -> dict:
    conn = _conn()
    try:
        return {r["slug"]: bool(r["active"]) for r in conn.execute("SELECT slug, active FROM partner_status")}
    finally:
        conn.close()


def all_partners() -> list:
    """Catálogo completo, cada item com a chave `active` resolvida."""
    ov = _overrides()
    return [{**p, "active": ov.get(p["slug"], p["default_active"])} for p in CATALOG]


def active_partners() -> list:
    return [p for p in all_partners() if p["active"]]


def set_active(slug: str, active: bool) -> None:
    conn = _conn()
    try:
        conn.execute(
            "INSERT INTO partner_status (slug, active) VALUES (?, ?) "
            "ON CONFLICT(slug) DO UPDATE SET active = excluded.active",
            (slug, int(active)),
        )
        conn.commit()
    finally:
        conn.close()


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def find_partners(query: str) -> list:
    """Parceiros que casam com a busca (slug ou nome, sem acento/pontuação/caixa).
    Match exato vence; senão devolve todos os que contêm o texto."""
    q = _norm(query)
    if not q:
        return []
    for p in CATALOG:
        if q in (_norm(p["slug"]), _norm(p["name"])):
            return [p]
    return [p for p in CATALOG if q in _norm(p["slug"]) or q in _norm(p["name"])]
