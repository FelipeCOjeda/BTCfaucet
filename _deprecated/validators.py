import re
import ipaddress
import logging
from typing import Optional
from config import CGNAT_SUBNETS

logger = logging.getLogger("faucet.validators")

# ── LN Address ────────────────────────────────────────────────────────────────
LN_ADDRESS_RE = re.compile(
    r'^[a-zA-Z0-9._+\-]{1,64}@[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,}$'
)

EMAIL_DOMAINS_BLACKLIST: set[str] = {
    "gmail.com", "hotmail.com", "yahoo.com", "outlook.com", "icloud.com",
    "proton.me", "pm.me", "bol.com.br", "terra.com.br", "uol.com.br",
    "live.com", "msn.com", "me.com", "mac.com", "googlemail.com",
    "yandex.com", "yandex.ru", "mail.ru", "inbox.ru",
}

INVOICE_PREFIXES: tuple[str, ...] = (
    "lnbc", "lntb", "lnurl", "lightning:", "lnbcrt", "00020126"
)


def is_valid_ln_address(address: str) -> tuple[bool, str]:
    """
    Valida um Lightning Address.
    Retorna (válido, mensagem_de_erro).
    Rejeita: emails comuns, invoices BOLT11, LNURLs, QR PIX,
             typos, domínios inválidos, espaços, unicode suspeito.
    """
    if not address:
        return False, "LN Address não informado"

    # Muito longo — provavelmente invoice ou LNURL colado
    if len(address) > 120:
        return False, "Endereço muito longo — use um Lightning Address (ex: voce@wallet.com)"

    # Espaços ou caracteres de controle
    if any(c in address for c in (" ", "\t", "\n", "\r")):
        return False, "LN Address não pode conter espaços"

    # Prefixo de invoice / LNURL / QR PIX
    lower = address.lower()
    if any(lower.startswith(p) for p in INVOICE_PREFIXES):
        return False, "Cole um Lightning Address (ex: voce@wallet.com), não uma invoice ou LNURL"

    if "@" not in address:
        return False, "Formato inválido — use algo@wallet.com"

    if address.count("@") > 1:
        return False, "Formato inválido — use algo@wallet.com"

    if not LN_ADDRESS_RE.match(address):
        return False, "Formato inválido — use algo@wallet.com (apenas letras, números, . _ + -)"

    domain = address.split("@", 1)[1].lower()
    if domain in EMAIL_DOMAINS_BLACKLIST:
        return False, (
            f"'{domain}' é um provedor de e-mail, não uma wallet Lightning. "
            "Use Wallet of Satoshi, Blink, Alby, etc."
        )

    return True, ""


# ── Fingerprint / JA3 ─────────────────────────────────────────────────────────

def sanitize_fp_hash(fp: Optional[str]) -> Optional[str]:
    """
    Valida que o valor é um SHA-256 hex legítimo (64 chars hex).
    Um bot pode enviar hashes diferentes a cada request para burlar o controle;
    aqui garantimos pelo menos que o formato é válido.
    Rejeita silenciosamente qualquer outra coisa.
    """
    if not fp:
        return None
    fp = fp.strip().lower()
    if len(fp) == 64 and re.match(r'^[a-f0-9]{64}$', fp):
        return fp
    return None


def sanitize_ja3(raw: Optional[str]) -> Optional[str]:
    """
    Valida que o JA3 é um MD5 hex (32 chars).
    Injetado pelo Cloudflare Worker via CF-JA3-Hash.
    """
    if not raw:
        return None
    raw = raw.strip().lower()
    if re.match(r'^[a-f0-9]{32}$', raw):
        return raw
    return None


# ── IP helpers ────────────────────────────────────────────────────────────────

def is_cgnat_ip(ip: str) -> bool:
    """
    Retorna True se o IP pertence a uma subnet CGNAT/privada.
    Para esses IPs, o cooldown por IP/subnet é desabilitado,
    pois múltiplos usuários legítimos compartilham o mesmo IP público.
    A proteção recai sobre LN address + browser fingerprint.
    """
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return False
        return any(addr in net for net in CGNAT_SUBNETS)
    except ValueError:
        return False


def normalize_ip_prefix(ip: str) -> Optional[str]:
    """
    IPv4 → /24 network address  (ex: 192.168.1.0)
    IPv6 → /64 network address  (ex: 2804:18:607f:5a04::)
    Garante que rotação de IPs dentro do mesmo bloco seja tratada como mesmo origem.
    """
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address)
    except ValueError:
        return None


# ── User Agent ────────────────────────────────────────────────────────────────

BOT_UA_PATTERNS: list[str] = [
    "curl/", "python-requests", "python-httpx", "wget/", "scrapy",
    "go-http-client", "java/", "libwww", "okhttp", "axios/",
    "ruby", "php/", "perl/", "bot", "spider", "crawler",
]


def is_bot_ua(ua: str) -> bool:
    """Retorna True se o User-Agent parece ser um bot/script."""
    if not ua:
        return True
    ua_lower = ua.lower()
    return any(p in ua_lower for p in BOT_UA_PATTERNS)
