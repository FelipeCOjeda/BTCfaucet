import logging
import httpx
from fastapi import HTTPException

from config import LNBITS_URL, LNBITS_ADMIN_KEY, HCAPTCHA_SECRET, FAUCET_AMOUNT_SAT, SITE_URL

logger = logging.getLogger("faucet.lightning")


async def verify_hcaptcha(token: str, client: httpx.AsyncClient) -> bool:
    """Valida token hCaptcha. Retorna True se aprovado."""
    try:
        resp = await client.post(
            "https://hcaptcha.com/siteverify",
            data={"secret": HCAPTCHA_SECRET, "response": token},
            timeout=10,
        )
        return resp.json().get("success", False)
    except Exception as e:
        logger.error(f"hCaptcha verify error: {e}")
        return False


async def resolve_ln_address(address: str, client: httpx.AsyncClient) -> str:
    """
    Resolve um Lightning Address para um BOLT11 invoice.
    Fluxo: LN Address → LNURL-pay metadata → callback → invoice PR.
    Raises HTTPException com mensagem amigável em caso de falha.
    """
    import re
    user, domain = address.split("@", 1)

    # Sanitização extra (já validado antes, mas defense in depth)
    if not re.match(r'^[a-zA-Z0-9._+\-]{1,64}$', user):
        raise HTTPException(400, "LN Address inválido")
    if not re.match(r'^[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,}$', domain):
        raise HTTPException(400, "LN Address inválido")

    url = f"https://{domain}/.well-known/lnurlp/{user}"
    try:
        r1 = await client.get(url, timeout=10)
        if r1.status_code != 200:
            raise HTTPException(400, "Lightning Address não encontrado ou wallet indisponível")

        meta = r1.json()
        if meta.get("status") == "ERROR":
            reason = meta.get("reason", "Erro retornado pela wallet")
            raise HTTPException(400, f"Wallet recusou o pagamento: {reason}")

        min_sat = meta.get("minSendable", 1000) // 1000
        max_sat = meta.get("maxSendable", 1_000_000) // 1000

        if not (min_sat <= FAUCET_AMOUNT_SAT <= max_sat):
            raise HTTPException(
                400,
                f"Esta wallet não aceita pagamentos de {FAUCET_AMOUNT_SAT} sats "
                f"(aceita entre {min_sat} e {max_sat} sats)"
            )

        r2 = await client.get(
            meta["callback"],
            params={"amount": FAUCET_AMOUNT_SAT * 1000},
            timeout=10,
        )
        data2 = r2.json()
        if data2.get("status") == "ERROR":
            reason = data2.get("reason", "Erro ao gerar invoice")
            raise HTTPException(400, f"Não foi possível gerar invoice: {reason}")

        return data2["pr"]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"resolve_ln_address error [{address}]: {e}")
        raise HTTPException(400, "Não foi possível contatar a wallet. Verifique o Lightning Address e tente novamente.")


async def pay_invoice(bolt11: str, client: httpx.AsyncClient) -> dict:
    """
    Paga um BOLT11 invoice via LNbits.
    Raises HTTPException com mensagem genérica em caso de falha (não expõe internals).
    """
    headers = {"X-Api-Key": LNBITS_ADMIN_KEY, "Content-Type": "application/json"}
    try:
        r = await client.post(
            f"{LNBITS_URL}/api/v1/payments",
            json={"out": True, "bolt11": bolt11},
            headers=headers,
            timeout=30,
        )
        if r.status_code not in (200, 201):
            logger.error(f"LNbits payment error {r.status_code}: {r.text[:500]}")
            raise HTTPException(500, "Erro ao processar pagamento. Tente novamente em instantes.")
        return r.json()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"pay_invoice unexpected error: {e}")
        raise HTTPException(500, "Erro interno ao processar pagamento. Tente novamente.")


def captcha_enabled() -> bool:
    """Retorna True se o hCaptcha está configurado (não é o token de bypass)."""
    return bool(HCAPTCHA_SECRET) and HCAPTCHA_SECRET != "0x0000000000000000000000000000000000000000"
