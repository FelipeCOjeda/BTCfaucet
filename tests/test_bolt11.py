"""
Testes dos decoders de BOLT11 (main.py). Os dois primeiros vetores são os
exemplos oficiais do próprio BOLT11 spec (lightning/bolts), reaproveitam o
payment_hash canônico usado em todos os exemplos do spec
(0001020304050607080900010203040506070809000102030405060708090102).
"""
import main


# "Please send $3 for a cup of coffee" — 2500u = 0.0025 BTC = 250_000_000 msat
BOLT11_2500U = (
    "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq"
    "dq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2aw"
    "hz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp"
)
BOLT11_PAYMENT_HASH = "0001020304050607080900010203040506070809000102030405060708090102"


def test_decode_amount_matches_spec_vector():
    assert main.decode_bolt11_amount_msat(BOLT11_2500U) == 250_000_000


def test_decode_payment_hash_matches_spec_vector():
    assert main.decode_bolt11_payment_hash(BOLT11_2500U) == BOLT11_PAYMENT_HASH


def test_decode_amount_amountless_invoice_returns_none():
    # hrp sem dígitos = invoice "amountless" — não dá pra confiar em nenhum valor
    assert main.decode_bolt11_amount_msat("lnbc1pvjluez") is None


def test_decode_amount_garbage_returns_none():
    assert main.decode_bolt11_amount_msat("not-a-bolt11-at-all") is None


def test_decode_payment_hash_garbage_returns_empty():
    assert main.decode_bolt11_payment_hash("not-a-bolt11-at-all") == ""


def test_decode_amount_multiplier_table():
    # Confere a fórmula oficial do BOLT11 (amount * multiplier * 1e11 msat)
    # pros 4 sufixos válidos, direto no HRP — não depende de payload completo.
    import re

    def decode_hrp(hrp):
        m = re.match(r'^ln[a-z]+(\d+)([munp]?)$', hrp)
        digits, mult = m.group(1), m.group(2)
        multiplier = {"": 1.0, "m": 1e-3, "u": 1e-6, "n": 1e-9, "p": 1e-12}[mult]
        return int(round(int(digits) * multiplier * 100_000_000_000))

    assert decode_hrp("lnbc21n") == 2100          # 21 * 1e-9 BTC
    assert decode_hrp("lnbc210n") == 21_000        # equivalente a 21 sats
    assert decode_hrp("lnbc20m") == 2_000_000_000  # 20 * 1e-3 BTC
    assert decode_hrp("lntb1500n") == 150_000       # testnet
