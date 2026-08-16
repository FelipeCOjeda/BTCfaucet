"""
Testa que decode_bolt11_pubkey() usa a recuperação ECDSA da assinatura real
como fonte de verdade, e NÃO confia isoladamente no campo opcional 'n' —
valida a correção do achado "pubkey do bolt11 confiado sem verificar
assinatura" (um LNURLp malicioso poderia forjar esse campo).

Monta um bolt11 sintético mínimo (timestamp + tag 'n' forjado + assinatura
real) via bech32 manual, reaproveitando os helpers já existentes em main.py.
O checksum de 6 chars no final não é validado pelo decoder (main._bolt11_
bech32_decode só descarta os últimos 6 chars), então não precisa ser real.
"""
import hashlib

import coincurve

import main


def _build_synthetic_bolt11(hrp: str, real_privkey: coincurve.PrivateKey, forged_pubkey_bytes: bytes) -> str:
    # timestamp: 7 grupos de 5 bits (valor arbitrário, decoder só pula)
    timestamp_5bit = [0] * 7

    # tag 'n' (tag=19) com o pubkey FORJADO (diferente da chave que realmente assina)
    tag_payload_5bit = main._bolt11_convertbits(list(forged_pubkey_bytes), 8, 5, True)
    dlen = len(tag_payload_5bit)
    assert dlen == 53, f"pubkey deveria virar 53 grupos de 5-bit, veio {dlen}"
    tag_header = [19, dlen >> 5, dlen & 31]

    data_no_sig = timestamp_5bit + tag_header + tag_payload_5bit

    data_bytes = bytes(main._bolt11_convertbits(data_no_sig, 5, 8, False) or [])
    msg_hash = hashlib.sha256(hashlib.sha256(hrp.encode("ascii") + data_bytes).digest()).digest()

    sig65 = real_privkey.sign_recoverable(msg_hash, hasher=None)  # 64 bytes sig + 1 recovery
    assert len(sig65) == 65
    sig_5bit = main._bolt11_convertbits(list(sig65), 8, 5, True)
    assert len(sig_5bit) == 104

    data5 = data_no_sig + sig_5bit
    body = "".join(main._BOLT11_CHARSET[v] for v in data5)
    fake_checksum = "qqqqqq"  # decoder não valida checksum, só descarta 6 chars
    return hrp + "1" + body + fake_checksum


def test_ecdsa_recovery_wins_over_forged_n_tag():
    real_key = coincurve.PrivateKey()
    real_pubkey_hex = real_key.public_key.format(compressed=True).hex()

    forged_key = coincurve.PrivateKey()
    forged_pubkey_bytes = forged_key.public_key.format(compressed=True)
    forged_pubkey_hex = forged_pubkey_bytes.hex()

    assert real_pubkey_hex != forged_pubkey_hex  # garantia de que o teste testa algo

    bolt11 = _build_synthetic_bolt11("lnbc1", real_key, forged_pubkey_bytes)
    decoded = main.decode_bolt11_pubkey(bolt11)

    assert decoded == real_pubkey_hex, (
        "decode_bolt11_pubkey retornou o pubkey do campo 'n' (forjável) "
        "em vez do pubkey recuperado da assinatura real"
    )
    assert decoded != forged_pubkey_hex
