"""
Validação real de endereços Spark mainnet (protocolo Spark/Buildonspark,
usado pela integração DePix via Flashnet/Eulen) — checksum bech32m (BIP-350)
+ estrutura mínima do payload, não é heurística de prefixo.

Formato: bech32m padrão, HRP "spark" (mainnet — testnet/regtest usam outros
HRPs, não aceitos aqui pois o depix.st só opera em mainnet). O payload
decodificado é um protobuf simples (biblioteca @buildonspark/spark-sdk,
SparkAddress): campo 1 (tag 0x0A, wire type 2) = chave pública de
identidade comprimida (33 bytes, prefixo 0x02/0x03). Endereços "invoice"
(com campos extras de valor/memo) têm bytes adicionais depois — aceitos,
mas só validamos o prefixo obrigatório.

Testado contra endereços reais gerados pelo SDK oficial em
scripts/test_spark_address.py (protótipo depix-spark-prototype).
"""

from dataclasses import dataclass

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

SPARK_HRP = "spark"  # mainnet — ver AddressNetwork no @buildonspark/spark-sdk

BECH32M_CONST = 0x2BC830A3


@dataclass
class SparkAddressInfo:
    valid: bool
    identity_pubkey_hex: str = ""
    reason: str = ""


def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 0x1F for c in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def _bech32m_decode(bech: str):
    if any(ord(c) < 33 or ord(c) > 126 for c in bech):
        return None
    if bech.lower() != bech and bech.upper() != bech:
        return None
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 6 + 1 > len(bech) or len(bech) > 1000:
        return None
    hrp = bech[:pos]
    data_part = bech[pos + 1:]
    try:
        data = [CHARSET.index(c) for c in data_part]
    except ValueError:
        return None
    if _bech32_polymod(_hrp_expand(hrp) + data) != BECH32M_CONST:
        return None
    return hrp, data[:-6]


def validate_spark_address(address: str) -> SparkAddressInfo:
    if not address:
        return SparkAddressInfo(False, reason="Endereço vazio")
    address = address.strip()
    if len(address) < 20 or len(address) > 1000:
        return SparkAddressInfo(False, reason="Tamanho de endereço inválido")

    lowered = address.lower()
    if not lowered.startswith(SPARK_HRP + "1"):
        return SparkAddressInfo(False, reason="Não começa com 'spark1' (mainnet)")

    decoded = _bech32m_decode(address)
    if decoded is None:
        return SparkAddressInfo(False, reason="Checksum bech32m inválido")

    hrp, data = decoded
    if hrp != SPARK_HRP:
        return SparkAddressInfo(False, reason=f"HRP inesperado: {hrp}")

    payload = bytes(_convertbits(data, 5, 8, pad=False) or [])
    if len(payload) < 35 or payload[0] != 0x0A or payload[1] != 33:
        return SparkAddressInfo(False, reason="Estrutura do endereço não reconhecida (campo de chave pública ausente/inválido)")

    pubkey = payload[2:35]
    if pubkey[0] not in (0x02, 0x03):
        return SparkAddressInfo(False, reason="Chave pública não é comprimida (prefixo inválido)")

    return SparkAddressInfo(True, identity_pubkey_hex=pubkey.hex())
