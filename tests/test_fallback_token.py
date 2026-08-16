"""
Testa o token HMAC do endpoint /api/claim/fallback — mesmo padrão do PoW,
protege contra sequestro de fallback por claim_id sequencial adivinhável
sob CGNAT.
"""
import main


def test_token_valid_for_same_claim_id():
    token = main._fallback_sign(42)
    assert main.hmac.compare_digest(main._fallback_sign(42), token)


def test_token_differs_for_different_claim_id():
    assert main._fallback_sign(42) != main._fallback_sign(43)


def test_token_int_and_string_claim_id_match():
    # body.get("claim_id") pode vir como int (JSON number) — garante que a
    # representação usada na assinatura e na verificação bate.
    assert main._fallback_sign(42) == main._fallback_sign("42")


def test_forged_token_fails():
    real_token = main._fallback_sign(42)
    forged = ("0" if real_token[0] != "0" else "1") + real_token[1:]
    assert not main.hmac.compare_digest(main._fallback_sign(42), forged)
