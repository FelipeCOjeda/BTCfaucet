"""Testes do desafio de Proof-of-Work assinado (main.py)."""
import time

import main


def _solve(seed: str, difficulty: int) -> int:
    """Resolve o PoW de verdade (só usado nos testes — mesmo algoritmo do
    frontend em static/index.html)."""
    nonce = 0
    prefix = "0" * difficulty
    while True:
        h = main.hashlib.sha256(f"{seed}:{nonce}".encode()).hexdigest()
        if h.startswith(prefix):
            return nonce
        nonce += 1


def test_issue_challenge_has_signature_and_difficulty():
    ch = main.issue_pow_challenge()
    assert ch["seed"]
    assert ch["sig"]
    assert ch["difficulty"] == main.POW_DIFFICULTY


def test_valid_solve_passes():
    ch = main.issue_pow_challenge()
    nonce = _solve(ch["seed"], ch["difficulty"])
    assert main.verify_pow_challenge(ch["seed"], ch["sig"], nonce) is True


def test_wrong_nonce_fails():
    ch = main.issue_pow_challenge()
    assert main.verify_pow_challenge(ch["seed"], ch["sig"], 0) is False


def test_forged_seed_with_valid_looking_sig_fails():
    # Cliente tenta forjar um seed próprio (não emitido pelo servidor) —
    # sem conhecer BANNER_SECRET não dá pra assinar corretamente.
    forged_seed = f"{int(time.time())}.forjado"
    forged_sig = "0" * 64
    nonce = _solve(forged_seed, main.POW_DIFFICULTY)
    assert main.verify_pow_challenge(forged_seed, forged_sig, nonce) is False


def test_tampered_signature_fails():
    ch = main.issue_pow_challenge()
    nonce = _solve(ch["seed"], ch["difficulty"])
    tampered_sig = ("f" if ch["sig"][0] != "f" else "0") + ch["sig"][1:]
    assert main.verify_pow_challenge(ch["seed"], tampered_sig, nonce) is False


def test_replay_same_seed_twice_fails():
    ch = main.issue_pow_challenge()
    nonce = _solve(ch["seed"], ch["difficulty"])
    assert main.verify_pow_challenge(ch["seed"], ch["sig"], nonce) is True
    # segunda vez com o MESMO seed já resolvido — uso único
    assert main.verify_pow_challenge(ch["seed"], ch["sig"], nonce) is False


def test_expired_seed_fails():
    ts_expired = int(time.time()) - main.POW_MAX_AGE - main.POW_CLOCK_SKEW - 10
    seed = f"{ts_expired}.{main._secrets.token_hex(12)}"
    sig = main._pow_sign(seed)
    nonce = _solve(seed, main.POW_DIFFICULTY)
    assert main.verify_pow_challenge(seed, sig, nonce) is False


def test_verify_pow_rejects_nonce_out_of_range():
    assert main.verify_pow("qualquer-seed", -1) is False
    assert main.verify_pow("qualquer-seed", 50_000_001) is False
