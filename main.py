import os
import sqlite3
import httpx
import asyncio
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager

# ── Config ────────────────────────────────────────────────────────────────────
LNBITS_URL        = os.getenv("LNBITS_URL", "http://localhost:5000")
LNBITS_ADMIN_KEY  = os.getenv("LNBITS_ADMIN_KEY", "YOUR_LNBITS_ADMIN_KEY")
HCAPTCHA_SECRET   = os.getenv("HCAPTCHA_SECRET", "YOUR_HCAPTCHA_SECRET")
HCAPTCHA_SITEKEY  = os.getenv("HCAPTCHA_SITEKEY", "YOUR_HCAPTCHA_SITEKEY")
FAUCET_AMOUNT_SAT = int(os.getenv("FAUCET_AMOUNT_SAT", "21"))   # sats por claim
COOLDOWN_HOURS    = int(os.getenv("COOLDOWN_HOURS", "24"))
DB_PATH           = os.getenv("DB_PATH", "faucet.db")

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS claims (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ln_address  TEXT NOT NULL,
                claimed_at  TEXT NOT NULL,
                amount_sat  INTEGER NOT NULL,
                payment_hash TEXT,
                status      TEXT DEFAULT 'pending'
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ln_address ON claims(ln_address)")
        conn.commit()

# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="LN Faucet", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Models ────────────────────────────────────────────────────────────────────
class ClaimRequest(BaseModel):
    ln_address: str
    captcha_token: str

# ── Helpers ───────────────────────────────────────────────────────────────────
def is_blocked(ln_address: str) -> tuple[bool, int]:
    """Returns (blocked, seconds_remaining)"""
    with get_db() as conn:
        row = conn.execute(
            "SELECT claimed_at FROM claims WHERE ln_address = ? AND status = 'paid' ORDER BY claimed_at DESC LIMIT 1",
            (ln_address.lower(),)
        ).fetchone()
    if not row:
        return False, 0
    last = datetime.fromisoformat(row["claimed_at"])
    delta = timedelta(hours=COOLDOWN_HOURS) - (datetime.utcnow() - last)
    if delta.total_seconds() > 0:
        return True, int(delta.total_seconds())
    return False, 0

async def verify_hcaptcha(token: str) -> bool:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://hcaptcha.com/siteverify",
            data={"secret": HCAPTCHA_SECRET, "response": token},
            timeout=10,
        )
        data = resp.json()
        return data.get("success", False)

async def resolve_ln_address(address: str) -> str:
    """Resolve LN Address → BOLT11 invoice for FAUCET_AMOUNT_SAT"""
    if "@" not in address:
        raise HTTPException(400, "LN Address inválido")
    user, domain = address.split("@", 1)
    url = f"https://{domain}/.well-known/lnurlp/{user}"
    async with httpx.AsyncClient() as client:
        # Step 1 – fetch LNURL-pay metadata
        r1 = await client.get(url, timeout=10)
        if r1.status_code != 200:
            raise HTTPException(400, f"LN Address não encontrado: {url}")
        meta = r1.json()
        if meta.get("status") == "ERROR":
            raise HTTPException(400, meta.get("reason", "Erro no LN Address"))

        min_sat = meta.get("minSendable", 1000) // 1000
        max_sat = meta.get("maxSendable", 1_000_000) // 1000
        if not (min_sat <= FAUCET_AMOUNT_SAT <= max_sat):
            raise HTTPException(400, f"Valor {FAUCET_AMOUNT_SAT} sats fora do range [{min_sat}–{max_sat}]")

        callback = meta["callback"]
        amount_msat = FAUCET_AMOUNT_SAT * 1000

        # Step 2 – fetch invoice
        r2 = await client.get(callback, params={"amount": amount_msat}, timeout=10)
        data2 = r2.json()
        if data2.get("status") == "ERROR":
            raise HTTPException(400, data2.get("reason", "Erro ao gerar invoice"))

        return data2["pr"]  # BOLT11

async def pay_invoice(bolt11: str) -> dict:
    """Pay BOLT11 via LNbits"""
    headers = {"X-Api-Key": LNBITS_ADMIN_KEY, "Content-Type": "application/json"}
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{LNBITS_URL}/api/v1/payments",
            json={"out": True, "bolt11": bolt11},
            headers=headers,
            timeout=30,
        )
        if r.status_code not in (200, 201):
            raise HTTPException(500, f"LNbits erro {r.status_code}: {r.text}")
        return r.json()

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/api/status")
async def status():
    return {
        "amount_sat": FAUCET_AMOUNT_SAT,
        "cooldown_hours": COOLDOWN_HOURS,
        "online": True,
    }

@app.post("/api/check")
async def check_address(body: dict):
    ln = body.get("ln_address", "").strip().lower()
    if not ln:
        raise HTTPException(400, "Informe um LN Address")
    blocked, secs = is_blocked(ln)
    if blocked:
        h = secs // 3600
        m = (secs % 3600) // 60
        return {"blocked": True, "wait_seconds": secs, "message": f"Aguarde {h}h {m}m para solicitar novamente"}
    return {"blocked": False}

@app.post("/api/claim")
async def claim(req: ClaimRequest, request: Request):
    ln = req.ln_address.strip().lower()

    # 1 – Rate limit
    blocked, secs = is_blocked(ln)
    if blocked:
        h = secs // 3600
        m = (secs % 3600) // 60
        raise HTTPException(429, f"Aguarde {h}h {m}m para solicitar novamente")

    # 2 – Captcha
    if HCAPTCHA_SECRET != "0x0000000000000000000000000000000000000000":
        ok = await verify_hcaptcha(req.captcha_token)
        if not ok:
            raise HTTPException(400, "Captcha inválido")

    # 3 – Registrar claim (pending) antes do pagamento
    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO claims (ln_address, claimed_at, amount_sat, status) VALUES (?,?,?,?)",
            (ln, now, FAUCET_AMOUNT_SAT, "pending")
        )
        claim_id = cur.lastrowid
        conn.commit()

    # 4 – Resolver LN Address → invoice
    try:
        bolt11 = await resolve_ln_address(ln)
    except HTTPException as e:
        with get_db() as conn:
            conn.execute("UPDATE claims SET status='failed' WHERE id=?", (claim_id,))
            conn.commit()
        raise

    # 5 – Pagar via LNbits
    try:
        result = await pay_invoice(bolt11)
        payment_hash = result.get("payment_hash", "")
        with get_db() as conn:
            conn.execute(
                "UPDATE claims SET status='paid', payment_hash=? WHERE id=?",
                (payment_hash, claim_id)
            )
            conn.commit()
        return {
            "success": True,
            "message": f"⚡ {FAUCET_AMOUNT_SAT} sats enviados!",
            "payment_hash": payment_hash,
        }
    except HTTPException as e:
        with get_db() as conn:
            conn.execute("UPDATE claims SET status='failed' WHERE id=?", (claim_id,))
            conn.commit()
        raise

@app.get("/api/config")
async def config():
    return {
        "hcaptcha_sitekey": HCAPTCHA_SITEKEY,
        "amount_sat": FAUCET_AMOUNT_SAT,
        "cooldown_hours": COOLDOWN_HOURS,
    }

@app.get("/api/stats")
async def stats():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) as c, SUM(amount_sat) as s FROM claims WHERE status='paid'").fetchone()
    return {
        "total_claims": total["c"] or 0,
        "total_sats_paid": total["s"] or 0,
    }

# Serve frontend
app.mount("/", StaticFiles(directory="static", html=True), name="static")
