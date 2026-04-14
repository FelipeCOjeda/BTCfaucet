# ⚡ Satoshi Faucet

A Bitcoin Lightning Network faucet built with FastAPI, LNbits, and hCaptcha. Users enter their Lightning Address, solve a captcha, and receive sats instantly. Each address is rate-limited to one claim per 24 hours.

**Live:** [bitcoinfaucet.st](https://bitcoinfaucet.st)

---

## Features

- ⚡ Instant Lightning payments via LNbits
- 🔒 hCaptcha bot protection
- ⏱ 24-hour cooldown per Lightning Address
- 🌐 PT / EN / ES interface
- 📱 Mobile-friendly responsive design
- 🧅 Self-hosted with Cloudflare Tunnel (no open ports needed)
- 🗃 SQLite for claim history and rate limiting

---

## Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI + Uvicorn |
| Payments | LNbits (self-hosted) |
| Captcha | hCaptcha |
| Database | SQLite |
| Frontend | Vanilla HTML/CSS/JS |
| Tunnel | Cloudflare Tunnel |
| Process | systemd |

---

## How It Works

```
User enters LN Address
        ↓
hCaptcha verification
        ↓
Check 24h cooldown in SQLite
        ↓
Resolve LN Address → LNURL-pay → BOLT11 invoice
        ↓
Pay invoice via LNbits API
        ↓
Record payment hash in SQLite
        ↓
User receives sats ⚡
```

---

## Requirements

- Python 3.11+
- LNbits instance (self-hosted)
- hCaptcha account
- Cloudflare account (optional, for tunnel)

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Felipecojeda/BTCfaucet.git
cd BTCfaucet
```

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

### 3. Configure environment variables

```bash
cp .env.example .env
nano .env
```

```env
LNBITS_URL=http://localhost:5000
LNBITS_ADMIN_KEY=your_lnbits_admin_key
HCAPTCHA_SECRET=your_hcaptcha_secret_key
HCAPTCHA_SITEKEY=your_hcaptcha_site_key
FAUCET_AMOUNT_SAT=21
COOLDOWN_HOURS=24
DB_PATH=faucet.db
```

### 4. Run locally

```bash
uvicorn main:app --host 127.0.0.1 --port 8420 --reload
```

Visit `http://localhost:8420`

---

## Production Deployment (Debian/Ubuntu)

### systemd service

```bash
sudo cp ln-faucet.service /etc/systemd/system/
sudo nano /etc/systemd/system/ln-faucet.service
# Update WorkingDirectory and ExecStart paths
sudo systemctl daemon-reload
sudo systemctl enable --now ln-faucet
```

### Nginx reverse proxy

```bash
sudo cp nginx.conf.example /etc/nginx/sites-available/yourdomain.com
sudo nano /etc/nginx/sites-available/yourdomain.com
# Replace yourdomain.com with your domain
sudo ln -s /etc/nginx/sites-available/yourdomain.com /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### Cloudflare Tunnel (recommended — no open ports)

```bash
cloudflared tunnel create BTCfaucet
nano ~/.cloudflared/BTCfaucet.yml
```

```yaml
tunnel: YOUR_TUNNEL_UUID
credentials-file: /home/user/.cloudflared/YOUR_TUNNEL_UUID.json

ingress:
  - hostname: yourdomain.com
    service: http://localhost:8420
  - service: http_status:404
```

```bash
cloudflared tunnel route dns BTCfaucet yourdomain.com
cloudflared tunnel run BTCfaucet
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/config` | Returns sitekey and faucet config |
| GET | `/api/status` | Returns faucet amount and cooldown |
| GET | `/api/stats` | Returns total claims and sats paid |
| POST | `/api/check` | Check if LN Address is rate-limited |
| POST | `/api/claim` | Submit claim request |

### POST /api/claim

```json
{
  "ln_address": "user@wallet.com",
  "captcha_token": "hcaptcha_response_token"
}
```

---

## Project Structure

```
BTCfaucet/
├── main.py                 # FastAPI backend
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variables template
├── ln-faucet.service       # systemd unit file
├── nginx.conf.example      # Nginx reverse proxy config
├── static/
│   ├── index.html          # Main faucet page (PT/EN/ES)
│   └── guia.html           # Beginner's guide (PT/EN/ES)
└── faucet.db               # SQLite database (auto-created, gitignored)
```

---

## Configuration

| Variable | Description | Default |
|---|---|---|
| `LNBITS_URL` | LNbits instance URL | `http://localhost:5000` |
| `LNBITS_ADMIN_KEY` | LNbits admin API key | — |
| `HCAPTCHA_SECRET` | hCaptcha secret key | — |
| `HCAPTCHA_SITEKEY` | hCaptcha site key | — |
| `FAUCET_AMOUNT_SAT` | Sats per claim | `21` |
| `COOLDOWN_HOURS` | Hours between claims | `24` |
| `DB_PATH` | SQLite database path | `faucet.db` |

---

## Donations

If this project helped you, consider sending some sats:

⚡ `donate@lnvoltz.com`

---

## License

MIT License — see [LICENSE](LICENSE) for details.
