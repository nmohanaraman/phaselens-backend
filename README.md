# PhaseLens API

Backend for [PhaseLens](https://phaselens.ai) — an AI-powered stock analysis tool that classifies companies by lifecycle phase (Pre-Revenue / Growth / Mature / Decline) and generates transparent Buy / Hold / Sell signals from public financial data.

> **Not financial advice.** PhaseLens is an educational research tool, not a licensed financial advisor, broker, or consultant. Signals are model-generated from public data and may be inaccurate or outdated. Do your own research and consult a licensed professional before investing.

---

## What This Does

| Endpoint | Description |
|---|---|
| `GET /api/stock/{ticker}` | Live price + fundamentals from Yahoo Finance (15-min cache) |
| `GET /api/analyze/{ticker}` | Phase classification + Buy/Hold/Sell signal + AI narrative (6-hr cache) |
| `POST /api/track` | Visitor event tracking (page_load, analyze, watchlist_add, etc.) |
| `POST /api/session` | Firebase token verification + user upsert |
| `GET /api/admin/summary?key=` | Analytics dashboard data (visitors, events, top tickers, daily activity) |

---

## The Signal Engine

Every score starts at 50. Rules are applied transparently — every adjustment is returned in `signalDrivers[]` so users see exactly how the signal was computed.

| Factor | Rule | Points |
|---|---|---|
| Revenue growth | >20% / >10% / negative | +10 / +5 / −10 |
| Operating margin | >25% / >10% / negative | +10 / +5 / −10 |
| FCF yield | >3% / >1.5% / negative | +10 / +5 / −10 |
| Valuation (P/E) | <20x / <35x / >60x | +10 / +5 / −10 |
| Leverage | Debt/Equity > 2x | −5 |
| Growth phase | Rule of 40 pass / fail | +10 / −5 |
| Decline phase | Lifecycle risk | −10 |
| Mature + dividend | Shareholder returns | +3 |

**Score → Signal:** 70–100 = **BUY** · 45–69 = **HOLD** · 0–44 = **SELL**

---

## Deploy to Render (Free)

### 1. Fork this repo

### 2. Create a new Web Service on [render.com](https://render.com)

Connect this repo. Render auto-detects `render.yaml`.

### 3. Set environment variables

| Variable | Description | Required |
|---|---|---|
| `ADMIN_KEY` | Any long random string — protects `/api/admin/summary` | ✅ Yes |
| `FIREBASE_PROJECT_ID` | Your Firebase project ID — enables sign-in | ✅ Yes |
| `GROQ_API_KEY` | Free key from [console.groq.com](https://console.groq.com) — enables LLM analysis | Optional |
| `DATABASE_URL` | Supabase Postgres connection string — for persistent analytics | Optional |
| `ALLOWED_ORIGINS` | Comma-separated extra CORS origins | Optional |
| `PHASELENS_MOCK` | Set to `1` for testing without live market data | Optional |

Generate a secure `ADMIN_KEY`:
```bash
openssl rand -hex 24
```

### 4. Verify deployment

```bash
curl https://your-service.onrender.com/
# → {"service":"PhaseLens API","status":"ok"}

curl https://your-service.onrender.com/api/stock/AAPL
# → {"ticker":"AAPL","price":...,"gross_margin":...}

curl https://your-service.onrender.com/api/analyze/NVDA
# → {"recommendation":"BUY","score":82,"signalDrivers":[...],...}
```

---

## Local Development

```bash
# Clone
git clone https://github.com/your-username/phaselens-backend
cd phaselens-backend

# Install dependencies
pip install -r requirements.txt

# Run with mock market data (no Yahoo Finance calls)
PHASELENS_MOCK=1 ADMIN_KEY=dev-key uvicorn main:app --reload

# Interactive API docs
open http://localhost:8000/docs
```

---

## Database

**Default:** SQLite (`phaselens.db` in the working directory). Simple, no setup, but **data resets on every Render redeploy**.

**Recommended for production:** Supabase Postgres — free tier, data persists forever.

1. Create a project at [supabase.com](https://supabase.com)
2. Project Settings → Database → Connection string (URI)
3. Set it as `DATABASE_URL` on Render

Tables created automatically on first run:

```sql
events (id, visitor_id, email, event, ticker, created_at)
accounts (uid, email, name, provider, first_seen, last_seen, sign_ins)
```

---

## Analytics Events

Every user action the frontend fires to `POST /api/track`:

| Event | Fired when |
|---|---|
| `page_load` | App opened |
| `view_dashboard` / `view_portfolio` / `view_watchlist` / `view_research` | Tab switched |
| `analyze` + ticker | Analysis modal opened |
| `watchlist_add` + ticker | Stock added to watchlist |
| `holding_add` + ticker | Holding added to portfolio |

---

## Admin Dashboard

Access your analytics at `/api/admin/summary?key=YOUR_ADMIN_KEY`.

Or use the included `admin.html` frontend — enter your Render URL and admin key, and you get a full dashboard: visitor counts, signed-in users, daily activity chart, most-analyzed tickers, and a live event feed.

---

## Stack

- **FastAPI** — API framework
- **yfinance** — Yahoo Finance market data
- **Groq / llama-3.1-8b-instant** — LLM-written analysis narratives (optional)
- **PyJWT + cryptography** — Firebase ID token verification
- **SQLite / Postgres** — Event and user storage
- **Render** — Hosting (free tier, cold-starts after 15 min inactivity)

---

## Caching

| Data | TTL |
|---|---|
| Stock fundamentals | 15 minutes |
| Full analysis (phase + signal + AI) | 6 hours |

Cache is in-memory (per process). Resets on restart. For multi-instance deployments, move cache to Redis.

---

## Limitations

- **Render free tier** sleeps after 15 minutes idle. First request after sleep takes ~50 seconds.
- **SQLite** data resets on redeploy. Use `DATABASE_URL` (Supabase) for persistence.
- **yfinance** is unofficial. Yahoo can rate-limit or break it without notice. The 503 error includes the raw reason.
- **Email sign-in** is identification, not authentication — no passwords. Good enough for beta. Real auth (Clerk/Firebase Auth) is on the roadmap.

---

## Roadmap

- [ ] Next.js frontend with Clerk auth and Supabase sync
- [ ] Management credibility score (earnings transcript analysis)
- [ ] Reverse DCF calculator
- [ ] Macro trigger overlays
- [ ] Redis cache for multi-instance deployments

---

## License

MIT — use it, fork it, build on it. Attribution appreciated but not required.

---

*PhaseLens is not a licensed financial advisor. Nothing here is investment advice.*
