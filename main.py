"""
PhaseLens API v2 — live market data, AI analysis, Buy/Hold/Sell engine,
Firebase sign-in (email + Google), visitor analytics, admin dashboard.

Env vars (set these on Render):
  FMP_API_KEY          Financial Modeling Prep key — free at financialmodelingprep.com
  FIREBASE_PROJECT_ID  required for sign-in — your Firebase project ID
  ADMIN_EMAIL          admin account email   (default: nmohanaraman@gmail.com)
  ADMIN_KEY            fallback admin key for the dashboard (any long random string)
  GROQ_API_KEY         optional — LLM-written analysis (free key: console.groq.com)
  DATABASE_URL         optional — Supabase Postgres URL (else SQLite file)
  ALLOWED_ORIGINS      optional — comma-separated extra CORS origins
  PHASELENS_MOCK       optional — "1" = sample market data (testing without network)
"""
import os, json, time, sqlite3
from datetime import datetime, timezone
from contextlib import contextmanager

import httpx
import jwt as pyjwt
from cryptography.x509 import load_pem_x509_certificate
from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

GROQ_API_KEY        = os.environ.get("GROQ_API_KEY", "")
FMP_API_KEY         = os.environ.get("FMP_API_KEY", "")
ADMIN_KEY           = os.environ.get("ADMIN_KEY", "")
ADMIN_EMAIL         = os.environ.get("ADMIN_EMAIL", "nmohanaraman@gmail.com").strip().lower()
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "")
DATABASE_URL        = os.environ.get("DATABASE_URL", "")
MOCK                = os.environ.get("PHASELENS_MOCK", "") == "1"

app = FastAPI(title="PhaseLens API", version="2.0")

_origins = [
    "https://phaselens.ai", "https://www.phaselens.ai",
    "https://phaselens.netlify.app",
    "http://localhost:3000", "http://localhost:8888", "null",
]
_origins += [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_origin_regex=r"https://.*\.netlify\.app",
    allow_methods=["*"], allow_headers=["*"],
)

# ─────────────────────────── Database ───────────────────────────────────────
IS_PG = DATABASE_URL.startswith("postgres")

def _connect():
    if IS_PG:
        import psycopg2
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(os.environ.get("SQLITE_PATH", "phaselens.db"))

@contextmanager
def db():
    conn = _connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def q(sql):
    return sql.replace("?", "%s") if IS_PG else sql

def init_db():
    with db() as conn:
        c = conn.cursor()
        if IS_PG:
            c.execute("""CREATE TABLE IF NOT EXISTS events(
                id SERIAL PRIMARY KEY, visitor_id TEXT, email TEXT,
                event TEXT, ticker TEXT, created_at TEXT)""")
        else:
            c.execute("""CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT, visitor_id TEXT, email TEXT,
                event TEXT, ticker TEXT, created_at TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS accounts(
            uid TEXT PRIMARY KEY, email TEXT, name TEXT, provider TEXT,
            first_seen TEXT, last_seen TEXT, sign_ins INTEGER DEFAULT 0)""")
init_db()

def now_iso():
    return datetime.now(timezone.utc).isoformat()

# ─────────────────────────── Firebase token verification ────────────────────
GOOGLE_CERT_URL = ("https://www.googleapis.com/robot/v1/metadata/x509/"
                   "securetoken@system.gserviceaccount.com")
_cert_cache = {"exp": 0.0, "certs": {}}

def _get_google_certs() -> dict:
    """Fetch + cache Google's public signing certs (rotated regularly)."""
    if _cert_cache["exp"] > time.time():
        return _cert_cache["certs"]
    r = httpx.get(GOOGLE_CERT_URL, timeout=10)
    r.raise_for_status()
    _cert_cache["certs"] = r.json()
    _cert_cache["exp"] = time.time() + 3600
    return _cert_cache["certs"]

def verify_firebase_token(token: str) -> dict:
    """Verify a Firebase ID token: signature, audience, issuer, expiry."""
    if not FIREBASE_PROJECT_ID:
        raise HTTPException(503, "Sign-in not configured: set FIREBASE_PROJECT_ID")
    try:
        header = pyjwt.get_unverified_header(token)
    except pyjwt.PyJWTError:
        raise HTTPException(401, "Malformed token")
    pem = _get_google_certs().get(header.get("kid", ""))
    if not pem:
        raise HTTPException(401, "Unknown signing key")
    public_key = load_pem_x509_certificate(pem.encode()).public_key()
    try:
        claims = pyjwt.decode(
            token, public_key, algorithms=["RS256"],
            audience=FIREBASE_PROJECT_ID,
            issuer=f"https://securetoken.google.com/{FIREBASE_PROJECT_ID}",
        )
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired — sign in again")
    except pyjwt.PyJWTError as exc:
        raise HTTPException(401, f"Invalid token: {exc}")
    email = (claims.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(401, "Token has no email")
    fb = claims.get("firebase") or {}
    return {"uid": claims.get("user_id") or claims.get("sub") or email,
            "email": email,
            "name": claims.get("name") or "",
            "provider": fb.get("sign_in_provider", "password")}

# ─────────────────────────── Market data (yfinance, cached) ─────────────────
_stock_cache: dict = {}
_analysis_cache: dict = {}
STOCK_TTL, ANALYSIS_TTL = 900, 21600

MOCK_DATA = {
    "ticker": "MOCK", "name": "Mock Co", "price": 100.0, "pe_ratio": 25.0,
    "fcf_yield": 2.5, "gross_margin": 50.0, "operating_margin": 20.0,
    "revenue_growth": 15.0, "dividend_yield": 0.5, "debt_to_equity": 0.8,
    "market_cap": 50_000_000_000,
}

def _fmp_get(path: str) -> dict:
    """Call FMP API and return parsed JSON. Raises HTTPException on failure."""
    url = f"https://financialmodelingprep.com/stable/{path}&apikey={FMP_API_KEY}"
    r = httpx.get(url, timeout=15)
    if r.status_code == 401:
        raise HTTPException(503, "FMP API key invalid — check FMP_API_KEY on Render")
    if r.status_code == 429:
        raise HTTPException(503, "FMP daily limit reached (250/day on free plan)")
    r.raise_for_status()
    data = r.json()
    if isinstance(data, dict) and "Error Message" in data:
        raise HTTPException(503, f"FMP error: {data['Error Message']}")
    return data


def fetch_stock(ticker: str) -> dict:
    t = ticker.upper().strip()
    hit = _stock_cache.get(t)
    if hit and hit[0] > time.time():
        return hit[1]
    if MOCK:
        data = dict(MOCK_DATA, ticker=t, name=f"{t} Inc (mock)")
    elif FMP_API_KEY:
        # ── Financial Modeling Prep — /stable/ endpoints ──
        # /stable/quote              → price, marketCap, name
        # /stable/ratios-ttm         → margins, debt/equity, dividend yield
        # /stable/key-metrics-ttm    → PE ratio, FCF yield (most reliable source)
        # /stable/income-statement   → revenue history for growth calc
        try:
            # 1. Quote: real-time price + name + market cap
            quote_raw = _fmp_get(f"quote?symbol={t}")
            if not quote_raw or not isinstance(quote_raw, list):
                raise HTTPException(503, f"No data for {t} — verify the ticker symbol")
            q = quote_raw[0]

            # 2. Key metrics TTM: PE ratio + FCF yield (most reliable FMP source)
            km_raw = _fmp_get(f"key-metrics-ttm?symbol={t}")
            km = km_raw[0] if km_raw and isinstance(km_raw, list) else {}

            # 3. Ratios TTM: margins + debt/equity + dividend yield
            ratios_raw = _fmp_get(f"ratios-ttm?symbol={t}")
            r = ratios_raw[0] if ratios_raw and isinstance(ratios_raw, list) else {}

            # 4. Income statement: 2 years for revenue growth
            income_raw = _fmp_get(f"income-statement?symbol={t}&limit=2&period=annual")
            rev_growth = None
            if income_raw and len(income_raw) >= 2:
                r_new = income_raw[0].get("revenue") or 0
                r_old = income_raw[1].get("revenue") or 1
                rev_growth = round((r_new - r_old) / abs(r_old) * 100, 1) if r_old else None

            price = q.get("price")
            mc    = q.get("marketCap") or 0

            if not price:
                raise HTTPException(503, f"No price returned for {t} — check ticker symbol")

            # Helper: first non-null non-zero value across multiple sources + field names
            def pick(*pairs, pct=False):
                """pairs = (obj, fieldname) tuples in priority order"""
                for obj, key in pairs:
                    v = obj.get(key)
                    if v is not None and v != 0:
                        return round(float(v) * (100 if pct else 1), 2)
                return None

            data = {
                "ticker":           t,
                "name":             q.get("name") or t,
                "price":            price,
                "pe_ratio":         pick(
                                      (km, "peRatioTTM"),
                                      (r,  "peRatioTTM"),
                                      (km, "priceEarningsRatioTTM"),
                                    ),
                "fcf_yield":        pick(
                                      (km, "freeCashFlowYieldTTM"),
                                      (km, "fcfYieldTTM"),
                                      (r,  "freeCashFlowYieldTTM"),
                                      pct=True,
                                    ),
                "gross_margin":     pick((r, "grossProfitMarginTTM"),
                                        (km,"grossProfitMarginTTM"), pct=True),
                "operating_margin": pick((r, "operatingProfitMarginTTM"),
                                        (km,"operatingProfitMarginTTM"), pct=True),
                "revenue_growth":   rev_growth,
                "dividend_yield":   pick((r,  "dividendYieldTTM"),
                                        (km, "dividendYieldTTM"),
                                        (q,  "dividendYield"), pct=True),
                "debt_to_equity":   pick((r,  "debtEquityRatioTTM"),
                                        (km, "debtToEquityTTM"),
                                        (r,  "totalDebtToEquityTTM")),
                "market_cap":       mc,
            }
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(503, f"Market data unavailable for {t}: {exc}")
    else:
        # ── yfinance fallback (works locally, unreliable on cloud) ──
        try:
            import yfinance as yf
            info = yf.Ticker(t).info
            mc     = info.get("marketCap") or 0
            fcf    = info.get("freeCashflow") or 0
            de_raw = info.get("debtToEquity")
            price  = info.get("currentPrice") or info.get("regularMarketPrice")
            if not price:
                raise ValueError("no price returned")
            data = {
                "ticker": t,
                "name":             info.get("longName") or info.get("shortName") or t,
                "price":            price,
                "pe_ratio":         info.get("trailingPE"),
                "fcf_yield":        round(fcf / mc * 100, 2) if mc else None,
                "gross_margin":     round((info.get("grossMargins") or 0) * 100, 1),
                "operating_margin": round((info.get("operatingMargins") or 0) * 100, 1),
                "revenue_growth":   round((info.get("revenueGrowth") or 0) * 100, 1),
                "dividend_yield":   round((info.get("dividendYield") or 0) * 100, 2),
                "debt_to_equity":   round(de_raw / 100, 2) if de_raw else None,
                "market_cap":       mc,
            }
        except Exception as exc:
            raise HTTPException(503, f"Market data unavailable for {t}: {exc}. Set FMP_API_KEY on Render for reliable data.")
    _stock_cache[t] = (time.time() + STOCK_TTL, data)
    return data

# ─────────────────────────── Phase classification ──────────────────────────
def classify_phase(m: dict) -> dict:
    rg  = m.get("revenue_growth") or 0
    om  = m.get("operating_margin") or 0
    fcf = m.get("fcf_yield") or 0
    gm  = m.get("gross_margin") or 0
    signals = []
    if rg <= 0 and gm <= 0:
        phase = "PRE_REVENUE"; signals.append("Negative revenue trend with negative gross margin")
    elif rg > 15:
        phase = "GROWTH"; signals.append(f"Revenue growth {rg:.1f}% exceeds 15% growth threshold")
    elif rg >= 3 and om > 10 and fcf > 1.5:
        phase = "MATURE"; signals.append(f"Moderate growth ({rg:.1f}%) with strong margins and FCF")
    elif rg < 3 and (om < 5 or fcf < 0):
        phase = "DECLINE"; signals.append(f"Low growth ({rg:.1f}%) with weak margins/FCF")
    elif rg >= 3:
        phase = "MATURE"; signals.append(f"Steady growth ({rg:.1f}%) with established profitability")
    else:
        phase = "DECLINE"; signals.append("Growth below maturity threshold")
    return {"phase": phase, "signals": signals}

# ─────────────────────────── Buy / Hold / Sell engine ───────────────────────
def compute_signal(m: dict, phase: str) -> dict:
    score, drivers = 50, []
    rg  = m.get("revenue_growth") or 0
    om  = m.get("operating_margin") or 0
    fcf = m.get("fcf_yield")
    pe  = m.get("pe_ratio")
    de  = m.get("debt_to_equity")

    def add(pts, why):
        nonlocal score
        score += pts
        drivers.append(("+" if pts >= 0 else "") + f"{pts}: {why}")

    if rg > 20: add(10, f"Strong revenue growth ({rg:.1f}%)")
    elif rg > 10: add(5, f"Healthy revenue growth ({rg:.1f}%)")
    elif rg < 0: add(-10, f"Revenue contracting ({rg:.1f}%)")

    if om > 25: add(10, f"Excellent operating margin ({om:.1f}%)")
    elif om > 10: add(5, f"Solid operating margin ({om:.1f}%)")
    elif om < 0: add(-10, f"Operating losses ({om:.1f}%)")

    if fcf is not None:
        if fcf > 3: add(10, f"High FCF yield ({fcf:.1f}%)")
        elif fcf > 1.5: add(5, f"Positive FCF yield ({fcf:.1f}%)")
        elif fcf < 0: add(-10, f"Negative free cash flow ({fcf:.1f}%)")

    if pe:
        if 0 < pe < 20: add(10, f"Attractive valuation (P/E {pe:.1f}x)")
        elif pe < 35: add(5, f"Reasonable valuation (P/E {pe:.1f}x)")
        elif pe > 60: add(-10, f"Stretched valuation (P/E {pe:.1f}x)")

    if de is not None and de > 2: add(-5, f"Elevated leverage (D/E {de:.1f}x)")

    if phase == "GROWTH":
        r40 = rg + om
        if r40 >= 40: add(10, f"Rule of 40 passed ({r40:.0f})")
        else: add(-5, f"Rule of 40 missed ({r40:.0f})")
    elif phase == "DECLINE":
        add(-10, "Decline-phase lifecycle risk")
    elif phase == "MATURE" and (m.get("dividend_yield") or 0) > 0:
        add(3, "Shareholder returns via dividend")

    score = max(0, min(100, score))
    rec = "BUY" if score >= 70 else "HOLD" if score >= 45 else "SELL"
    return {"score": score, "recommendation": rec, "drivers": drivers}

# ─────────────────────────── AI analysis (Groq, optional) ──────────────────
def groq_analysis(t, m, phase, sig):
    prompt = (
        f"You are an equity research analyst. Company {t}: {json.dumps(m)}. "
        f"Lifecycle phase: {phase}. Model signal: {sig['recommendation']} (score {sig['score']}). "
        'Return ONLY JSON: {"summary":str(2-3 sentences),"phaseRationale":str,'
        '"strengths":[3 strings],"risks":[3 strings],"mgmtNote":str(1 sentence)}'
    )
    r = httpx.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
        json={"model": "llama-3.1-8b-instant",
              "messages": [{"role": "user", "content": prompt}],
              "response_format": {"type": "json_object"}, "temperature": 0.4},
        timeout=25,
    )
    r.raise_for_status()
    return json.loads(r.json()["choices"][0]["message"]["content"])

def fallback_analysis(t, m, phase, sig):
    rg, om = m.get("revenue_growth") or 0, m.get("operating_margin") or 0
    return {
        "summary": f"{m.get('name', t)} shows {rg:.1f}% revenue growth with a "
                   f"{om:.1f}% operating margin, placing it in the {phase} lifecycle phase. "
                   f"The rules-based model scores it {sig['score']}/100 → {sig['recommendation']}.",
        "phaseRationale": f"{phase}: classified from revenue growth, margin structure and FCF yield.",
        "strengths": [d[d.index(':')+2:] for d in sig["drivers"] if d.startswith("+")][:3]
                     or ["Review fundamentals against sector peers"],
        "risks": [d[d.index(':')+2:] for d in sig["drivers"] if d.startswith("-")][:3]
                 or ["Macro and competitive risks apply"],
        "mgmtNote": "Management credibility scoring requires earnings-transcript analysis (roadmap).",
    }

DISCLAIMER = ("PhaseLens is an educational research tool — not a licensed financial advisor, "
              "broker, or consultant. Signals are generated automatically by a rules-based model "
              "from public data and may be inaccurate or outdated. Nothing here is financial advice "
              "or a recommendation to trade any security. Do your own research and consult a "
              "licensed financial professional before investing.")

# ─────────────────────────── Public endpoints ───────────────────────────────
@app.get("/")
def root():
    return {"service": "PhaseLens API", "version": "2.0", "status": "ok",
            "mock_mode": MOCK, "ai_enabled": bool(GROQ_API_KEY),
            "fmp_enabled": bool(FMP_API_KEY),
            "auth_enabled": bool(FIREBASE_PROJECT_ID)}

@app.get("/api/stock/{ticker}")
def api_stock(ticker: str):
    return fetch_stock(ticker)

@app.get("/api/analyze/{ticker}")
def api_analyze(ticker: str):
    t = ticker.upper().strip()
    hit = _analysis_cache.get(t)
    if hit and hit[0] > time.time():
        return hit[1]
    m = fetch_stock(t)
    ph = classify_phase(m)
    sig = compute_signal(m, ph["phase"])
    if GROQ_API_KEY:
        try:
            ai = groq_analysis(t, m, ph["phase"], sig)
        except Exception:
            ai = fallback_analysis(t, m, ph["phase"], sig)
    else:
        ai = fallback_analysis(t, m, ph["phase"], sig)
    payload = {
        "ticker": t, "name": m.get("name"), "price": m.get("price"),
        "phase": ph["phase"], "phaseSignals": ph["signals"],
        "score": sig["score"], "recommendation": sig["recommendation"],
        "signalDrivers": sig["drivers"], "metrics": m,
        "summary": ai.get("summary"), "phaseRationale": ai.get("phaseRationale"),
        "strengths": ai.get("strengths"), "risks": ai.get("risks"),
        "mgmtNote": ai.get("mgmtNote"), "disclaimer": DISCLAIMER,
        "generated_at": now_iso(),
    }
    _analysis_cache[t] = (time.time() + ANALYSIS_TTL, payload)
    return payload

# ─────────────────────────── Auth session ───────────────────────────────────
class SessionIn(BaseModel):
    token: str
    visitor_id: str | None = None

@app.post("/api/session")
def api_session(body: SessionIn):
    u = verify_firebase_token(body.token)
    with db() as conn:
        c = conn.cursor()
        c.execute(q("SELECT uid FROM accounts WHERE uid=?"), (u["uid"],))
        if c.fetchone():
            c.execute(q("""UPDATE accounts SET email=?, name=?, provider=?,
                           last_seen=?, sign_ins=sign_ins+1 WHERE uid=?"""),
                      (u["email"], u["name"], u["provider"], now_iso(), u["uid"]))
        else:
            c.execute(q("""INSERT INTO accounts(uid,email,name,provider,first_seen,last_seen,sign_ins)
                           VALUES(?,?,?,?,?,?,1)"""),
                      (u["uid"], u["email"], u["name"], u["provider"], now_iso(), now_iso()))
        c.execute(q("INSERT INTO events(visitor_id,email,event,ticker,created_at) VALUES(?,?,?,?,?)"),
                  ((body.visitor_id or "")[:64], u["email"], "signin", "", now_iso()))
    return {"ok": True, "email": u["email"], "name": u["name"],
            "is_admin": u["email"] == ADMIN_EMAIL}

# ─────────────────────────── Event tracking ─────────────────────────────────
class TrackIn(BaseModel):
    visitor_id: str
    event: str
    ticker: str | None = None
    email: str | None = None

@app.post("/api/track")
def api_track(body: TrackIn):
    with db() as conn:
        c = conn.cursor()
        c.execute(q("INSERT INTO events(visitor_id,email,event,ticker,created_at) VALUES(?,?,?,?,?)"),
                  (body.visitor_id[:64], (body.email or "")[:120], body.event[:64],
                   (body.ticker or "")[:12], now_iso()))
    return {"ok": True}

# ─────────────────────────── Debug (remove after field names confirmed) ───────
@app.get("/api/debug/{ticker}")
def api_debug(ticker: str):
    """Dump raw FMP field names — open in browser to see exact keys. Delete once done."""
    if not FMP_API_KEY:
        raise HTTPException(503, "FMP_API_KEY not set")
    t = ticker.upper().strip()
    result = {}
    for name, path in [
        ("key_metrics_ttm", f"key-metrics-ttm?symbol={t}"),
        ("ratios_ttm",      f"ratios-ttm?symbol={t}"),
        ("quote",           f"quote?symbol={t}"),
    ]:
        try:
            raw = _fmp_get(path)
            result[name] = raw[0] if raw and isinstance(raw, list) else raw
        except Exception as e:
            result[name] = {"error": str(e)}
    return result

# ─────────────────────────── Admin (key OR signed-in admin email) ───────────
def check_admin(key: str | None, authorization: str | None):
    if ADMIN_KEY and key == ADMIN_KEY:
        return
    if authorization and authorization.lower().startswith("bearer "):
        u = verify_firebase_token(authorization[7:])
        if u["email"] == ADMIN_EMAIL:
            return
        raise HTTPException(403, f"{u['email']} is not the admin account")
    raise HTTPException(401, "Admin auth required: ?key= or Bearer token")

@app.get("/api/admin/summary")
def admin_summary(key: str | None = Query(None),
                  authorization: str | None = Header(None)):
    check_admin(key, authorization)
    with db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(DISTINCT visitor_id) FROM events"); visitors = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM accounts"); n_accounts = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM events"); total_events = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM events WHERE event LIKE 'analyze%'"); analyses = c.fetchone()[0]
        c.execute("""SELECT ticker, COUNT(*) n FROM events
                     WHERE ticker<>'' GROUP BY ticker ORDER BY n DESC LIMIT 8""")
        top_tickers = [{"ticker": r[0], "count": r[1]} for r in c.fetchall()]
        c.execute("""SELECT substr(created_at,1,10) d, COUNT(*) n FROM events
                     GROUP BY d ORDER BY d DESC LIMIT 14""")
        daily = [{"date": r[0], "count": r[1]} for r in c.fetchall()][::-1]
        c.execute("""SELECT email,name,provider,sign_ins,first_seen,last_seen
                     FROM accounts ORDER BY last_seen DESC LIMIT 50""")
        accounts = [{"email": r[0], "name": r[1] or "", "provider": r[2] or "",
                     "sign_ins": r[3], "first_seen": r[4], "last_seen": r[5]}
                    for r in c.fetchall()]
        c.execute("""SELECT visitor_id,email,event,ticker,created_at FROM events
                     ORDER BY id DESC LIMIT 50""")
        events = [{"visitor_id": r[0], "email": r[1] or "", "event": r[2],
                   "ticker": r[3] or "", "at": r[4]} for r in c.fetchall()]
    return {"visitors": visitors, "accounts": n_accounts,
            "total_events": total_events, "analyses": analyses,
            "top_tickers": top_tickers, "daily": daily,
            "account_list": accounts, "recent_events": events,
            "admin_email": ADMIN_EMAIL}
