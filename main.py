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
        c.execute("""CREATE TABLE IF NOT EXISTS terms(
            visitor_id TEXT PRIMARY KEY, email TEXT,
            agreed_at TEXT, ip_hash TEXT)""")
        # analyses table — stores every verdict result for admin dashboard
        c.execute("""CREATE TABLE IF NOT EXISTS analyses(
            id INTEGER PRIMARY KEY """ + ("GENERATED ALWAYS AS IDENTITY" if IS_PG else "AUTOINCREMENT") + """,
            visitor_id TEXT, email TEXT, ticker TEXT,
            verdict TEXT, recommendation TEXT, score INTEGER,
            phase TEXT, buffett_score INTEGER, dilution_status TEXT,
            runway_status TEXT, stage TEXT, created_at TEXT)""" if not IS_PG else
            """CREATE TABLE IF NOT EXISTS analyses(
            id SERIAL PRIMARY KEY, visitor_id TEXT, email TEXT, ticker TEXT,
            verdict TEXT, recommendation TEXT, score INTEGER,
            phase TEXT, buffett_score INTEGER, dilution_status TEXT,
            runway_status TEXT, stage TEXT, created_at TEXT)""")
        # Migrate: add terms_agreed_at to accounts if missing
        try:
            c.execute("ALTER TABLE accounts ADD COLUMN terms_agreed_at TEXT")
        except Exception:
            pass
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

            # 4. Income statement: 4 years for revenue growth + EPS predictability
            income_raw = _fmp_get(f"income-statement?symbol={t}&limit=4&period=annual")
            rev_growth = None
            eps_history = []   # list of EPS values newest→oldest, for predictability check
            if income_raw and len(income_raw) >= 2:
                r_new = income_raw[0].get("revenue") or 0
                r_old = income_raw[1].get("revenue") or 1
                rev_growth = round((r_new - r_old) / abs(r_old) * 100, 1) if r_old else None
                # Collect EPS for up to 4 years
                for yr in income_raw:
                    eps_val = yr.get("eps") or yr.get("epsdiluted")
                    if eps_val is not None:
                        eps_history.append(eps_val)

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

            # Field names confirmed from live FMP debug endpoint response
            data = {
                "ticker":           t,
                "name":             q.get("name") or t,
                "price":            price,
                "pe_ratio":         pick(
                                      (r,  "priceToEarningsRatioTTM"),   # confirmed in ratios_ttm
                                    ),
                "fcf_yield":        pick(
                                      (km, "freeCashFlowYieldTTM"),       # confirmed in key_metrics_ttm
                                      pct=True,
                                    ),
                "gross_margin":     pick((r, "grossProfitMarginTTM"),     # confirmed
                                        pct=True),
                "operating_margin": pick((r, "operatingProfitMarginTTM"), # confirmed
                                        pct=True),
                "revenue_growth":   rev_growth,
                "dividend_yield":   pick((r, "dividendYieldTTM"),         # confirmed: 0.00360664
                                        pct=True),
                "debt_to_equity":   pick((r, "debtToEquityRatioTTM"),    # confirmed in ratios_ttm
                                    ),
                "market_cap":       mc,
                # Extra fields for forensic analysis
                "roic":             pick((km, "returnOnInvestedCapitalTTM"), pct=True),
                "eps_history":      eps_history,   # newest→oldest, up to 4yr
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

# ─────────────────────────── Deep data (balance sheet + cash flow) ─────────
def fetch_deep_data(ticker: str) -> dict:
    """Fetch balance sheet + cash flow statement for forensic analysis.
    Only called from /api/analyze — adds 2 FMP calls per ticker."""
    t = ticker.upper().strip()
    if MOCK:
        return {
            "cash": 50_000_000_000, "total_debt": 40_000_000_000,
            "total_equity": 80_000_000_000, "retained_earnings": 60_000_000_000,
            "retained_earnings_prior": 55_000_000_000,
            "preferred_stock": 0, "treasury_stock": -20_000_000_000,
            "shares_outstanding": 15_000_000_000, "shares_outstanding_prior": 15_500_000_000,
            "net_share_issuance": -3_000_000_000, "net_share_issuance_prior": -2_500_000_000,
            "fcf": 100_000_000_000, "fcf_prior": 90_000_000_000,
            "operating_income": 30_000_000_000,
        }
    if not FMP_API_KEY:
        return {}
    result = {}
    try:
        # Balance sheet: 2 years for trend comparison
        bs_raw = _fmp_get(f"balance-sheet-statement?symbol={t}&limit=2&period=annual")
        if bs_raw and isinstance(bs_raw, list) and bs_raw:
            bs = bs_raw[0]
            bs_prior = bs_raw[1] if len(bs_raw) >= 2 else {}
            result["cash"]              = (bs.get("cashAndCashEquivalents") or 0) + (bs.get("shortTermInvestments") or 0)
            result["total_debt"]        = bs.get("totalDebt") or bs.get("longTermDebt") or 0
            result["total_equity"]      = bs.get("totalStockholdersEquity") or 0
            result["retained_earnings"] = bs.get("retainedEarnings") or 0
            result["retained_earnings_prior"] = bs_prior.get("retainedEarnings") or 0
            result["preferred_stock"]   = bs.get("preferredStock") or 0
            result["treasury_stock"]    = bs.get("totalTreasuryStock") or bs.get("treasuryStock") or 0
            result["shares_outstanding"] = bs.get("commonStockSharesOutstanding") or bs.get("sharesOutstanding") or 0
            result["shares_outstanding_prior"] = bs_prior.get("commonStockSharesOutstanding") or bs_prior.get("sharesOutstanding") or 0

        # Cash flow statement: 2 years for dilution trend
        cf_raw = _fmp_get(f"cash-flow-statement?symbol={t}&limit=2&period=annual")
        if cf_raw and isinstance(cf_raw, list) and cf_raw:
            cf = cf_raw[0]
            cf_prior = cf_raw[1] if len(cf_raw) >= 2 else {}
            result["net_share_issuance"] = (cf.get("commonStockIssued") or 0) - abs(cf.get("commonStockRepurchased") or 0)
            result["net_share_issuance_prior"] = (cf_prior.get("commonStockIssued") or 0) - abs(cf_prior.get("commonStockRepurchased") or 0)
            result["fcf"]       = cf.get("freeCashFlow") or 0
            result["fcf_prior"] = cf_prior.get("freeCashFlow") or 0
            result["operating_income"] = cf.get("operatingIncome") or 0
    except Exception:
        pass  # deep data is optional — analysis still works without it
    return result


# ─────────────────────────── Forensic analysis engine ─────────────────────
def _status(val, g_thresh, y_thresh, invert=False):
    """Map a numeric value to green/yellow/red. invert=True: lower is better."""
    if val is None: return "gray"
    if not invert:
        if val >= g_thresh: return "green"
        if val >= y_thresh: return "yellow"
        return "red"
    else:
        if val <= g_thresh: return "green"
        if val <= y_thresh: return "yellow"
        return "red"

def compute_forensics(m: dict, deep: dict) -> dict:
    """
    Spec-compliant forensics. Every metric returned as:
      {value: str, status: green|yellow|red|gray, label: str}
    Structured exactly as the frontend mapping spec requires.
    """
    checks  = {}
    drivers = []

    # ── 1. BUFFETT CHECKS ─────────────────────────────────────────────
    roic     = m.get("roic")             # % already
    gm       = m.get("gross_margin")     # %
    de       = m.get("debt_to_equity")   # ratio
    fcf_y    = m.get("fcf_yield")        # %
    eps_hist = m.get("eps_history", [])  # newest→oldest

    # ROIC
    roic_s = _status(roic, 10, 5)
    checks["roic"] = {
        "value": f"{roic:.1f}%" if roic else "N/A",
        "status": roic_s,
        "label": "Pass" if roic_s=="green" else ("Warning" if roic_s=="yellow" else "Fail"),
    }
    if roic_s=="green":   drivers.append(f"+5: ROIC {roic:.1f}% — strong capital efficiency")
    elif roic_s=="yellow":drivers.append(f"-2: ROIC {roic:.1f}% — mediocre capital allocation")
    elif roic_s=="red":   drivers.append(f"-8: ROIC {roic:.1f}% — poor capital efficiency")

    # Gross Margin
    gm_s = _status(gm, 40, 20)
    checks["gross_margin"] = {
        "value": f"{gm:.1f}%" if gm else "N/A",
        "status": gm_s,
        "label": "Pricing Power" if gm_s=="green" else ("Average" if gm_s=="yellow" else "Commoditized"),
    }
    if gm_s=="green":  drivers.append(f"+5: Gross margin {gm:.1f}% — pricing power intact")
    elif gm_s=="red":  drivers.append(f"-5: Gross margin {gm:.1f}% — highly commoditized")

    # Debt-to-Equity (spec: <1.0 green, 1-2.5 yellow, >2.5 red)
    de_s = _status(de, 1.0, 2.5, invert=True)
    checks["debt_to_equity"] = {
        "value": f"{de:.2f}x" if de else "N/A",
        "status": de_s,
        "label": "Low Leverage" if de_s=="green" else ("Moderate" if de_s=="yellow" else "Over-Leveraged"),
    }
    if de and de_s=="red":   drivers.append(f"-8: D/E {de:.2f}x — dangerously over-leveraged")
    elif de and de_s=="yellow": drivers.append(f"-3: D/E {de:.2f}x — moderate leverage")
    elif de and de_s=="green":  drivers.append(f"+3: D/E {de:.2f}x — conservative balance sheet")

    # FCF Yield (spec: >5% green, 2-5% yellow, <2% or negative red)
    fcf_s = _status(fcf_y, 5, 2)
    checks["fcf_yield"] = {
        "value": f"{fcf_y:.1f}%" if fcf_y is not None else "N/A",
        "status": fcf_s,
        "label": "Strong FCF" if fcf_s=="green" else ("Adequate" if fcf_s=="yellow" else "Weak/Negative"),
    }
    if fcf_y and fcf_s=="green":  drivers.append(f"+8: FCF yield {fcf_y:.1f}% — exceptional cash generation")
    elif fcf_y and fcf_s=="yellow":drivers.append(f"+3: FCF yield {fcf_y:.1f}% — adequate cash generation")
    elif fcf_y and fcf_s=="red":   drivers.append(f"-8: FCF yield {fcf_y:.1f}% — insufficient cash generation")

    # EPS Predictability: 3+ consecutive years of growth
    eps_status, eps_label = "gray", "Insufficient Data"
    if len(eps_hist) >= 3:
        growing = all(eps_hist[i] > eps_hist[i+1] for i in range(min(3, len(eps_hist)-1)))
        positive = all(e > 0 for e in eps_hist[:3])
        if growing and positive:
            eps_status, eps_label = "green", "Consistent Growth (3yr+)"
        elif positive:
            eps_status, eps_label = "yellow", "Positive but Volatile"
        else:
            eps_status, eps_label = "red", "Negative or Erratic EPS"
    checks["eps_predictability"] = {
        "value": f"{len(eps_hist)} years data",
        "status": eps_status,
        "label": eps_label,
        "history": [round(e,2) for e in eps_hist],
    }
    if eps_status=="green":  drivers.append(f"+5: EPS growing consistently for 3+ years")
    elif eps_status=="red":  drivers.append(f"-8: Negative or erratic EPS — unpredictable earnings")

    buffett_pass = sum(1 for c in ["roic","gross_margin","debt_to_equity","fcf_yield","eps_predictability"]
                      if checks[c]["status"]=="green")
    checks["buffett_score"] = {"pass": buffett_pass, "total": 5}
    if buffett_pass >= 4: drivers.append(f"+5: Strong Buffett Balance Sheet — {buffett_pass}/5 checks passed")
    elif buffett_pass <= 2: drivers.append(f"-5: Weak Buffett Balance Sheet — only {buffett_pass}/5 checks passed")

    # ── 2. DILUTION (spec format) ─────────────────────────────────────
    shares     = deep.get("shares_outstanding") or 0
    shares_pri = deep.get("shares_outstanding_prior") or 0
    dil_pct    = round((shares - shares_pri) / shares_pri * 100, 1) if shares_pri else None
    if dil_pct is None:
        dil_status, dil_msg = "gray", "Insufficient Data"
    elif dil_pct < 0:
        dil_status, dil_msg = "green",  "Accretive (Buying Back Shares)"
        drivers.append(f"+5: Share buyback — float reduced {abs(dil_pct):.1f}% YoY")
    elif dil_pct <= 2:
        dil_status, dil_msg = "gray",   "Neutral (Standard Employee Comp)"
    elif dil_pct <= 10:
        dil_status, dil_msg = "red",    f"Dilution Alert: Issuing Stock (+{dil_pct:.1f}%)"
        drivers.append(f"-5: Share dilution {dil_pct:.1f}% YoY")
    else:
        dil_status, dil_msg = "red",    f"Toxic Dilution: +{dil_pct:.1f}% YoY"
        drivers.append(f"-15: Toxic dilution — shares expanded {dil_pct:.1f}% YoY")
    checks["dilution"] = {
        "yoy_change": f"{dil_pct:+.1f}%" if dil_pct is not None else "N/A",
        "status": dil_status,
        "message": dil_msg,
        "shares": shares,
        "shares_prior": shares_pri,
    }

    # ── 3. CASH RUNWAY ENGINE (spec format) ──────────────────────────
    fcf_abs   = deep.get("fcf") or 0
    cash      = deep.get("cash") or 0
    if fcf_abs >= 0:
        checks["runway"] = {
            "status": "green",
            "message": "Self-Sustaining (Positive FCF)",
            "months": None,
            "cash": cash,
            "fcf": fcf_abs,
        }
        drivers.append("+5: Positive FCF — no capital raise risk")
    else:
        monthly_burn = abs(fcf_abs) / 12
        months = round(cash / monthly_burn) if monthly_burn else None
        if months is None:
            runway_s, runway_msg = "gray", "Insufficient Data"
        elif months > 24:
            runway_s, runway_msg = "green",  f"Comfortable Runway ({months} months)"
            drivers.append(f"+3: Cash runway {months} months — no near-term raise risk")
        elif months >= 12:
            runway_s, runway_msg = "yellow", f"Moderate Runway — Monitoring Required ({months} months)"
            drivers.append(f"-3: Cash runway {months} months — capital raise possible within 2 years")
        else:
            runway_s, runway_msg = "red",    f"Critical Risk — Imminent Dilution or Debt Raise Likely ({months} months)"
            drivers.append(f"-10: SURVIVAL RISK — only {months} months cash runway")
        checks["runway"] = {
            "status": runway_s,
            "message": runway_msg,
            "months": months,
            "cash": cash,
            "fcf": fcf_abs,
        }

    # ── 4. STAGE CLASSIFIER (spec: 4 named nodes) ────────────────────
    rg = m.get("revenue_growth") or 0
    om = m.get("operating_margin") or 0
    if rg > 30 and fcf_abs <= 0:
        stage_node, stage_status = "Early Stage / Venture",   "blue"
    elif 15 <= rg <= 30:
        stage_node, stage_status = "Growth Phase",            "green"
    elif 0 <= rg < 15 and om > 5:
        stage_node, stage_status = "Mature / Cash Cow",       "green"
    else:
        stage_node, stage_status = "Decline / Distressed",    "red"
        drivers.append("-10: Decline-phase lifecycle risk")
    checks["stage"] = {
        "current_node": stage_node,
        "status": stage_status,
        "revenue_growth": rg,
        "operating_margin": om,
    }

    return {"checks": checks, "drivers": drivers}


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

# ─────────────────────────── Value Trap Detector ────────────────────────────
def compute_value_verdict(m: dict, forensics: dict, phase: str) -> dict:
    """
    Explicit Value Stock vs Value Trap classification.
    Returns verdict, confidence, reasons (supporting) and warnings (against).

    Logic:
      VALUE TRAP  — cheap valuation + broken fundamentals underneath
      VALUE STOCK — cheap valuation + intact/recovering fundamentals
      NEUTRAL     — no clear valuation signal either way
      GROWTH_PLAY — expensive by traditional metrics but justified by growth
    """
    fc = forensics.get("checks", {})
    pe  = m.get("pe_ratio")
    rg  = m.get("revenue_growth") or 0
    om  = m.get("operating_margin") or 0

    buffett_score = fc.get("buffett", {}).get("total_pass", 0)
    dilution_flag = fc.get("dilution", {}).get("flag", "CLEAN")
    dilution_pct  = fc.get("dilution", {}).get("dilution_pct") or 0
    stage         = fc.get("stage", {}).get("stage", 2)
    runway_years  = fc.get("cash_runway", {}).get("years")
    cash          = fc.get("cash_runway", {}).get("cash") or 0
    debt          = fc.get("buffett", {}).get("cash_gt_debt", {}).get("debt") or 0
    retained_grow = fc.get("buffett", {}).get("retained_earnings_growing", {}).get("pass", False)
    has_treasury  = fc.get("buffett", {}).get("treasury_stock", {}).get("pass", False)
    preferred     = fc.get("buffett", {}).get("zero_preferred", {}).get("amount", 0)

    # Is it optically "cheap"? (traditional value screen)
    optically_cheap = pe is not None and 0 < pe < 18

    trap_score = 0     # higher = more trap
    value_score = 0    # higher = more genuine value
    reasons = []       # supporting value case
    warnings = []      # value trap red flags

    # ── VALUE TRAP red flags (each adds to trap_score) ──────────────────
    if dilution_flag == "TOXIC":
        trap_score += 40
        warnings.append(f"🚨 TOXIC DILUTION: shares expanded {dilution_pct:.1f}% YoY — cheap price masks shareholder destruction via equity printing")

    if dilution_flag == "WARNING" and dilution_pct > 5:
        trap_score += 15
        warnings.append(f"⚠️ Ongoing dilution {dilution_pct:.1f}% YoY — management issuing equity, eroding per-share value")

    if runway_years is not None and runway_years < 3:
        trap_score += 30
        warnings.append(f"🚨 SURVIVAL RISK: {runway_years:.1f} yr cash runway — forced capital raise will dilute at distressed prices")

    if buffett_score <= 1:
        trap_score += 20
        warnings.append(f"🚨 Buffett Balance Sheet {buffett_score}/5 — structurally broken balance sheet cannot support recovery")

    if buffett_score == 2:
        trap_score += 10
        warnings.append(f"⚠️ Weak balance sheet {buffett_score}/5 — limited financial buffer for downturn")

    if not retained_grow:
        trap_score += 15
        warnings.append("⚠️ Retained earnings declining or negative — losses compounding, not reversing")

    if preferred and preferred > 0:
        trap_score += 10
        warnings.append(f"⚠️ Preferred stock ${preferred/1e6:.0f}M — hybrid financing signals balance sheet stress")

    if rg < -5:
        trap_score += 20
        warnings.append(f"🚨 Revenue contracting {rg:.1f}% — fundamental demand destruction, not cyclical dip")

    if om < -20:
        trap_score += 15
        warnings.append(f"⚠️ Deep operating losses ({om:.1f}%) — no visible path to profitability")

    if stage == 1 and optically_cheap and pe:
        trap_score += 15
        warnings.append(f"⚠️ Low P/E ({pe:.1f}x) on Stage 1 company — earnings multiple meaningless when operating at a loss")

    # ── VALUE STOCK indicators (each adds to value_score) ──────────────
    if buffett_score >= 4:
        value_score += 25
        reasons.append(f"✅ Fortress balance sheet {buffett_score}/5 Buffett checks — financial durability intact")

    if dilution_flag in ("CLEAN", "BUYBACK"):
        value_score += 20
        reasons.append(f"✅ {'Share buybacks reducing float' if dilution_flag == 'BUYBACK' else 'Clean capital structure — no dilution'}")

    if retained_grow:
        value_score += 15
        reasons.append("✅ Retained earnings growing — compounding profitability confirmed")

    if has_treasury:
        value_score += 10
        reasons.append("✅ Treasury stock present — management returning capital to shareholders")

    if stage >= 3:
        value_score += 15
        reasons.append(f"✅ Stage {stage} profitable business — no capital raise risk")

    if om > 15:
        value_score += 10
        reasons.append(f"✅ Strong operating margin {om:.1f}% — pricing power and efficiency intact")

    if cash > debt and debt > 0:
        value_score += 10
        reasons.append(f"✅ Net cash positive — company can self-fund through downturns")

    if rg > 3 and om > 10:
        value_score += 10
        reasons.append(f"✅ Growing and profitable ({rg:.1f}% revenue, {om:.1f}% margin) — recovery catalyst present")

    # ── Final verdict ────────────────────────────────────────────────────
    if phase == "GROWTH" and pe and pe > 40:
        verdict = "GROWTH_PLAY"
        confidence = "HIGH" if buffett_score >= 3 and dilution_flag in ("CLEAN","BUYBACK") else "MEDIUM"
        summary = (f"Not a value play — priced for growth (P/E {pe:.1f}x). "
                   f"Evaluate on Rule of 40 and revenue quality, not traditional value metrics.")
    elif not optically_cheap and pe and pe > 25:
        verdict = "NOT_VALUE"
        confidence = "HIGH"
        summary = f"P/E {pe:.1f}x — not in value territory by traditional screens. Analyze as growth or quality compounder."
    elif trap_score >= 40 and trap_score > value_score:
        verdict = "VALUE_TRAP"
        confidence = "HIGH" if trap_score >= 60 else "MEDIUM"
        summary = (f"Classic value trap pattern: optically cheap{'(P/E {:.1f}x)'.format(pe) if pe else ''} "
                   f"but fundamentals are deteriorating underneath. "
                   f"Trap score {trap_score} vs value score {value_score}.")
    elif trap_score > 20 and trap_score > value_score * 0.8:
        verdict = "VALUE_TRAP"
        confidence = "MEDIUM"
        summary = f"More trap than value — {len(warnings)} red flags outweigh {len(reasons)} positives."
    elif value_score >= 40 and optically_cheap:
        verdict = "VALUE_STOCK"
        confidence = "HIGH" if value_score >= 60 and trap_score < 15 else "MEDIUM"
        summary = (f"Genuine value opportunity: cheap{' (P/E {:.1f}x)'.format(pe) if pe else ''} "
                   f"with intact fundamentals. Value score {value_score} vs trap score {trap_score}.")
    elif value_score >= 30 and trap_score < 20:
        verdict = "VALUE_STOCK"
        confidence = "MEDIUM"
        summary = f"Leans value — strong fundamentals, moderate valuation."
    else:
        verdict = "NEUTRAL"
        confidence = "LOW"
        summary = "Mixed signals — insufficient evidence for clear value or trap classification."

    return {
        "verdict": verdict,
        "confidence": confidence,
        "summary": summary,
        "trap_score": trap_score,
        "value_score": value_score,
        "reasons": reasons,
        "warnings": warnings,
        "optically_cheap": optically_cheap,
        "pe_ratio": pe,
    }


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


def compute_signal_with_forensics(m: dict, phase: str, forensics: dict) -> dict:
    """Enhanced signal: base rules + forensic adjustments."""
    sig = compute_signal(m, phase)
    score = sig["score"]
    drivers = list(sig["drivers"])

    for d in forensics.get("drivers", []):
        drivers.append(d)
        # Extract numeric adjustment from driver string
        try:
            prefix = d.split(":")[0].strip()
            pts = int(prefix)
            score += pts
        except (ValueError, IndexError):
            pass

    score = max(0, min(100, score))
    rec = "BUY" if score >= 70 else "HOLD" if score >= 45 else "SELL"
    return {"score": score, "recommendation": rec, "drivers": drivers}

# ─────────────────────────── AI analysis (Groq, optional) ──────────────────
def groq_analysis(t, m, phase, sig, forensics=None):
    forensics_ctx = ""
    if forensics and forensics.get("checks"):
        fc = forensics["checks"]
        forensics_ctx = (
            f" FORENSIC DATA: "
            f"Business Stage: {fc.get('stage',{}).get('label','Unknown')}. "
            f"Cash Runway: {fc.get('cash_runway',{}).get('years','N/A')} years. "
            f"Dilution Flag: {fc.get('dilution',{}).get('flag','Unknown')} "
            f"(shares changed {fc.get('dilution',{}).get('dilution_pct','N/A')}% YoY). "
            f"Buffett Balance Sheet: {fc.get('buffett',{}).get('total_pass',0)}/5 checks passed "
            f"(Cash>Debt:{fc.get('buffett',{}).get('cash_gt_debt',{}).get('pass','?')}, "
            f"D/E<0.8:{fc.get('buffett',{}).get('debt_to_equity',{}).get('pass','?')}, "
            f"NoPreferred:{fc.get('buffett',{}).get('zero_preferred',{}).get('pass','?')}, "
            f"RetainedGrowth:{fc.get('buffett',{}).get('retained_earnings_growing',{}).get('pass','?')}, "
            f"TreasuryStock:{fc.get('buffett',{}).get('treasury_stock',{}).get('pass','?')})."
        )

    prompt = (
        f"You are a forensic equity research analyst. Company: {t}. "
        f"Financial metrics: {json.dumps(m)}. "
        f"Lifecycle phase: {phase}. Signal: {sig['recommendation']} (score {sig['score']}/100). "
        f"{forensics_ctx}"
        f" QUALITATIVE MOAT ASSESSMENT — evaluate these 4 structural lenses. Rate each strictly as Anti-fragile, Robust, or Fragile. "
        f"Use the ACTUAL business model of {t}, not assumptions from another industry. "

        f"LENS 1 — COST OF FAILURE (Liability): "
        f"For SOFTWARE companies: would a 90% AI accuracy rate cause catastrophic legal/operational damage? "
        f"For PHYSICAL RETAIL, HEALTHCARE, MANUFACTURING companies: would a supply chain failure, product recall, or service disruption be catastrophic and unrecoverable? "
        f"Anti-fragile = errors cause permanent brand damage or legal liability (FDA trials, financial fraud). Fragile = errors are minor and easily fixed (marketing copy). "

        f"LENS 2 — BUSINESS MODEL (Revenue Structure): "
        f"CRITICAL DEFINITIONS: "
        f"'Seat-based' means charging PER HUMAN EMPLOYEE or PER USER LICENSE (like Salesforce, Workday, Microsoft Office). This IS Fragile because AI reduces headcount. "
        f"'Membership subscription' (like Costco $65/year, Netflix) is NOT seat-based — it is ANTI-FRAGILE because it is recurring, inflation-resistant, and usage-agnostic. "
        f"'Usage-based' (like AWS per-compute) = Anti-fragile as AI increases usage. "
        f"'Transaction-based' (retail, restaurants) = Robust to Fragile depending on brand loyalty. "
        f"Correctly identify which category {t} belongs to before rating. "

        f"LENS 3 — PHYSICAL WORLD INTEGRATION (Atoms vs Bits): "
        f"Does the company REQUIRE physical infrastructure that cannot be replaced by software? "
        f"Anti-fragile examples: warehouse retail (Costco), hospitals, manufacturing, logistics hubs, body cameras. "
        f"Fragile examples: pure SaaS, content platforms, digital marketplaces with no physical component. "

        f"LENS 4 — NETWORK / DATA GRAVITY: "
        f"Does the company possess proprietary data or network effects that public LLMs cannot access or replicate? "
        f"Anti-fragile: member purchase histories (Costco 130M+ cardholders), proprietary financial data, clinical trial data. "
        f"Fragile: generic content, easily scraped web data, no switching costs. "

        f" Return ONLY JSON with these exact keys: "
        '{"summary":str(3-4 sentences covering financial health AND moat assessment with company-specific evidence),'
        '"phaseRationale":str(why this lifecycle phase based on operating income trajectory),'
        '"strengths":[3 strings with specific quantitative data points],'
        '"risks":[3 strings with specific data points],'
        '"moatAssessment":{"liability":{"rating":str,"reasoning":str(2 sentences, company-specific)},"businessModel":{"rating":str,"reasoning":str(2 sentences, name the specific revenue model type)},"physicalIntegration":{"rating":str,"reasoning":str(2 sentences, name the physical assets)},"dataGravity":{"rating":str,"reasoning":str(2 sentences, name the specific data advantage)}},'
        '"mgmtNote":str(1 sentence on capital allocation discipline)}'
    )
    r = httpx.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
        json={"model": "llama-3.1-8b-instant",
              "messages": [{"role": "user", "content": prompt}],
              "response_format": {"type": "json_object"}, "temperature": 0.2},
        timeout=30,
    )
    r.raise_for_status()
    return json.loads(r.json()["choices"][0]["message"]["content"])

def fallback_analysis(t, m, phase, sig, forensics=None):
    rg, om = m.get("revenue_growth") or 0, m.get("operating_margin") or 0
    fc = forensics.get("checks", {}) if forensics else {}
    buffett_score = fc.get("buffett", {}).get("total_pass", "N/A")
    dilution = fc.get("dilution", {}).get("flag", "N/A")
    stage = fc.get("stage", {}).get("label", "N/A")
    runway = fc.get("cash_runway", {}).get("years")
    runway_str = f" Cash runway: {runway} years." if runway else ""

    return {
        "summary": f"{m.get('name', t)} shows {rg:.1f}% revenue growth with a "
                   f"{om:.1f}% operating margin ({stage}). "
                   f"Buffett Balance Sheet: {buffett_score}/5. Dilution: {dilution}.{runway_str} "
                   f"Model score: {sig['score']}/100 → {sig['recommendation']}.",
        "phaseRationale": f"{phase}: classified from operating income trajectory, margin structure and FCF yield.",
        "strengths": [d[d.index(':')+2:] for d in sig["drivers"] if d.startswith("+")][:4]
                     or ["Review fundamentals against sector peers"],
        "risks": [d[d.index(':')+2:] for d in sig["drivers"] if d.startswith("-")][:4]
                 or ["Macro and competitive risks apply"],
        "moatAssessment": {"note": "Enable GROQ_API_KEY for AI-powered qualitative moat assessment"},
        "mgmtNote": "Enable GROQ_API_KEY for AI-powered management credibility assessment.",
    }

# ─────────────────────────── Verdict card formatter ─────────────────────────
COMPLIANCE_SHIELD = (
    "CRITICAL MARKET RISK DISCLAIMER: The implied market actions and verdicts "
    "generated above are purely algorithmic data profiles based on historical "
    "corporate filings and financial metrics. This is an automated mathematical "
    "analysis, NOT financial, investment, or advisory software. PhaseLens does "
    "not know your personal financial situation, risk tolerance, or investment "
    "horizon. All investments are inherently subject to extreme market risk, "
    "including the permanent loss of principal. PhaseLens does not explicitly "
    "command you to buy or sell any security. DO YOUR OWN RESEARCH (DYOR). "
    "You assume 100% of the financial risk for any market actions taken based "
    "on this analysis."
)

def format_verdict_card(sig: dict, value_verdict: dict, m: dict) -> dict:
    """Format the structured 4-section PhaseLens Verdict card per spec."""
    vv    = value_verdict.get("verdict", "NEUTRAL")
    rec   = sig.get("recommendation", "HOLD")
    score = sig.get("score", 50)
    reasons  = value_verdict.get("reasons", [])
    warnings = value_verdict.get("warnings", [])
    pe  = m.get("pe_ratio")
    rg  = m.get("revenue_growth") or 0
    om  = m.get("operating_margin") or 0
    fcf = m.get("fcf_yield")

    # Section 1: Classification + Market Action Profile
    classification = {
        "VALUE_STOCK": "VALUE STOCK",
        "VALUE_TRAP":  "VALUE TRAP",
        "GROWTH_PLAY": "NOT APPLICABLE",
        "NOT_VALUE":   "NOT APPLICABLE",
        "NEUTRAL":     "NEUTRAL",
    }.get(vv, "NEUTRAL")

    if vv == "VALUE_TRAP":
        market_action = "AVOID OR EXIT PROFILE"
    elif vv in ("GROWTH_PLAY", "NOT_VALUE"):
        market_action = "NOT APPLICABLE"
    elif rec == "BUY" and score >= 80:
        market_action = "STRONG BUY PROFILE"
    elif rec == "BUY":
        market_action = "ACCUMULATE PROFILE"
    elif rec == "HOLD":
        market_action = "HOLD OR WATCH PROFILE"
    else:
        market_action = "AVOID OR EXIT PROFILE"

    # Section 2: Reasoning
    if classification == "VALUE STOCK":
        top_reasons = "; ".join(r.replace("✅ ","") for r in reasons[:3]) or "strong fundamentals"
        reasoning = (
            f"This company exhibits core hallmarks of genuine value: {top_reasons}. "
            f"The stock appears undervalued relative to its intrinsic financial health — "
            f"{f'P/E {pe:.1f}x, ' if pe else ''}{om:.1f}% operating margin, "
            f"{'and ' + str(fcf) + '% FCF yield' if fcf else 'with positive cash generation'}. "
            f"Balance sheet strength and capital allocation discipline support the investment case."
        )
    elif classification == "VALUE TRAP":
        top_warnings = [w.replace("🚨 ","").replace("⚠️ ","") for w in warnings[:3]]
        reasoning = (
            f"Classic value trap pattern — optically cheap metrics obscure deteriorating "
            f"fundamentals. Key red flags: {'; '.join(top_warnings) or 'balance sheet stress and declining margins'}. "
            f"{'Low P/E of ' + str(round(pe,1)) + 'x is misleading — ' if pe and pe < 18 else ''}"
            f"the cheap price reflects structural business problems, not temporary sentiment."
        )
    elif classification == "NEUTRAL":
        reasoning = (
            f"Current valuation{f' (P/E {pe:.1f}x)' if pe else ''} fairly reflects risk-reward. "
            f"Revenue growth {rg:.1f}% and operating margin {om:.1f}% are neither compelling "
            f"enough for a strong buy nor deteriorating enough to classify as a trap. "
            f"A more favorable margin of safety or clear catalyst is needed."
        )
    else:
        reasoning = (
            f"Traditional value metrics cannot accurately assess this company. "
            f"{'High-growth profile (revenue +' + str(rg) + '%) prices in future execution, not current earnings. ' if rg > 20 else ''}"
            f"{'Pre-profitability means P/E is not meaningful. ' if om < 0 else ''}"
            f"Evaluate on growth metrics: Rule of 40, NRR, TAM penetration, cash runway."
        )

    # Section 3: Implied Market Action
    if classification == "VALUE STOCK":
        action_text = (
            "This profile historically represents an asymmetric risk-reward opportunity "
            "where fundamentals outpace market sentiment. Investors looking for long-term "
            "equity growth typically view this as a potential BUY/ACCUMULATE candidate, "
            "provided it aligns with their risk tolerance."
        )
    elif classification == "VALUE TRAP":
        action_text = (
            "This profile historically represents a capital destruction risk where low "
            "multiples hide deteriorating core business health. Investors looking to "
            "protect capital typically view this as a SELL/AVOID candidate to prevent "
            "catching a falling knife."
        )
    else:
        action_text = (
            "This profile suggests waiting for a structural shift or a more favorable "
            "margin of safety. Market participants typically HOLD or keep this on a "
            "watch list, as current data does not present a high-conviction signal."
        )

    return {
        "section1": {
            "title": "FINAL VERDICT",
            "classification": classification,
            "market_action_profile": market_action,
            "confidence": value_verdict.get("confidence", "MEDIUM"),
            "trap_score": value_verdict.get("trap_score", 0),
            "value_score": value_verdict.get("value_score", 0),
        },
        "section2": {
            "title": "THE REASONING",
            "reasoning": reasoning,
            "supporting": reasons,
            "red_flags": warnings,
        },
        "section3": {
            "title": "IMPLIED MARKET ACTION & RISK ASSESSMENT",
            "text": action_text,
        },
        "section4": {
            "title": "MANDATORY COMPLIANCE SHIELD",
            "text": COMPLIANCE_SHIELD,
        },
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
def api_analyze(ticker: str, visitor_id: str = "", email: str = ""):
    t = ticker.upper().strip()
    hit = _analysis_cache.get(t)
    if hit and hit[0] > time.time():
        return hit[1]
    m = fetch_stock(t)
    ph = classify_phase(m)
    deep = fetch_deep_data(t)
    forensics = compute_forensics(m, deep)
    sig = compute_signal_with_forensics(m, ph["phase"], forensics)
    if GROQ_API_KEY:
        try:
            ai = groq_analysis(t, m, ph["phase"], sig, forensics)
        except Exception:
            ai = fallback_analysis(t, m, ph["phase"], sig, forensics)
    else:
        ai = fallback_analysis(t, m, ph["phase"], sig, forensics)
    value_verdict = compute_value_verdict(m, forensics, ph["phase"])
    verdict_card  = format_verdict_card(sig, value_verdict, m)
    payload = {
        "ticker": t, "name": m.get("name"), "price": m.get("price"),
        "phase": ph["phase"], "phaseSignals": ph["signals"],
        "score": sig["score"], "recommendation": sig["recommendation"],
        "signalDrivers": sig["drivers"], "metrics": m,
        "forensics": forensics.get("checks"),
        "verdictCard": verdict_card,
        "moatAssessment": ai.get("moatAssessment"),
        "summary": ai.get("summary"), "phaseRationale": ai.get("phaseRationale"),
        "strengths": ai.get("strengths"), "risks": ai.get("risks"),
        "mgmtNote": ai.get("mgmtNote"),
        "disclaimer": DISCLAIMER,
        "complianceShield": COMPLIANCE_SHIELD,
        "generated_at": now_iso(),
    }
    _analysis_cache[t] = (time.time() + ANALYSIS_TTL, payload)
    # Auto-log verdict to analyses table for admin dashboard
    try:
        fc    = forensics.get("checks", {})
        bs    = fc.get("buffett_score", {}).get("pass")
        dil_s = fc.get("dilution", {}).get("status")
        run_s = fc.get("runway", {}).get("status")
        stg   = fc.get("stage", {}).get("current_node")
        vrd   = payload.get("verdictCard", {}).get("section1", {}).get("classification")
        with db() as conn:
            c = conn.cursor()
            c.execute(q("INSERT INTO analyses(visitor_id,email,ticker,verdict,recommendation,"
                        "score,phase,buffett_score,dilution_status,runway_status,stage,created_at)"
                        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"),
                      (visitor_id[:64] if visitor_id else "", email[:120] if email else "", t, vrd or "", sig.get("recommendation",""),
                       sig.get("score",0), ph.get("phase",""),
                       bs, dil_s or "", run_s or "", stg or "", now_iso()))
    except Exception:
        pass   # never let DB write break the API response
    return payload

# ─────────────────────────── Terms agreement ────────────────────────────────
class TermsIn(BaseModel):
    visitor_id: str
    email: str | None = None

@app.post("/api/terms/agree")
def api_terms_agree(body: TermsIn):
    """Record that a visitor has agreed to PhaseLens Terms of Use."""
    vid = body.visitor_id[:64]
    now = now_iso()
    with db() as conn:
        c = conn.cursor()
        # Upsert into terms table
        c.execute(q("SELECT visitor_id FROM terms WHERE visitor_id=?"), (vid,))
        if c.fetchone():
            c.execute(q("UPDATE terms SET agreed_at=?, email=? WHERE visitor_id=?"),
                      (now, (body.email or "")[:120], vid))
        else:
            c.execute(q("INSERT INTO terms(visitor_id,email,agreed_at) VALUES(?,?,?)"),
                      (vid, (body.email or "")[:120], now))
        # Log event
        c.execute(q("INSERT INTO events(visitor_id,email,event,ticker,created_at) VALUES(?,?,?,?,?)"),
                  (vid, (body.email or "")[:120], "terms_agreed", "", now))
    return {"ok": True, "terms_agreed_at": now}

@app.get("/api/terms/status/{visitor_id}")
def api_terms_status(visitor_id: str):
    """Check if a visitor has already agreed to terms."""
    vid = visitor_id[:64]
    with db() as conn:
        c = conn.cursor()
        c.execute(q("SELECT agreed_at FROM terms WHERE visitor_id=?"), (vid,))
        row = c.fetchone()
        agreed = bool(row and row[0])
        return {"agreed": agreed, "terms_agreed_at": row[0] if agreed else None}

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
        c.execute("SELECT COUNT(*) FROM analyses"); analyses = c.fetchone()[0]
        c.execute("SELECT COUNT(DISTINCT visitor_id) FROM analyses WHERE visitor_id<>''"); unique_analyzers = c.fetchone()[0]
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
        # Verdict breakdown
        c.execute("""SELECT verdict, COUNT(*) n FROM analyses
                     WHERE verdict<>'' GROUP BY verdict ORDER BY n DESC""")
        verdict_breakdown = [{"verdict": r[0], "count": r[1]} for r in c.fetchall()]

        # Recent analyses with full verdict data
        c.execute("""SELECT visitor_id, email, ticker, verdict, recommendation,
                            score, phase, buffett_score, dilution_status,
                            runway_status, stage, created_at
                     FROM analyses ORDER BY id DESC LIMIT 100""")
        recent_analyses = [{
            "visitor_id": r[0], "email": r[1] or "(anonymous)",
            "ticker": r[2], "verdict": r[3], "recommendation": r[4],
            "score": r[5], "phase": r[6], "buffett_score": r[7],
            "dilution_status": r[8], "runway_status": r[9],
            "stage": r[10], "at": r[11],
        } for r in c.fetchall()]

        # Top tickers by verdict — what % of analyses were traps?
        c.execute("""SELECT ticker,
                            SUM(CASE WHEN verdict='VALUE TRAP' THEN 1 ELSE 0 END) traps,
                            SUM(CASE WHEN verdict='VALUE STOCK' THEN 1 ELSE 0 END) stocks,
                            COUNT(*) total
                     FROM analyses WHERE ticker<>''
                     GROUP BY ticker ORDER BY total DESC LIMIT 10""")
        ticker_verdicts = [{"ticker":r[0],"traps":r[1],"stocks":r[2],"total":r[3]}
                           for r in c.fetchall()]

    return {"visitors": visitors, "accounts": n_accounts,
            "total_events": total_events, "analyses": analyses, "unique_analyzers": unique_analyzers,
            "top_tickers": top_tickers, "daily": daily,
            "verdict_breakdown": verdict_breakdown,
            "recent_analyses": recent_analyses,
            "ticker_verdicts": ticker_verdicts,
            "account_list": accounts, "recent_events": events,
            "admin_email": ADMIN_EMAIL}
