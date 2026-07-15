"""
PhaseLens backtest API — bridges the LIVE verdict engine to the simulation core.

WHAT THIS DOES
  1. Pulls *periodic* fundamentals (income / balance / cash-flow / key-metrics)
     once per backtest — 4-5 FMP calls total, NOT per bar.
  2. Reconstructs, for each reporting period, the SAME metrics dict (`m`) and
     deep dict your live /api/analyze builds — but as-of that period.
  3. Calls your REAL, UNMODIFIED verdict functions imported from main.py:
        classify_phase -> compute_forensics -> compute_signal_with_forensics
     so the backtest verdict can NEVER drift from what the live app shows.
  4. Turns the BUY/HOLD/SELL stream into a position series, time-stamped at each
     filing's acceptedDate (point-in-time: you act when the 10-K/10-Q is public,
     not on the fiscal period-end — this is what kills look-ahead bias).
  5. Runs backtest_engine.simulate + compute_metrics and returns chartable JSON.

TIER BEHAVIOR (the one honest limit)
  FREE  : period=annual, limit=5  -> ~4 fundamental decision points = ANECDOTE.
          The endpoint still returns a real equity curve, but stamps a warning.
  STARTER ($22): set BACKTEST_PERIOD=quarter, BACKTEST_LIMIT=40 in Render env
          -> 40 decision points = a defensible track record. ONE env change,
          zero code change. That's the entire free->paid migration.

WHY NOT ROUTE THROUGH /api/analyze
  /analyze does ~5 FMP + 1 Groq LLM call per request and fetches CURRENT
  fundamentals. Looping it over history would detonate the FMP budget, burn
  Groq, and leak future data. Importing the pure verdict functions instead is
  cheap, deterministic, and point-in-time correct.
"""
from __future__ import annotations

import os
import math
import logging
from fastapi import APIRouter, HTTPException, Request

import backtest_engine as engine

router = APIRouter()

# ── Tier resolution: SELF-DETECTING with optional env override ──────────────
# Old design required BACKTEST_PERIOD/BACKTEST_LIMIT env vars — a human step
# that silently failed on any typo (and did, in production, July 2026).
# New design: on first use, probe one quarterly statement request. If the plan
# grants it (Starter+), run quarter/40; if FMP refuses (free tier), annual/5.
# Env vars still work as explicit overrides; values are normalized; anything
# unrecognized falls through to auto-detection instead of breaking.
_TIER_CACHE: dict = {}   # {"period": str, "limit": int} once resolved

def _tier() -> tuple[str, int]:
    import main
    if _TIER_CACHE:
        return _TIER_CACHE["period"], _TIER_CACHE["limit"]
    env_p = (os.getenv("BACKTEST_PERIOD") or "").strip().lower()
    env_l = (os.getenv("BACKTEST_LIMIT") or "").strip()
    if env_p in ("quarter", "annual"):
        limit = int(env_l) if env_l.isdigit() else (40 if env_p == "quarter" else 5)
        _TIER_CACHE.update(period=env_p, limit=limit, source="env")
    elif main.MOCK:
        _TIER_CACHE.update(period="annual", limit=5, source="mock")
    else:
        # Probe: does the plan grant quarterly history beyond the free cap?
        try:
            probe = main._fmp_get("income-statement?symbol=AAPL&limit=40&period=quarter")
            granted = isinstance(probe, list) and len(probe) > 5
        except Exception:
            granted = False
        if granted:
            _TIER_CACHE.update(period="quarter", limit=40, source="auto-detected")
        else:
            _TIER_CACHE.update(period="annual", limit=5, source="auto-detected")
        logging.getLogger("uvicorn.error").info(
            "Backtest tier auto-detected: %s/%s", _TIER_CACHE["period"], _TIER_CACHE["limit"])
    return _TIER_CACHE["period"], _TIER_CACHE["limit"]

MIN_DECISION_POINTS = 10                                  # below this = anecdotal


# ── FMP periodic fetch (uses main's _fmp_get so it shares your key/base URL) ─
def _periodic(endpoint: str, ticker: str) -> list[dict]:
    """One periodic statement, newest->oldest. Function-level import of main
    avoids a circular import (main.py includes this router at the bottom).
    Returns [] on any error (402 = tier-gated, network, etc) — callers build
    the best series they can from whatever endpoints succeed."""
    import main
    if main.MOCK:
        return []
    p, l = _tier()
    try:
        raw = main._fmp_get(f"{endpoint}?symbol={ticker}&limit={l}&period={p}")
        return raw if isinstance(raw, list) else []
    except Exception:
        # 402 (tier-gated endpoint like key-metrics quarterly on Starter),
        # network errors, or any other failure — degrade, don't crash.
        return []


def _historical_prices(ticker: str) -> list[dict]:
    """Daily EOD closes — the FREE, uncapped endpoint (~5yr, complete)."""
    import main
    if main.MOCK:
        return []
    raw = main._fmp_get(f"historical-price-eod/full?symbol={ticker}")
    # FMP returns either a bare list or {"historical": [...]}; normalize.
    if isinstance(raw, dict):
        raw = raw.get("historical") or []
    return [{"date": r["date"], "close": r["close"]} for r in raw
            if r.get("date") and r.get("close") is not None]


# ── as-of reconstruction ────────────────────────────────────────────────────
def _key(row: dict) -> str:
    """Align statements across endpoints by fiscal period."""
    return f"{row.get('calendarYear','')}-{row.get('period','')}"


def _price_asof(prices_desc: list[tuple[str, float]], as_of: str) -> float | None:
    """Most recent close on or before as_of (prices_desc sorted DESC by date)."""
    for d, c in prices_desc:
        if d <= as_of:
            return c
    return None


def _build_asof_series(ticker: str, prices: list[dict]) -> list[dict]:
    """
    Returns a list (oldest->newest) of:
        {as_of, m, deep, period_label}
    where `m` and `deep` match the shapes fetch_stock()/fetch_deep_data() build,
    so the imported verdict functions accept them unchanged.

    WIRE NOTE: FMP field names below are the same ones main.py already relies on
    (grossProfit, operatingIncome, totalDebt, freeCashFlow, eps, roic, ...). If a
    statement endpoint on your plan returns a variant name, map it here — this is
    the single place field mapping lives.
    """
    inc = _periodic("income-statement", ticker)
    bal = _periodic("balance-sheet-statement", ticker)
    cf  = _periodic("cash-flow-statement", ticker)
    km  = _periodic("key-metrics", ticker)
    if not inc or not bal:
        return []

    bal_by = {_key(r): r for r in bal}
    cf_by  = {_key(r): r for r in cf}
    km_by  = {_key(r): r for r in km}
    prices_desc = sorted(((p["date"], float(p["close"])) for p in prices),
                         key=lambda x: x[0], reverse=True)

    series = []
    # inc is newest->oldest; iterate so index+1 is the PRIOR period for trends.
    for i, ic in enumerate(inc):
        k = _key(ic)
        b  = bal_by.get(k, {})
        c  = cf_by.get(k, {})
        kmr = km_by.get(k, {})
        ic_prior = inc[i + 1] if i + 1 < len(inc) else {}
        b_prior  = bal_by.get(_key(ic_prior), {}) if ic_prior else {}
        c_prior  = cf_by.get(_key(ic_prior), {}) if ic_prior else {}

        # Point-in-time date: when this filing became public. Fall back gracefully.
        as_of = ic.get("acceptedDate") or ic.get("fillingDate") or ic.get("date")
        if not as_of:
            continue
        as_of = as_of[:10]  # YYYY-MM-DD
        px = _price_asof(prices_desc, as_of)
        if px is None:
            continue

        revenue   = ic.get("revenue") or 0
        rev_prior = ic_prior.get("revenue") or 0
        gross     = ic.get("grossProfit")
        op_income = ic.get("operatingIncome")
        eps       = ic.get("eps") if ic.get("eps") is not None else ic.get("epsdiluted")

        shares = (b.get("commonStockSharesOutstanding")
                  or b.get("sharesOutstanding") or 0)
        equity = b.get("totalStockholdersEquity") or 0
        debt   = b.get("totalDebt") or b.get("longTermDebt") or 0
        fcf    = c.get("freeCashFlow") or 0
        mcap   = (px * shares) if shares else 0

        def pct(n, d):
            return round(n / d * 100, 2) if (n is not None and d) else None

        # eps_history newest->oldest, as available up to & including this period
        eps_hist = []
        for j in range(i, len(inc)):
            e = inc[j].get("eps") if inc[j].get("eps") is not None else inc[j].get("epsdiluted")
            if e is not None:
                eps_hist.append(e)

        m = {
            "ticker": ticker,
            "price": px,
            "market_cap": mcap,
            "revenue_growth":   pct(revenue - rev_prior, abs(rev_prior)) if rev_prior else None,
            "gross_margin":     pct(gross, revenue),
            "operating_margin": pct(op_income, revenue),
            "pe_ratio":         round(px / eps, 2) if eps and eps > 0 else None,
            "fcf_yield":        pct(fcf, mcap) if mcap else None,
            "debt_to_equity":   round(debt / equity, 2) if equity else None,
            "dividend_yield":   None,  # not needed by signal; left None (matches mature-div branch off)
            "roic":             round((kmr.get("roic") or 0) * 100, 2) if kmr.get("roic") else None,
            "eps_history":      eps_hist,
        }

        deep = {
            "cash": (b.get("cashAndCashEquivalents") or 0) + (b.get("shortTermInvestments") or 0),
            "total_debt": debt,
            "total_equity": equity,
            "retained_earnings": b.get("retainedEarnings") or 0,
            "retained_earnings_prior": b_prior.get("retainedEarnings") or 0,
            "preferred_stock": b.get("preferredStock") or 0,
            "treasury_stock": b.get("totalTreasuryStock") or b.get("treasuryStock") or 0,
            "shares_outstanding": shares,
            "shares_outstanding_prior": (b_prior.get("commonStockSharesOutstanding")
                                         or b_prior.get("sharesOutstanding") or 0),
            "net_share_issuance": (c.get("commonStockIssued") or 0) - abs(c.get("commonStockRepurchased") or 0),
            "net_share_issuance_prior": (c_prior.get("commonStockIssued") or 0) - abs(c_prior.get("commonStockRepurchased") or 0),
            "fcf": fcf,
            "fcf_prior": c_prior.get("freeCashFlow") or 0,
            "operating_income": c.get("operatingIncome") or op_income or 0,
        }
        series.append({"as_of": as_of, "m": m, "deep": deep, "period_label": k})

    series.sort(key=lambda x: x["as_of"])  # oldest -> newest
    return series


def _verdict_for(m: dict, deep: dict) -> dict:
    """Call the REAL, imported verdict pipeline — identical to /api/analyze."""
    import main
    ph = main.classify_phase(m)
    forensics = main.compute_forensics(m, deep)
    sig = main.compute_signal_with_forensics(m, ph["phase"], forensics)
    return {"phase": ph["phase"], "recommendation": sig["recommendation"], "score": sig["score"]}


# ── position construction (no look-ahead) ────────────────────────────────────
def _positions_from_signals(dates: list[str], changes: list[dict], in_on: set[str]) -> list[int]:
    """
    Step function: on each price date d, position = the verdict from the most
    recent filing whose as_of <= d. Flat (0) before the first filing.
    `changes` = [{as_of, recommendation}, ...] oldest->newest.
    """
    pos, ci, cur = [], 0, 0
    for d in dates:
        while ci < len(changes) and changes[ci]["as_of"] <= d:
            cur = 1 if changes[ci]["recommendation"] in in_on else 0
            ci += 1
        pos.append(cur)
    return pos


@router.get("/api/backtest/{ticker}")
def api_backtest(ticker: str, request: Request, benchmark: str = "SPY", in_on: str = "BUY"):
    """
    Backtest the live PhaseLens verdict.
      in_on=BUY        -> hold only while the signal is BUY  (default)
      in_on=BUY,HOLD   -> hold while BUY or HOLD (exit only on SELL)
    """
    try:
        return _run_backtest(ticker, request, benchmark, in_on)
    except HTTPException:
        raise
    except Exception as exc:
        logging.getLogger("uvicorn.error").exception("backtest(%s) unhandled:", ticker)
        raise HTTPException(500, f"Backtest failed unexpectedly. The error has been logged.")


def _run_backtest(ticker: str, request: Request, benchmark: str, in_on: str):
    t = ticker.upper().strip()
    bm = benchmark.upper().strip()
    # Backtests are the most expensive route (multiple FMP calls) — reuse the
    # same per-IP limiter as /api/analyze.
    import main
    main._rate_limit(f"bt:{main._client_ip(request)}")
    in_set = {s.strip().upper() for s in in_on.split(",") if s.strip()}
    if not in_set:
        in_set = {"BUY"}

    px_t = _historical_prices(t)
    px_b = _historical_prices(bm)
    if not px_t or not px_b:
        raise HTTPException(503, f"No price history for {t} or {bm}.")

    series = _build_asof_series(t, px_t)
    if not series:
        raise HTTPException(503, f"No periodic fundamentals for {t} on this plan.")

    changes = [{"as_of": s["as_of"], "recommendation": _verdict_for(s["m"], s["deep"])["recommendation"]}
               for s in series]

    # Align ticker & benchmark on common dates (engine helper), then build positions.
    t_rows = engine.load_fmp_prices(px_t)
    b_rows = engine.load_fmp_prices(px_b)
    dates, tp, bp = engine.align(t_rows, b_rows)
    if len(dates) < 2:
        raise HTTPException(503, "Insufficient overlapping price history.")

    positions = _positions_from_signals(dates, changes, in_set)

    # Auto-fallback: if the requested mode never puts us in the market (e.g.
    # BUY-only on a name the model only ever rated HOLD), rerun as BUY+HOLD and
    # SAY SO — a silently flat line looks broken; a silently switched mode lies.
    auto_switched = False
    if in_set == {"BUY"} and not any(positions):
        in_set = {"BUY", "HOLD"}
        positions = _positions_from_signals(dates, changes, in_set)
        auto_switched = True

    s_eq, s_pos = engine.simulate(tp, lambda _p: positions)
    bh_eq, bh_pos = engine.simulate(tp, engine.buy_and_hold)
    bm_eq, bm_pos = engine.simulate(bp, engine.buy_and_hold)

    # daily price series -> annualize with 252; metrics module is period-agnostic.
    ppy = 252.0
    result = {
        "ticker": t,
        "benchmark": bm,
        "dates": dates,
        "strategy": {"equity": s_eq, **engine.compute_metrics(s_eq, s_pos, ppy)},
        "buy_hold": {"equity": bh_eq, **engine.compute_metrics(bh_eq, bh_pos, ppy)},
        "benchmark_curve": {"equity": bm_eq, **engine.compute_metrics(bm_eq, bm_pos, ppy)},
        "signal_log": changes,                 # the as-of BUY/HOLD/SELL stream
        "decision_points": len(changes),
        "tier": {"period": _tier()[0], "limit": _tier()[1], "source": _TIER_CACHE.get("source")},
        "disclaimer": engine.DISCLAIMER,
    }
    if len(changes) < MIN_DECISION_POINTS:
        p, _ = _tier()
        freq = "quarterly" if p == "quarter" else "annual"
        result["warning"] = (
            f"This backtest is based on only {len(changes)} {freq} filing dates — "
            f"too few for statistical confidence. Treat it as an illustration of the "
            f"methodology, not as evidence of performance."
        )
    # The signal may never fire (e.g. BUY-only on a name the model only ever rated
    # HOLD). That makes vol/Sharpe/win-rate mathematically undefined -> NaN. NaN is
    # NOT valid JSON and breaks JSON.parse in the browser, so scrub non-finite
    # floats to null. The frontend already renders null metrics as an en-dash.
    if auto_switched:
        result["note"] = (
            "The signal never rated this stock BUY over the available history, so a "
            "BUY-only strategy would have stayed 100% in cash. Auto-switched to "
            "'BUY or HOLD' so you can see how the signal actually behaved."
        )
    elif result["strategy"].get("exposure") in (0, 0.0):
        result["note"] = (
            f"The PhaseLens signal was never {in_on} over the available history, so the "
            f"strategy stayed in cash (flat line). Try the 'BUY or HOLD' mode, or upgrade "
            f"to quarterly data for more decision points."
        )
    return _clean(result)


def _clean(obj):
    """Recursively replace NaN/Inf with None so the payload is valid JSON."""
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    return obj
