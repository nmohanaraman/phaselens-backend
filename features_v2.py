"""
PhaseLens v2 features — Peer Comparison, Entry Context (valuation percentile),
Verification Membrane (dual-source), and Debate Mode.

Design constraints honored (Requirements v2):
  * FREE-TIER ONLY: FMP free endpoints + yfinance best-effort + Groq.
  * NON-BLOCKING: every enrichment is wrapped so a failure can never break
    /api/analyze — panels simply hide in the UI when data is absent.
  * INDIA-READY: all fetchers take exchange="US" (only supported value today);
    an India provider later implements the same signatures.
  * BUDGET-AWARE: results ride the existing 6h analysis cache; peers add at
    most ~4 FMP calls per UNCACHED analysis; entry context adds 1;
    verification adds 0 FMP calls (yfinance side, 2s time-boxed).
"""
from __future__ import annotations

import json
import os
import time
import logging
import concurrent.futures as _fut

from fastapi import APIRouter, HTTPException, Request

log = logging.getLogger("uvicorn.error")
router = APIRouter()

_PEER_CACHE: dict = {}          # industry -> (expiry, [tickers])
_PEER_TTL = 24 * 3600
_DEBATE_CACHE: dict = {}        # ticker -> (expiry, payload)
_DEBATE_TTL = 6 * 3600


# ────────────────────────── Phase 1a: peer resolution ──────────────────────
def resolve_peers(t: str, n: int = 3, exchange: str = "US") -> list[str]:
    """Same-industry US peers by market cap. Tries FMP stock-peers first
    (1 call); falls back to profile→screener. Empty list on any failure."""
    import main
    if main.MOCK:
        return ["PEER1", "PEER2", "PEER3"][:n]
    try:
        raw = main._fmp_get(f"stock-peers?symbol={t}")
        if isinstance(raw, list) and raw:
            peers = [p.get("symbol") for p in raw if p.get("symbol") and p.get("symbol") != t]
            if peers:
                return peers[:n]
    except Exception:
        pass
    try:
        prof = main._fmp_get(f"profile?symbol={t}")
        industry = (prof[0].get("industry") if isinstance(prof, list) and prof else None)
        if not industry:
            return []
        hit = _PEER_CACHE.get(industry)
        if hit and hit[0] > time.time():
            return [p for p in hit[1] if p != t][:n]
        scr = main._fmp_get(
            f"company-screener?industry={industry.replace(' ', '%20')}"
            f"&exchange=NASDAQ,NYSE&limit=10&sortBy=marketCap&order=desc")
        peers = [r.get("symbol") for r in scr if r.get("symbol")] if isinstance(scr, list) else []
        _PEER_CACHE[industry] = (time.time() + _PEER_TTL, peers)
        return [p for p in peers if p != t][:n]
    except Exception as exc:
        log.info("resolve_peers(%s): %s", t, main._scrub_secrets(str(exc)))
        return []


def peer_comparison(t: str, m: dict) -> dict | None:
    """Target vs up to 3 peers. BUDGET-CRITICAL: exactly ONE FMP call per peer
    (ratios-ttm), never the full fetch_stock (~5 calls each) — the original
    version quadrupled the per-analysis FMP cost and could exhaust the free
    daily quota in ~12 analyses. Peer FCF yield / revenue growth are omitted
    by design (each would cost an extra call per peer)."""
    import main
    peers = resolve_peers(t)
    if not peers:
        return None
    rows = []
    for p in peers[:3]:
        try:
            if main.MOCK:
                rows.append({"ticker": p, "pe_ratio": 25.0, "gross_margin": 45.0,
                             "operating_margin": 20.0, "debt_to_equity": 0.8})
                continue
            rr = main._fmp_get(f"ratios-ttm?symbol={p}")
            r0 = rr[0] if isinstance(rr, list) and rr else {}
            def pv(key, pct=False):
                v = r0.get(key)
                if v in (None, 0):
                    return None
                return round(v * 100, 2) if pct else round(v, 2)
            rows.append({
                "ticker": p,
                "pe_ratio": pv("priceToEarningsRatioTTM"),
                "gross_margin": pv("grossProfitMarginTTM", pct=True),
                "operating_margin": pv("operatingProfitMarginTTM", pct=True),
                "debt_to_equity": pv("debtToEquityRatioTTM"),
            })
        except Exception:
            continue
    rows = [r for r in rows if any(v is not None for k, v in r.items() if k != "ticker")]
    if not rows:
        return None

    def med(key):
        vals = sorted(r[key] for r in rows if isinstance(r.get(key), (int, float)))
        return vals[len(vals)//2] if vals else None

    fields = ["pe_ratio", "gross_margin", "operating_margin", "debt_to_equity"]
    medians = {f: med(f) for f in fields}
    LOWER_BETTER = {"pe_ratio", "debt_to_equity"}
    stance = {}
    for f in fields:
        tv, mv = m.get(f), medians.get(f)
        if not isinstance(tv, (int, float)) or not isinstance(mv, (int, float)):
            stance[f] = "na"
        elif f == "debt_to_equity" and (tv < 0 or mv < 0):
            stance[f] = "na"   # negative book equity: D/E comparison is meaningless
        elif tv == mv:
            stance[f] = "inline"
        else:
            better = tv < mv if f in LOWER_BETTER else tv > mv
            stance[f] = "better" if better else "worse"
    return {"peers": rows, "peer_median": medians, "target_vs_median": stance}


# ─────────────── Phase 1b: entry context (valuation percentile) ────────────
def entry_context(t: str, m: dict) -> dict | None:
    """
    Where does today's P/E sit inside the stock's OWN ~5y P/E band?
    Built ENTIRELY from free data: daily closes (free, complete) divided by a
    step function of annual EPS (limit-5 endpoint). Honest approximation —
    annual EPS steps, not point-in-time TTM — and labeled as such in the UI.
    """
    import main
    eps_hist = m.get("eps_history") or []          # newest → oldest
    pe_now   = m.get("pe_ratio")
    if main.MOCK:
        return {"pe_now": pe_now or 30.0, "pe_low": 18.2, "pe_median": 27.5,
                "pe_high": 41.0, "percentile": 62,
                "note": "Approximate band: daily price / stepped annual EPS (5y)."}
    if not isinstance(pe_now, (int, float)) or pe_now <= 0 or len([e for e in eps_hist if e and e > 0]) < 3:
        return None
    try:
        raw = main._fmp_get(f"historical-price-eod/full?symbol={t}")
        if isinstance(raw, dict):
            raw = raw.get("historical") or []
        closes = sorted(((r["date"], r["close"]) for r in raw
                         if r.get("date") and r.get("close")), key=lambda x: x[0])
        if len(closes) < 250:
            return None
        # Step the annual EPS across the window: newest year gets eps_hist[0], etc.
        years = sorted({d[:4] for d, _ in closes}, reverse=True)
        eps_by_year = {}
        for i, y in enumerate(years):
            e = eps_hist[min(i, len(eps_hist) - 1)]
            if e and e > 0:
                eps_by_year[y] = e
        pes = sorted(c / eps_by_year[d[:4]] for d, c in closes
                     if d[:4] in eps_by_year and c > 0)
        if len(pes) < 100:
            return None
        pct = round(sum(1 for p in pes if p < pe_now) / len(pes) * 100)
        q = lambda f: round(pes[min(int(len(pes) * f), len(pes) - 1)], 1)
        return {"pe_now": round(pe_now, 1), "pe_low": q(0.05), "pe_median": q(0.5),
                "pe_high": q(0.95), "percentile": pct,
                "note": "Approximate band: daily price / stepped annual EPS (5y)."}
    except Exception as exc:
        log.info("entry_context(%s): %s", t, main._scrub_secrets(str(exc)))
        return None


# ───────────────── Phase 2: verification membrane (dual-source) ────────────
def verify_price(t: str, fmp_price) -> dict:
    """Best-effort yfinance cross-check, hard 2s box. Never raises."""
    import main
    result = {"primary": "fmp", "secondary": None, "status": "SINGLE_SOURCE", "divergence_pct": None}
    if main.MOCK or not isinstance(fmp_price, (int, float)) or fmp_price <= 0:
        return result

    def _yf():
        import yfinance as yf
        fi = yf.Ticker(t).fast_info
        return float(fi["last_price"] if "last_price" in dir(fi) or hasattr(fi, "__getitem__") else fi.last_price)

    try:
        with _fut.ThreadPoolExecutor(max_workers=1) as ex:
            alt = ex.submit(_yf).result(timeout=2.0)
        if alt and alt > 0:
            div = abs(alt - fmp_price) / fmp_price * 100
            result.update(secondary="yfinance", divergence_pct=round(div, 2),
                          status="VERIFIED" if div <= 1.5 else "CONFLICT",
                          secondary_price=round(alt, 2))
    except Exception:
        pass   # stays SINGLE_SOURCE — amber, honest
    return result


# ─────────────────────────── Phase 3b: Debate Mode ──────────────────────────
_PERSONAS = {
    "BULL": ("You are arguing the investment BULL case for {t}. Present the strongest "
             "evidence for the opportunity. Cite ONLY the numbers provided in CONTEXT — "
             "never introduce outside figures. Acknowledge weaknesses but frame them "
             "constructively. 3 tight bullet points, plain text."),
    "BEAR": ("You are arguing the investment BEAR case for {t}. Present the strongest "
             "evidence for caution. Cite ONLY the numbers provided in CONTEXT — never "
             "introduce outside figures. Acknowledge strengths but contextualize the "
             "risks. 3 tight bullet points, plain text."),
}

@router.get("/api/debate/{ticker}")
def api_debate(ticker: str, request: Request, rounds: int = 2):
    import main, httpx
    t = main.validate_ticker(ticker)
    main._rate_limit(f"debate:{main._client_ip(request)}")
    hit = _DEBATE_CACHE.get(t)
    if hit and hit[0] > time.time():
        return hit[1]
    if not main.GROQ_API_KEY:
        raise HTTPException(503, "Debate Mode requires the AI narrative engine, which is not configured.")
    # Reuse the cached analysis; run one if absent (counts against rate limit naturally).
    cached = main._analysis_cache.get(t)
    analysis = cached[1] if cached and cached[0] > time.time() else main.api_analyze(t, request)
    ctx = json.dumps({
        "score": analysis.get("score"), "recommendation": analysis.get("recommendation"),
        "phase": analysis.get("phase"), "metrics": analysis.get("metrics"),
        "signalDrivers": analysis.get("signalDrivers"),
        "forensics": analysis.get("forensics"),
    }, default=str)[:6000]
    rounds = max(1, min(3, rounds))
    transcript, history = [], ""
    try:
        for rnd in range(1, rounds + 1):
            for side in ("BULL", "BEAR"):
                prompt = (_PERSONAS[side].format(t=t) +
                          f"\nROUND {rnd} of {rounds}." +
                          (f"\nOPPONENT SO FAR:\n{history[-2000:]}" if history else "") +
                          f"\nCONTEXT:\n{ctx}")
                r = httpx.post("https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {main.GROQ_API_KEY}"},
                    json={"model": "llama-3.1-8b-instant",
                          "messages": [{"role": "user", "content": prompt}],
                          "temperature": 0.5, "max_tokens": 350}, timeout=30)
                r.raise_for_status()
                text = r.json()["choices"][0]["message"]["content"].strip()
                transcript.append({"round": rnd, "side": side, "text": text})
                history += f"\n[{side} R{rnd}] {text}"
    except Exception as exc:
        log.warning("debate(%s): %s", t, main._scrub_secrets(str(exc)))
        raise HTTPException(503, "Debate Mode is temporarily unavailable. Please try again shortly.")
    payload = {"ticker": t, "rounds": rounds, "transcript": transcript,
               "adjudicator": {"score": analysis.get("score"),
                               "recommendation": analysis.get("recommendation"),
                               "note": "The deterministic scorecard is the adjudicator — both personas argued the same audited data."},
               "disclaimer": analysis.get("disclaimer")}
    _DEBATE_CACHE[t] = (time.time() + _DEBATE_TTL, payload)
    return payload


# ══════════════════ Epic 1: Forensic Fair Value Estimator ══════════════════
# Zero FMP calls — consumes data already fetched by /api/analyze.
# Backend returns the INPUTS + defaults; the frontend re-computes live as the
# user drags the discount-rate slider (same formulas, mirrored in JS), so
# stress-testing costs nothing.
def fair_value(t: str, m: dict, deep: dict) -> dict | None:
    """Three baselines:
       EPV        — Greenwald Earnings Power Value: normalized EPS / r. Zero growth.
       FCF_YIELD  — zero-growth FCF perpetuity: (FCF/shares) / r.
       DCF        — GROWTH-DEPENDENT (user's explicit choice to include): 5y FCF
                    at capped growth g, terminal growth 2.5%, discounted at r.
       Exclusion logic: a model that would produce a nonsensical value (negative
       or zero inputs) returns null rather than a fake number."""
    try:
        price  = m.get("price")
        shares = deep.get("shares_outstanding") or 0
        fcf    = deep.get("fcf") or 0
        eps_hist = [e for e in (m.get("eps_history") or []) if isinstance(e, (int, float))]
        if not isinstance(price, (int, float)) or price <= 0:
            return None

        R_DEFAULT, TG, G_CAP = 0.09, 0.025, 0.10
        rg = m.get("revenue_growth")
        g = max(0.0, min((rg or 0) / 100.0, G_CAP))   # capped, floor 0 — conservative

        eps_norm = round(sum(eps_hist[:4]) / min(len(eps_hist), 4), 2) if eps_hist else None
        fcf_ps   = round(fcf / shares, 4) if shares and fcf else None

        def _epv(r):        # normalized earnings / r
            return round(eps_norm / r, 2) if eps_norm and eps_norm > 0 else None
        def _perp(r):       # zero-growth FCF perpetuity
            return round(fcf_ps / r, 2) if fcf_ps and fcf_ps > 0 else None
        def _dcf(r):        # 5y growing FCF + Gordon terminal — growth-dependent
            if not fcf_ps or fcf_ps <= 0 or r <= TG:
                return None
            pv, c = 0.0, fcf_ps
            for yr in range(1, 6):
                c *= (1 + g)
                pv += c / ((1 + r) ** yr)
            terminal = (c * (1 + TG)) / (r - TG)
            pv += terminal / ((1 + r) ** 5)
            return round(pv, 2)

        r = R_DEFAULT
        models = {
            "epv":  {"label": "Earnings Power Value", "kind": "DETERMINISTIC",
                     "value": _epv(r),
                     "formula": "Normalized EPS (4y avg) / discount rate",
                     "inputs": {"eps_norm": eps_norm, "r": r}},
            "fcf_perpetuity": {"label": "FCF Perpetuity (zero growth)", "kind": "DETERMINISTIC",
                     "value": _perp(r),
                     "formula": "(TTM FCF / shares) / discount rate",
                     "inputs": {"fcf_per_share": fcf_ps, "r": r}},
            "dcf":  {"label": "Conservative DCF", "kind": "GROWTH-DEPENDENT",
                     "value": _dcf(r),
                     "formula": "5y FCF @ g (capped 10%), terminal g 2.5%, discounted at r",
                     "inputs": {"fcf_per_share": fcf_ps, "g": round(g, 4),
                                "terminal_g": TG, "r": r}},
        }
        if all(mm["value"] is None for mm in models.values()):
            return {"status": "INSUFFICIENT_DATA",
                    "reason": "Negative or missing FCF/EPS — a fair value computed from these inputs would be meaningless."}
        for key, mm in models.items():
            if mm["value"]:
                mm["vs_price_pct"] = round((mm["value"] - price) / price * 100, 1)
        return {"status": "OK", "price": price, "r_default": R_DEFAULT,
                "r_range": [0.06, 0.14], "models": models,
                "note": ("EPV and FCF Perpetuity assume ZERO growth — deterministic by design. "
                         "The DCF depends on a growth assumption (g shown) and is labeled accordingly. "
                         "None of these are price targets or advice.")}
    except Exception:
        return None


# ═══════════ Epic 2: Deterministic Structural Insights (no LLM) ═══════════
# Plain-English strengths/vulnerabilities derived ONLY from rule thresholds.
# Every bullet cites its value+threshold and carries an anchor (which tab /
# metric produced it). Predictive language is impossible by construction —
# these are canned strings keyed to deterministic checks.
def structural_insights(m: dict, forensics: dict) -> dict:
    fc = (forensics or {}).get("checks", {})
    S, V = [], []
    def add(lst, text, anchor):
        lst.append({"text": text, "anchor": anchor})

    de = m.get("debt_to_equity")
    if isinstance(de, (int, float)):
        if de < 0:
            add(V, f"Negative book equity (D/E {de:.2f}x): decades of buybacks or losses have depleted equity — leverage cannot be judged by D/E here; check debt against cash flow instead.", "forensics")
        elif de < 0.5:  add(S, f"Low leverage: D/E of {de:.2f}x means minimal debt burden (threshold: 0–0.5x).", "forensics")
        elif de > 2:  add(V, f"High leverage: D/E of {de:.2f}x exceeds the 2.0x risk threshold.", "forensics")

    gm = m.get("gross_margin")
    if isinstance(gm, (int, float)):
        if gm > 40:   add(S, f"Pricing power: {gm:.0f}% gross margin clears the 40% quality bar.", "metrics")
        elif gm < 20 and gm >= 0: add(V, f"Thin gross margin ({gm:.0f}%): little pricing cushion against cost shocks.", "metrics")

    om = m.get("operating_margin")
    if isinstance(om, (int, float)) and om < 0:
        add(V, f"Operating losses: operating margin is {om:.0f}% — the core business currently loses money.", "metrics")

    fy = m.get("fcf_yield")
    if isinstance(fy, (int, float)):
        if fy > 3:    add(S, f"Cash generative: {fy:.1f}% FCF yield (threshold: >3%).", "metrics")
        elif fy < 0:  add(V, "Negative free cash flow: operations consume more cash than they produce.", "metrics")

    roic = (fc.get("roic") or {})
    if roic.get("status") == "green":
        add(S, f"Efficient capital allocation: ROIC check passed ({roic.get('value','')}).", "forensics")
    elif roic.get("status") == "red":
        add(V, f"Weak returns on capital: ROIC check failed ({roic.get('value','')}).", "forensics")

    eps = (fc.get("eps_predictability") or {})
    if eps.get("status") == "green":
        add(S, "Predictable earnings: EPS has grown consistently across the reported history.", "forensics")
    elif eps.get("status") == "red":
        add(V, "Erratic earnings: EPS history is volatile or declining.", "forensics")

    dil = (fc.get("dilution") or {})
    if dil.get("status") == "green":
        add(S, "Shareholder-friendly: share count is shrinking (buybacks).", "forensics")
    elif dil.get("status") == "red":
        add(V, f"Dilution: share count grew {dil.get('yoy_change','')} YoY.", "forensics")

    run = (fc.get("runway") or {})
    if isinstance(run.get("months"), (int, float)) and run["months"] < 24:
        add(V, f"Limited cash runway: ~{int(run['months'])} months at the current burn rate.", "forensics")

    return {"strengths": S, "vulnerabilities": V,
            "method": "Deterministic rule engine — every bullet cites its threshold; no model-generated language."}


# ════════════════ TODAY'S RADAR — deterministic daily stock surfacing ════════
# NOT "AI picks." Selection is 100% rule-based from FMP market-activity data
# + PhaseLens quality filters. Groq writes a one-line context per stock AFTER
# selection (labeled "AI summary"), never influences inclusion or ranking.
# Cost: ~5-8 FMP calls, 1 Groq call, cached 24h.
_RADAR_CACHE: dict = {}   # {"expiry": float, "payload": dict}
_RADAR_TTL = 24 * 3600

@router.get("/api/radar")
def api_radar(request: Request):
    import main
    main._rate_limit(f"radar:{main._client_ip(request)}")
    hit = _RADAR_CACHE.get("data")
    if hit and hit["expiry"] > time.time():
        return hit["payload"]

    if main.MOCK:
        payload = _mock_radar()
        _RADAR_CACHE["data"] = {"expiry": time.time() + _RADAR_TTL, "payload": payload}
        return payload

    # Step 1: gather candidates from market activity (2 FMP calls)
    candidates = {}
    for endpoint in ("most-actives", "biggest-gainers"):
        try:
            raw = main._fmp_get(endpoint)
            if isinstance(raw, list):
                for item in raw[:20]:
                    sym = item.get("symbol")
                    if sym and sym not in candidates:
                        candidates[sym] = {
                            "ticker": sym,
                            "name": item.get("name") or item.get("companyName") or sym,
                            "price": item.get("price"),
                            "change_pct": item.get("changesPercentage"),
                            "volume": item.get("volume"),
                            "source": endpoint,
                        }
        except Exception:
            continue

    if not candidates:
        return {"status": "UNAVAILABLE", "picks": [],
                "note": "Market activity data is temporarily unavailable."}

    # Step 2: score candidates with lightweight ratios (1 FMP call each, stop at 12)
    scored = []
    checked = 0
    for sym, info in list(candidates.items())[:25]:
        if checked >= 12:
            break
        try:
            rr = main._fmp_get(f"ratios-ttm?symbol={sym}")
            r0 = rr[0] if isinstance(rr, list) and rr else {}
            checked += 1

            pe = r0.get("priceToEarningsRatioTTM")
            gm = r0.get("grossProfitMarginTTM")
            om = r0.get("operatingProfitMarginTTM")
            de = r0.get("debtToEquityRatioTTM")
            fy = r0.get("freeCashFlowYieldTTM") if r0.get("freeCashFlowYieldTTM") else None

            # Quality score: simple deterministic tally
            quality = 0
            reasons = []
            if isinstance(gm, (int, float)) and gm > 0.40:
                quality += 2; reasons.append(f"Gross margin {gm*100:.0f}% (>40%)")
            if isinstance(om, (int, float)) and om > 0.15:
                quality += 2; reasons.append(f"Op margin {om*100:.0f}% (>15%)")
            if isinstance(pe, (int, float)) and 0 < pe < 35:
                quality += 2; reasons.append(f"P/E {pe:.1f}x (<35x)")
            if isinstance(de, (int, float)) and de < 1.5:
                quality += 1; reasons.append(f"D/E {de:.1f}x (<1.5x)")
            if isinstance(fy, (int, float)) and fy > 0.02:
                quality += 1; reasons.append(f"FCF yield {fy*100:.1f}% (>2%)")

            if quality >= 3:
                info.update(quality=quality, reasons=reasons,
                            pe=round(pe, 1) if isinstance(pe, (int, float)) else None,
                            gm=round(gm*100, 1) if isinstance(gm, (int, float)) else None,
                            om=round(om*100, 1) if isinstance(om, (int, float)) else None)
                scored.append(info)
        except Exception:
            continue

    # Step 3: rank by quality score desc, take top 5
    scored.sort(key=lambda x: x.get("quality", 0), reverse=True)
    picks = scored[:5]

    # Step 4: Groq one-liner per pick (optional, non-blocking)
    if picks and main.GROQ_API_KEY:
        try:
            import httpx as _hx
            tickers_ctx = "; ".join(
                f"{p['ticker']} ({p['name']}, P/E {p.get('pe','?')}, GM {p.get('gm','?')}%, "
                f"chg {p.get('change_pct','?')}%)" for p in picks)
            prompt = (
                "For each stock below, write ONE short factual sentence (max 15 words) "
                "explaining why it's interesting today based ONLY on the data shown. "
                "No predictions, no 'buy/sell', no superlatives. Format: TICKER: sentence\n\n"
                + tickers_ctx)
            r = _hx.post("https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {main.GROQ_API_KEY}"},
                json={"model": "llama-3.1-8b-instant",
                      "messages": [{"role": "user", "content": prompt}],
                      "temperature": 0.3, "max_tokens": 250}, timeout=15)
            r.raise_for_status()
            lines = r.json()["choices"][0]["message"]["content"].strip().split("\n")
            for line in lines:
                if ":" in line:
                    tk = line.split(":")[0].strip().upper()
                    ctx = ":".join(line.split(":")[1:]).strip()
                    for p in picks:
                        if p["ticker"] == tk:
                            p["ai_context"] = ctx
        except Exception:
            pass  # picks still work without AI context

    payload = {
        "status": "OK",
        "picks": picks,
        "generated_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "method": ("Deterministic screen: today's most active + biggest gainers filtered by "
                   "gross margin >40%, operating margin >15%, P/E <35x, D/E <1.5x, FCF yield >2%. "
                   "Ranked by quality score. AI context lines are labeled separately."),
        "disclaimer": "Not investment advice. Stocks surfaced by market activity + quality filters, not predictions.",
    }
    _RADAR_CACHE["data"] = {"expiry": time.time() + _RADAR_TTL, "payload": payload}
    return payload


def _mock_radar():
    return {
        "status": "OK",
        "picks": [
            {"ticker": "DEMO1", "name": "DemoCorp Alpha", "price": 142.50, "change_pct": 4.2,
             "quality": 7, "reasons": ["Gross margin 55% (>40%)", "Op margin 22% (>15%)", "P/E 18.5x (<35x)"],
             "ai_context": "Strong margins and reasonable valuation amid sector rotation."},
            {"ticker": "DEMO2", "name": "DemoCorp Beta", "price": 89.30, "change_pct": 3.1,
             "quality": 6, "reasons": ["Gross margin 48% (>40%)", "P/E 21.0x (<35x)", "D/E 0.6x (<1.5x)"],
             "ai_context": "Low leverage and steady margins on above-average volume."},
            {"ticker": "DEMO3", "name": "DemoCorp Gamma", "price": 215.80, "change_pct": 2.8,
             "quality": 5, "reasons": ["Op margin 19% (>15%)", "FCF yield 3.2% (>2%)"],
             "ai_context": "Cash generation improving quarter-over-quarter."},
        ],
        "generated_at": "2026-07-15 14:00 UTC",
        "method": "Deterministic screen (mock data).",
        "disclaimer": "Not investment advice. Stocks surfaced by market activity + quality filters, not predictions.",
    }


# ═══════════ THEMED FUNDAMENTAL SCREENS ("ProPicks" analog) — v2 ═══════════
# LESSONS from v1 (which hung in production): never do whole-market bulk +
# 50 price fetches + 5 LLM calls inside ONE synchronous request.
# v2 design:
#   /api/screens                  → FAST: candidates + filters only (<10s)
#   /api/screens/{id}/performance → LAZY: one theme's chart on demand (~8 calls)
# Bulk endpoint handled as CSV (FMP bulk returns CSV, not JSON) with a
# seed-universe fallback if the plan gates bulk (the key-metrics lesson).
import backtest_engine as engine
import csv as _csv
import io as _io

_SCREENS_CACHE: dict = {}
_SCREENS_TTL = 24 * 3600
_PERF_CACHE: dict = {}    # theme_id -> {"expiry", "payload"}

# Fallback universe if bulk is plan-gated: liquid, well-known US names.
SEED_UNIVERSE = [
    "AAPL","MSFT","GOOGL","AMZN","NVDA","META","TSLA","AVGO","BRK-B","JPM",
    "V","MA","UNH","JNJ","XOM","PG","HD","COST","ABBV","WMT",
    "KO","PEP","MRK","ORCL","CRM","AMD","NFLX","ADBE","TMO","MCD",
    "CSCO","ACN","LIN","ABT","INTU","TXN","QCOM","IBM","GE","CAT",
    "NOW","ISRG","AMAT","BKNG","VZ","T","LOW","NKE","UNP","PFE",
]

# Static sector map for the seed universe (zero API cost). Drives the
# financials exclusion (banks/insurers have structurally incomparable FCF and
# margins — CFA review July 2026) and the concentration warning.
SECTOR = {
 "AAPL":"Technology","MSFT":"Technology","GOOGL":"Technology","AMZN":"Consumer","NVDA":"Technology",
 "META":"Technology","TSLA":"Consumer","AVGO":"Technology","BRK-B":"Financials","JPM":"Financials",
 "V":"Financials-Networks","MA":"Financials-Networks","UNH":"Healthcare","JNJ":"Healthcare","XOM":"Energy",
 "PG":"Consumer Staples","HD":"Consumer","COST":"Consumer Staples","ABBV":"Healthcare","WMT":"Consumer Staples",
 "KO":"Consumer Staples","PEP":"Consumer Staples","MRK":"Healthcare","ORCL":"Technology","CRM":"Technology",
 "AMD":"Technology","NFLX":"Communication","ADBE":"Technology","TMO":"Healthcare","MCD":"Consumer",
 "CSCO":"Technology","ACN":"Technology","LIN":"Materials","ABT":"Healthcare","INTU":"Technology",
 "TXN":"Technology","QCOM":"Technology","IBM":"Technology","GE":"Industrials","CAT":"Industrials",
 "NOW":"Technology","ISRG":"Healthcare","AMAT":"Technology","BKNG":"Consumer","VZ":"Communication",
 "T":"Communication","LOW":"Consumer","NKE":"Consumer","UNP":"Industrials","PFE":"Healthcare",
}
# True financials (banks/insurers): FCF, operating margin, and D/E-style
# leverage metrics do not apply. Payment NETWORKS (V/MA) are asset-light
# processors, not balance-sheet lenders — their FCF is economically real,
# so they stay in. A sector-appropriate "Bank Fortress" lens (ROA, CET1,
# NIM) is a named roadmap item, not built.
FINANCIALS_EXCLUDE = {"JPM", "BRK-B"}


def _v(r, key):
    v = r.get(key)
    try:
        return float(v) if v not in (None, "", "None") else None
    except (TypeError, ValueError):
        return None

def _pct(r, key):
    v = _v(r, key)
    return round(v * 100, 2) if v is not None else None


def _leverage_ok(r, de_max, nde_max):
    """CFA fix (July 2026 review): decades of buybacks push book equity
    negative (MCD D/E ~ -43x), so a bare 'D/E < x' test flags the MOST
    leveraged names as least leveraged. Order of preference:
      1. Net Debt / EBITDA if the vendor provides it (capital-structure
         neutral — the gold-standard leverage metric).
      2. Otherwise D/E, REQUIRING 0 <= D/E < threshold (negative = fail:
         leverage is unmeasurable via equity, not 'low')."""
    nde = _v(r, "netDebtToEBITDATTM")
    if nde is not None:
        return nde < nde_max
    de = _v(r, "debtToEquityRatioTTM")
    return de is not None and 0 <= de < de_max


THEMES = [
    {"id": "fortress", "name": "Buffett Fortresses",
     "desc": "Ultra-low leverage, wide margins, high returns on capital.",
     "filter": lambda r: (
         r.get("symbol") not in FINANCIALS_EXCLUDE and
         _leverage_ok(r, 0.5, 1.5) and
         40 < (_pct(r, "grossProfitMarginTTM") or 0) <= 98 and
         (_pct(r, "_roic") or 0) > 15),
     "criteria": "NetDebt/EBITDA < 1.5x (or 0 \u2264 D/E < 0.5x) AND Gross Margin 40\u201398% AND ROIC > 15% \u00b7 banks/insurers excluded"},
    {"id": "cash_machines", "name": "Cash Machines",
     "desc": "Businesses generating outsized free cash flow relative to their market value.",
     "filter": lambda r: (
         r.get("symbol") not in FINANCIALS_EXCLUDE and
         (_pct(r, "_fcf_yield") or 0) > 5 and
         (_pct(r, "operatingProfitMarginTTM") or 0) > 15),
     "criteria": "FCF Yield > 5% AND Operating Margin > 15% \u00b7 banks/insurers excluded (FCF not meaningful for lenders)"},
    {"id": "growth_quality", "name": "Quality Growth",
     "desc": "Fast growers that aren't sacrificing margins or balance sheet health.",
     "filter": lambda r: (
         r.get("symbol") not in FINANCIALS_EXCLUDE and
         (_v(r, "_rev_cagr3") if _v(r, "_rev_cagr3") is not None else (_v(r, "_rev_growth") or 0)) > 0.15 and
         35 < (_pct(r, "grossProfitMarginTTM") or 0) <= 98 and
         0 < (_v(r, "priceToEarningsRatioTTM") or 0) < 40),
     "criteria": "3-Year Revenue CAGR > 15% AND Gross Margin 35\u201398% AND P/E < 40x \u00b7 multi-year smoothing avoids peak-earnings traps"},
    {"id": "dividend", "name": "Dividend Compounders",
     "desc": "Paying dividends while maintaining financial discipline.",
     "filter": lambda r: (
         r.get("symbol") not in FINANCIALS_EXCLUDE and
         (_pct(r, "dividendYieldTTM") or 0) > 2 and
         _leverage_ok(r, 1.0, 3.0) and
         (_pct(r, "operatingProfitMarginTTM") or 0) > 10),
     "criteria": "Dividend Yield > 2% AND NetDebt/EBITDA < 3.0x (or 0 \u2264 D/E < 1.0x) AND Operating Margin > 10% \u00b7 banks/insurers excluded"},
    {"id": "undervalued", "name": "Undervalued Quality",
     "desc": "Cheap on earnings with solid margins and cash generation.",
     "filter": lambda r: (
         r.get("symbol") not in FINANCIALS_EXCLUDE and
         0 < (_v(r, "priceToEarningsRatioTTM") or 0) < 15 and
         30 < (_pct(r, "grossProfitMarginTTM") or 0) <= 98 and
         (_pct(r, "_fcf_yield") or 0) > 3),
     "criteria": "P/E < 15x AND Gross Margin 30\u201398% AND FCF Yield > 3% \u00b7 banks/insurers excluded"},
]


def _fetch_screen_rows(main) -> list[dict]:
    """Merged screening rows for the seed universe. Per ticker (threaded):
       ratios-ttm      -> P/E, margins, D/E, dividend yield
       key-metrics-ttm -> FCF yield, ROIC          (NOT in ratios-ttm!)
       income (2yr)    -> revenue growth           (in NO ttm snapshot)
    Field names are the ones main.fetch_stock uses in production — verified
    against live FMP responses, not guessed. 3 calls x 50 tickers = 150,
    under the 300/min Starter limit, threaded ~8s, cached 24h.
    (v2 lesson: ratios-ttm alone lacks FCF yield / growth / ROE -> 4 of 5
    themes screened against nonexistent fields and returned zero.)"""
    def one(sym):
        try:
            row = {"symbol": sym}
            rr = main._fmp_get(f"ratios-ttm?symbol={sym}")
            if isinstance(rr, list) and rr:
                row.update(rr[0])
            km = main._fmp_get(f"key-metrics-ttm?symbol={sym}")
            if isinstance(km, list) and km:
                row["_fcf_yield"] = km[0].get("freeCashFlowYieldTTM")
                row["_roic"]      = km[0].get("returnOnInvestedCapitalTTM")
            inc = main._fmp_get(f"income-statement?symbol={sym}&limit=4&period=annual")
            if isinstance(inc, list) and len(inc) >= 2:
                r_new = inc[0].get("revenue") or 0
                r_old = inc[1].get("revenue") or 0
                if r_old:
                    row["_rev_growth"] = (r_new - r_old) / abs(r_old)
                # 3y CAGR (peak-earnings smoothing) when 4 fiscal years exist
                if len(inc) >= 4:
                    r3 = inc[3].get("revenue") or 0
                    if r3 > 0 and r_new > 0:
                        row["_rev_cagr3"] = (r_new / r3) ** (1/3) - 1
            return row
        except Exception:
            return None
    rows = []
    with _fut.ThreadPoolExecutor(max_workers=5) as ex:
        for res in ex.map(one, SEED_UNIVERSE):
            if res and len(res) > 1:
                rows.append(res)
    return rows


@router.get("/api/screens")
def api_screens(request: Request):
    """FAST path: themes + qualifying stocks. Performance is a separate,
    per-theme lazy endpoint."""
    import main
    main._rate_limit(f"screens:{main._client_ip(request)}")
    hit = _SCREENS_CACHE.get("all")
    if hit and hit["expiry"] > time.time():
        return hit["payload"]

    if main.MOCK:
        payload = _mock_screens()
        _SCREENS_CACHE["all"] = {"expiry": time.time() + _SCREENS_TTL, "payload": payload}
        return payload

    rows = _fetch_screen_rows(main)
    if not rows:
        raise HTTPException(503, "Screening data temporarily unavailable.")

    results = []
    for th in THEMES:
        passing = []
        for row in rows:
            sym = row.get("symbol")
            if not sym or not isinstance(sym, str) or "." in sym:
                continue
            try:
                if th["filter"](row):
                    passing.append({
                        "ticker": sym,
                        "pe": round(_v(row, "priceToEarningsRatioTTM") or 0, 1) or None,
                        "gm": _pct(row, "grossProfitMarginTTM"),
                        "om": _pct(row, "operatingProfitMarginTTM"),
                        "de": round(_v(row, "debtToEquityRatioTTM"), 2) if _v(row, "debtToEquityRatioTTM") is not None else None,
                        "fcf_yield": _pct(row, "_fcf_yield"),
                        "div_yield": _pct(row, "dividendYieldTTM"),
                    })
            except Exception:
                continue
        passing.sort(key=lambda x: (-(x.get("gm") or 0), (x.get("pe") or 99)))
        top15 = passing[:15]
        # CFP suitability: warn on sector over-concentration (>35% one sector)
        conc = None
        if len(top15) >= 3:
            counts = {}
            for s in top15:
                sec = SECTOR.get(s["ticker"], "Other")
                counts[sec] = counts.get(sec, 0) + 1
            top_sec, top_n = max(counts.items(), key=lambda kv: kv[1])
            share = round(top_n / len(top15) * 100)
            if share > 35:
                conc = (f"{share}% {top_sec} \u2014 this lens is sector-concentrated. "
                        f"For a diversified portfolio, pair these with holdings from other sectors.")
        results.append({
            "id": th["id"], "name": th["name"], "desc": th["desc"],
            "criteria": th["criteria"], "count": len(top15),
            "stocks": top15, "concentration_warning": conc,
            "performance": None,  # fetched lazily per theme
        })

    payload = {
        "themes": results,
        "generated_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "universe": f"curated universe: {len(rows)} liquid US large-caps (bulk endpoints deferred)",
        "survivorship_warning": (
            "IMPORTANT: Performance charts show hypothetical past returns of stocks that pass "
            "TODAY's screen — not what the screen would have selected historically. Stocks look "
            "good today partly BECAUSE they went up. This is survivorship bias, disclosed plainly. "
            "Forward tracking (from today) is the honest track record and will accrue over time."),
        "disclaimer": "Not investment advice. Deterministic screens with transparent criteria.",
    }
    _SCREENS_CACHE["all"] = {"expiry": time.time() + _SCREENS_TTL, "payload": payload}
    return payload


@router.get("/api/screens/{theme_id}/performance")
def api_screen_performance(theme_id: str, request: Request):
    """LAZY path: one theme's equal-weight constituent history vs SPY.
    ~8 price calls, bounded, cached 24h."""
    import main
    main._rate_limit(f"screenperf:{main._client_ip(request)}")
    hit = _PERF_CACHE.get(theme_id)
    if hit and hit["expiry"] > time.time():
        return hit["payload"]

    if main.MOCK:
        payload = {"theme": theme_id, "constituents": 3,
                   "returns": {"1y": {"portfolio": 42.5, "spy": 18.3},
                               "3y": {"portfolio": 95.2, "spy": 31.1}, "5y": None},
                   "chart": {"dates": ["2024-07","2025-01","2025-07","2026-01","2026-07"],
                             "portfolio": [100,112,128,135,142], "spy": [100,105,110,113,118]}}
        _PERF_CACHE[theme_id] = {"expiry": time.time() + _SCREENS_TTL, "payload": payload}
        return payload

    allscreens = _SCREENS_CACHE.get("all")
    if not allscreens or allscreens["expiry"] <= time.time():
        raise HTTPException(409, "Run /api/screens first — screen data expired.")
    theme = next((t for t in allscreens["payload"]["themes"] if t["id"] == theme_id), None)
    if not theme:
        raise HTTPException(404, "Unknown theme.")
    stocks = theme["stocks"][:8]   # bounded
    if len(stocks) < 3:
        raise HTTPException(503, "Too few constituents for a meaningful chart.")

    perf = _theme_performance_v2(stocks, main)
    if not perf:
        raise HTTPException(503, "Insufficient price history for this theme.")
    payload = {"theme": theme_id, **perf}
    _PERF_CACHE[theme_id] = {"expiry": time.time() + _SCREENS_TTL, "payload": payload}
    return payload


def _theme_performance_v2(stocks: list, main_mod) -> dict | None:
    """Equal-weight hypothetical returns of current constituents vs SPY."""
    try:
        spy_raw = main_mod._fmp_get("historical-price-eod/full?symbol=SPY")
        if isinstance(spy_raw, dict):
            spy_raw = spy_raw.get("historical") or []
        spy_by_date = {r["date"]: r["close"] for r in spy_raw if r.get("date") and r.get("close")}
        if len(spy_by_date) < 250:
            return None
        stock_series = {}
        for s in stocks:
            try:
                raw = main_mod._fmp_get(f"historical-price-eod/full?symbol={s['ticker']}")
                if isinstance(raw, dict):
                    raw = raw.get("historical") or []
                series = {r["date"]: r["close"] for r in raw if r.get("date") and r.get("close")}
                if len(series) > 250:
                    stock_series[s["ticker"]] = series
            except Exception:
                continue
        if len(stock_series) < 3:
            return None
        common = set(spy_by_date)
        for sd in stock_series.values():
            common &= set(sd)
        dates = sorted(common)
        if len(dates) < 250:
            return None
        tickers = list(stock_series)
        port, spy = [10000.0], [10000.0]
        for i in range(1, len(dates)):
            d0, d1 = dates[i-1], dates[i]
            rets = [stock_series[tk][d1]/stock_series[tk][d0]-1
                    for tk in tickers if stock_series[tk].get(d0)]
            port.append(port[-1] * (1 + (sum(rets)/len(rets) if rets else 0)))
            spy.append(spy[-1] * (spy_by_date[d1]/spy_by_date[d0] if spy_by_date.get(d0) else 1))
        def ret(days):
            if len(dates) <= days: return None
            i = len(dates)-days
            return {"portfolio": round((port[-1]/port[i]-1)*100, 1),
                    "spy": round((spy[-1]/spy[i]-1)*100, 1)}
        step = max(1, len(dates)//100)
        return {"constituents": len(tickers),
                "returns": {"1y": ret(252), "3y": ret(756), "5y": ret(1260)},
                "chart": {"dates": [dates[i] for i in range(0, len(dates), step)],
                          "portfolio": [round(port[i]/port[0]*100, 1) for i in range(0, len(dates), step)],
                          "spy": [round(spy[i]/spy[0]*100, 1) for i in range(0, len(dates), step)]}}
    except Exception as exc:
        log.warning("theme_performance: %s", str(exc)[:200])
        return None


def _mock_screens():
    return {
        "themes": [
            {"id": "fortress", "name": "Buffett Fortresses",
             "desc": "Ultra-low leverage, wide margins, high returns on capital.",
             "criteria": "D/E < 0.5x AND Gross Margin > 40% AND ROIC > 15%",
             "count": 3,
             "stocks": [
                 {"ticker": "MSFT", "pe": 32.1, "gm": 69.8, "om": 44.2, "de": 0.35},
                 {"ticker": "AAPL", "pe": 28.5, "gm": 45.9, "om": 30.1, "de": 0.48},
                 {"ticker": "NVDA", "pe": 38.2, "gm": 72.1, "om": 54.3, "de": 0.29}],
             "performance": None},
        ],
        "generated_at": "2026-07-15 14:00 UTC",
        "universe": "mock",
        "survivorship_warning": "IMPORTANT: Hypothetical past performance of TODAY's constituents — survivorship bias disclosed.",
        "disclaimer": "Not investment advice. Deterministic screens with transparent criteria.",
    }


# ═══════════ BATCH QUOTES — light price/day-change for cards & pulse ════════
# ONE FMP call for up to 10 symbols (vs ~5 calls each via fetch_stock).
# Powers: watchlist card prices, dashboard holdings day-change, and the
# Market Pulse portfolio-breadth mode. Cached 10 minutes.
_QUOTES_CACHE: dict = {}   # key -> (expiry, payload)

@router.get("/api/quotes")
def api_quotes(symbols: str, request: Request, debug: bool = False):
    import main
    main._rate_limit(f"quotes:{main._client_ip(request)}")
    syms = sorted({main.validate_ticker(s) for s in symbols.split(",") if s.strip()})[:10]
    if not syms:
        raise HTTPException(400, "No valid symbols.")
    key = ",".join(syms)
    hit = _QUOTES_CACHE.get(key)
    if hit and hit[0] > time.time():
        return hit[1]
    if main.MOCK:
        payload = {"quotes": [{"symbol": s, "price": 100.0 + i, "day_change_pct": (-1) ** i * 1.2}
                              for i, s in enumerate(syms)]}
        _QUOTES_CACHE[key] = (time.time() + 600, payload)
        return payload

    def _chg(r):
        """Day-change %, defensively: FMP's /stable API renamed fields vs v3
        (the ratios-ttm lesson). Try every known name; if only the absolute
        'change' exists, derive the percentage from change/previousClose."""
        for k in ("changesPercentage", "changePercentage", "changes_percentage", "percentChange"):
            v = r.get(k)
            if v is not None:
                try:
                    return float(str(v).replace("%", "").strip())
                except (TypeError, ValueError):
                    continue
        ch, pr = r.get("change"), r.get("price")
        prev = r.get("previousClose")
        try:
            if ch is not None:
                base = prev if prev else (pr - ch if pr is not None else None)
                if base:
                    return round(float(ch) / float(base) * 100, 2)
        except (TypeError, ValueError, ZeroDivisionError):
            pass
        return None

    raw = None
    try:
        if len(syms) == 1:
            raw = main._fmp_get(f"quote?symbol={syms[0]}")
        else:
            # FMP documents batch-quote as its own endpoint; the comma form on
            # /quote may silently return only the first symbol.
            raw = main._fmp_get(f"batch-quote?symbols={key}")
            if not (isinstance(raw, list) and len(raw) >= min(2, len(syms))):
                raw = []
                for s in syms:          # per-symbol fallback, bounded at 10
                    try:
                        rr = main._fmp_get(f"quote?symbol={s}")
                        if isinstance(rr, list) and rr:
                            raw.append(rr[0])
                    except Exception:
                        continue
    except Exception:
        raw = []
    quotes = [{"symbol": r.get("symbol"), "price": r.get("price"),
               "day_change_pct": _chg(r)}
              for r in raw if r.get("symbol")] if isinstance(raw, list) else []
    payload = {"quotes": quotes}
    if debug:
        payload["_raw"] = raw   # unprocessed FMP response — diagnostic only
    _QUOTES_CACHE[key] = (time.time() + 600, payload)
    return payload


# ═══════════ PRIVATE BETA ACCESS CODES (honest gate, not a fake paywall) ═══
# Codes live in env ACCESS_CODES (comma-separated; per-channel codes let you
# see which distribution source converts). Everything shown to the user is
# TRUE: it IS invite-only, founders DO get 12 months free, planned pricing IS
# planned. Client-side entitlement gates the door; API-level enforcement is
# the Supabase milestone (with forward-tracking + passkeys).
_DEFAULT_CODES = "FOUNDER2026"
FOUNDER_MONTHS = 12

@router.get("/api/access/validate")
def api_access_validate(code: str, request: Request):
    import main
    main._rate_limit(f"access:{main._client_ip(request)}")   # brute-force brake
    codes = {c.strip().upper() for c in
             (os.getenv("ACCESS_CODES") or _DEFAULT_CODES).split(",") if c.strip()}
    entered = (code or "").strip().upper()
    if not entered or entered not in codes:
        log.info("access code rejected: %s", entered[:20])
        return {"valid": False}
    expires = time.strftime("%Y-%m-%d", time.gmtime(time.time() + FOUNDER_MONTHS * 30.44 * 86400))
    log.info("access code accepted: %s", entered)
    return {"valid": True, "plan": "founder", "label": "Founding Member",
            "months_free": FOUNDER_MONTHS, "expires": expires, "code": entered}
