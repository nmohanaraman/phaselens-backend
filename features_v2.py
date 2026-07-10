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
    """Target vs up to 3 peers on the core ratio set. None = hide panel."""
    import main
    peers = resolve_peers(t)
    if not peers:
        return None
    rows = []
    for p in peers[:3]:
        try:
            pm = main.fetch_stock(p)   # shares the 15-min cache
            rows.append({
                "ticker": p,
                "pe_ratio": pm.get("pe_ratio"),
                "gross_margin": pm.get("gross_margin"),
                "operating_margin": pm.get("operating_margin"),
                "fcf_yield": pm.get("fcf_yield"),
                "debt_to_equity": pm.get("debt_to_equity"),
                "revenue_growth": pm.get("revenue_growth"),
            })
        except Exception:
            continue
    if not rows:
        return None

    def med(key):
        vals = sorted(r[key] for r in rows if isinstance(r.get(key), (int, float)))
        return vals[len(vals)//2] if vals else None

    fields = ["pe_ratio","gross_margin","operating_margin","fcf_yield","debt_to_equity","revenue_growth"]
    medians = {f: med(f) for f in fields}
    LOWER_BETTER = {"pe_ratio", "debt_to_equity"}
    stance = {}
    for f in fields:
        tv, mv = m.get(f), medians.get(f)
        if not isinstance(tv, (int, float)) or not isinstance(mv, (int, float)):
            stance[f] = "na"
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
