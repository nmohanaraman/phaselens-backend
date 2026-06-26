"""
PhaseLens backtest engine — core simulation + metrics.

DESIGN NOTES (read before extending):
- TIER-AGNOSTIC: this module never talks to FMP. It consumes a list of
  (date, close) tuples. Where those come from — free daily EOD, Starter
  quarterly, or SEC point-in-time — is the caller's problem. Swapping data
  source is a one-line change at the fetch layer, never here.
- NO LOOK-AHEAD: the signal at the close of bar t decides whether you are
  invested over bar t -> t+1. You can only act on information available at t.
- The signal function is a HOOK. Today it's a transparent price-based stand-in
  (SMA crossover). The real PhaseLens fundamental verdict (BUY/HOLD/SELL)
  slots into exactly this interface — it just returns 1 (in) or 0 (out) per bar.

What free-tier data supports HONESTLY:
  * Equity curve, benchmark, Sharpe/Sortino/drawdown/win-rate  -> REAL (prices are complete)
  * A statistically valid *fundamental* track record           -> NO (<=5 fundamental bars). Needs Starter.
"""

from __future__ import annotations
import json
import math
from typing import Callable, Iterable

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_fmp_prices(raw: list[dict]) -> list[tuple[str, float]]:
    """Accept FMP /historical-price-eod/full rows (or any [{date, close}, ...])
    and return [(date, close), ...] sorted ASCENDING by date."""
    rows = [(r["date"], float(r["close"])) for r in raw]
    rows.sort(key=lambda x: x[0])
    return rows


def align(a: list[tuple[str, float]],
          b: list[tuple[str, float]]) -> tuple[list[str], list[float], list[float]]:
    """Intersect two series on date. Returns (dates, a_closes, b_closes) aligned."""
    bmap = dict(b)
    dates, av, bv = [], [], []
    for d, av_ in a:
        if d in bmap:
            dates.append(d); av.append(av_); bv.append(bmap[d])
    return dates, av, bv


# ---------------------------------------------------------------------------
# Signal hooks (pluggable). A signal returns a list of positions in {0,1}
# aligned to `prices`. position[t] = exposure carried over bar t -> t+1.
# ---------------------------------------------------------------------------

SignalFn = Callable[[list[float]], list[int]]


def buy_and_hold(prices: list[float]) -> list[int]:
    return [1] * len(prices)


def sma_crossover(short: int = 3, long: int = 10) -> SignalFn:
    """Long when short SMA >= long SMA, else flat. Transparent stand-in for the
    PhaseLens fundamental verdict so we can exercise the engine on real prices."""
    def _fn(prices: list[float]) -> list[int]:
        pos = []
        for t in range(len(prices)):
            if t + 1 < long:
                pos.append(0)            # not enough history -> flat, no look-ahead
                continue
            s = sum(prices[t + 1 - short:t + 1]) / short
            l = sum(prices[t + 1 - long:t + 1]) / long
            pos.append(1 if s >= l else 0)
        return pos
    return _fn


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------

def simulate(prices: list[float], signal_fn: SignalFn,
             starting_capital: float = 10_000.0) -> tuple[list[float], list[int]]:
    """Return (equity_curve, positions). equity_curve[0] == starting_capital.
    Return over bar t->t+1 is earned only if position[t] == 1 (long/flat model)."""
    pos = signal_fn(prices)
    assert len(pos) == len(prices)
    equity = [starting_capital]
    for t in range(len(prices) - 1):
        bar_ret = prices[t + 1] / prices[t] - 1.0
        equity.append(equity[-1] * (1.0 + pos[t] * bar_ret))
    return equity, pos


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def _returns(equity: list[float]) -> list[float]:
    return [equity[i] / equity[i - 1] - 1.0 for i in range(1, len(equity))]


def _max_drawdown(equity: list[float]) -> float:
    peak = equity[0]; mdd = 0.0
    for v in equity:
        peak = max(peak, v)
        mdd = min(mdd, v / peak - 1.0)
    return mdd


def compute_metrics(equity: list[float], positions: list[int],
                    periods_per_year: float) -> dict:
    r = _returns(equity)
    n = len(r)
    total_return = equity[-1] / equity[0] - 1.0
    years = n / periods_per_year if periods_per_year else float("nan")
    cagr = (equity[-1] / equity[0]) ** (1.0 / years) - 1.0 if years > 0 else float("nan")

    mean = sum(r) / n if n else 0.0
    var = sum((x - mean) ** 2 for x in r) / n if n else 0.0
    std = math.sqrt(var)
    sharpe = (mean / std) * math.sqrt(periods_per_year) if std > 0 else float("nan")

    downside = math.sqrt(sum(min(x, 0.0) ** 2 for x in r) / n) if n else 0.0
    sortino = (mean / downside) * math.sqrt(periods_per_year) if downside > 0 else float("nan")

    # period-based win rate: of bars we were actually invested in, % positive
    invested = [(positions[t], r[t]) for t in range(n)]
    held = [ret for p, ret in invested if p == 1]
    period_win = (sum(1 for x in held if x > 0) / len(held)) if held else float("nan")

    # trade-based win rate: group consecutive long bars into trades
    trades, cur = [], None
    for t in range(n):
        if positions[t] == 1:
            cur = (1.0 + r[t]) * (cur if cur is not None else 1.0)
        elif cur is not None:
            trades.append(cur - 1.0); cur = None
    if cur is not None:
        trades.append(cur - 1.0)
    trade_win = (sum(1 for x in trades if x > 0) / len(trades)) if trades else float("nan")

    return {
        "total_return": total_return,
        "cagr": cagr,
        "ann_vol": std * math.sqrt(periods_per_year),
        "sharpe": sharpe,
        "sortino": sortino,
        "max_drawdown": _max_drawdown(equity),
        "period_win_rate": period_win,
        "trade_win_rate": trade_win,
        "num_trades": len(trades),
        "exposure": (sum(positions[:n]) / n) if n else float("nan"),
        "periods": n,
        "years": years,
    }


DISCLAIMER = ("Illustrative — restated data, not point-in-time; signal is a "
              "transparent stand-in for the PhaseLens verdict. Past performance "
              "is not indicative of future results.")


def run_backtest(ticker_raw: list[dict], benchmark_raw: list[dict],
                 signal_fn: SignalFn, periods_per_year: float) -> dict:
    t = load_fmp_prices(ticker_raw)
    b = load_fmp_prices(benchmark_raw)
    dates, tp, bp = align(t, b)
    s_eq, s_pos = simulate(tp, signal_fn)
    bh_eq, bh_pos = simulate(tp, buy_and_hold)
    bm_eq, bm_pos = simulate(bp, buy_and_hold)
    return {
        "dates": dates,
        "strategy": {"equity": s_eq, **compute_metrics(s_eq, s_pos, periods_per_year)},
        "buy_hold": {"equity": bh_eq, **compute_metrics(bh_eq, bh_pos, periods_per_year)},
        "benchmark": {"equity": bm_eq, **compute_metrics(bm_eq, bm_pos, periods_per_year)},
        "disclaimer": DISCLAIMER,
    }
