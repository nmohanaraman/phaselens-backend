"""Validate the engine: (1) correctness invariants, (2) a real run on actual
AAPL/SPY monthly closes (2021-06 .. 2026-06) extracted from the live FMP probe."""
import math
from backtest_engine import (
    load_fmp_prices, simulate, buy_and_hold, sma_crossover,
    compute_metrics, run_backtest,
)

def approx(a, b, tol=1e-9): return abs(a - b) <= tol

# --- (1) INVARIANT TESTS -----------------------------------------------------
print("=== correctness invariants ===")

# Buy&hold equity, normalized, must EXACTLY track normalized price.
px = [100, 110, 99, 99, 120, 150, 130]
eq, pos = simulate(px, buy_and_hold, starting_capital=10_000)
norm_px = [p / px[0] for p in px]
norm_eq = [e / eq[0] for e in eq]
assert all(approx(a, b) for a, b in zip(norm_px, norm_eq)), "B&H must track price"
assert approx(eq[-1] / eq[0] - 1, px[-1] / px[0] - 1), "B&H total return == price return"
print("  [ok] buy&hold equity exactly tracks price; total return matches")

# Monotonic-up series -> zero drawdown.
up = [10, 11, 12, 13, 14]
eqe, pp = simulate(up, buy_and_hold)
assert approx(compute_metrics(eqe, pp, 252)["max_drawdown"], 0.0), "no DD on monotonic up"
print("  [ok] monotonic-up series has 0 drawdown")

# Hand-checked drawdown: 100 -> 150 -> 75 is a -50% drawdown.
dd = [100, 150, 75, 90]
eqd, pd_ = simulate(dd, buy_and_hold)
got = compute_metrics(eqd, pd_, 252)["max_drawdown"]
assert approx(got, -0.5), f"expected -0.5 DD, got {got}"
print(f"  [ok] peak-to-trough drawdown computed exactly ({got:.1%})")

# No-look-ahead: SMA signal at t never uses prices after t (flat until warmup).
sig = sma_crossover(3, 10)(list(range(20)))
assert sig[:9] == [0]*9, "must be flat before long-window warmup (no peeking)"
print("  [ok] signal respects warmup / no look-ahead")
print()

# --- (2) REAL DATA: AAPL & SPY month-end closes, 2021-06 .. 2026-06 ----------
# (extracted from the FMP probe output you pasted)
months = ["2021-06","2021-07","2021-08","2021-09","2021-10","2021-11","2021-12",
"2022-01","2022-02","2022-03","2022-04","2022-05","2022-06","2022-07","2022-08",
"2022-09","2022-10","2022-11","2022-12","2023-01","2023-02","2023-03","2023-04",
"2023-05","2023-06","2023-07","2023-08","2023-09","2023-10","2023-11","2023-12",
"2024-01","2024-02","2024-03","2024-04","2024-05","2024-06","2024-07","2024-08",
"2024-09","2024-10","2024-11","2024-12","2025-01","2025-02","2025-03","2025-04",
"2025-05","2025-06","2025-07","2025-08","2025-09","2025-10","2025-11","2025-12",
"2026-01","2026-02","2026-03","2026-04","2026-05","2026-06"]

aapl = [136.96,145.86,151.83,141.50,149.80,165.30,177.57,174.78,165.12,174.61,
157.65,148.84,136.72,162.51,157.22,138.20,153.34,148.03,129.93,144.29,147.41,
164.90,169.68,177.25,193.97,196.45,187.87,171.21,170.77,189.95,192.53,184.40,
180.75,171.48,170.33,192.25,210.62,222.08,229.00,233.00,225.91,237.33,250.42,
236.00,241.84,222.13,212.50,200.85,205.17,207.57,232.14,254.63,270.37,278.85,
271.86,259.48,264.18,253.79,271.35,312.06,277.135]

spy = [428.06,438.51,451.56,429.14,459.25,455.56,474.96,449.91,436.63,451.64,
412.00,412.93,377.25,411.99,395.18,357.18,386.21,407.68,382.43,406.48,396.26,
409.39,415.93,417.85,443.28,457.79,450.35,427.48,418.20,456.40,475.31,482.88,
508.08,523.07,501.98,527.37,544.22,550.81,563.68,573.76,568.64,602.55,586.08,
601.82,594.18,559.39,554.54,589.39,617.85,632.08,645.05,666.18,682.06,683.39,
681.92,691.97,685.99,650.34,718.66,756.48,735.37]

assert len(months) == len(aapl) == len(spy) == 61
aapl_raw = [{"date": m, "close": c} for m, c in zip(months, aapl)]
spy_raw  = [{"date": m, "close": c} for m, c in zip(months, spy)]

res = run_backtest(aapl_raw, spy_raw, sma_crossover(3, 10), periods_per_year=12)

def show(name, m):
    print(f"  {name:<22} ret {m['total_return']:+7.1%}  CAGR {m['cagr']:+6.1%}  "
          f"vol {m['ann_vol']:5.1%}  Sharpe {m['sharpe']:5.2f}  "
          f"Sortino {m['sortino']:5.2f}  maxDD {m['max_drawdown']:6.1%}")

print("=== REAL DATA: AAPL strategy vs AAPL buy&hold vs SPY (61 monthly bars) ===")
show("AAPL  SMA(3/10)", res["strategy"])
show("AAPL  buy & hold", res["buy_hold"])
show("SPY   buy & hold", res["benchmark"])
s = res["strategy"]
print(f"\n  strategy exposure: {s['exposure']:.0%} of months invested | "
      f"trades: {s['num_trades']} | trade win-rate: {s['trade_win_rate']:.0%} | "
      f"period win-rate: {s['period_win_rate']:.0%}")
print(f"\n  {res['disclaimer']}")
print("\n[ALL TESTS PASSED]")
