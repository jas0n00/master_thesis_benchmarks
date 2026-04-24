#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.optimize import curve_fit

# ====== CONFIG ======
CSV_PATH = "log_ns/delay_data.csv"
OUT_PNG  = "figure_delay_impact_comparison.png"
OUT_PDF  = "figure_delay_impact_comparison.pdf"

# TLS modes order to display
MODE_ORDER = ["classic-rsa","classic", "hybrid-kem", "hybrid-full", "pqc"]

# ====== LOAD DATA ======
df = pd.read_csv(CSV_PATH)
df = df[["mode", "delay_ms", "handshakes_sec"]].dropna()
df = df[df["mode"].isin(MODE_ORDER)].copy()
df["mode"] = pd.Categorical(df["mode"], categories=MODE_ORDER, ordered=True)
df = df.sort_values(["mode", "delay_ms"])

# ====== MODEL: inverse-with-offset y = A / (1 + B*x) + C ======
def inv_offset_model(x, A, B, C):
    return A / (1.0 + B * x) + C

def fit_mode(sub):
    """Fit inverse+offset model per mode, return params and R^2."""
    x = sub["delay_ms"].to_numpy(dtype=float)
    y = sub["handshakes_sec"].to_numpy(dtype=float)

    # Sensible initial guesses
    A0 = max(y) - min(y)
    C0 = min(y) * 0.6
    B0 = 0.05  # mild curvature

    # Constrain to keep the fit physically reasonable
    # A>=0, B>=0, C>=0
    bounds = ([0.0, 0.0, 0.0], [np.inf, np.inf, np.inf])

    popt, _ = curve_fit(
        inv_offset_model, x, y,
        p0=[A0, B0, C0],
        bounds=bounds,
        maxfev=20000
    )

    y_hat = inv_offset_model(x, *popt)
    ss_res = np.sum((y - y_hat) ** 2)
    ss_tot = np.sum((y - np.mean(y)) ** 2)
    r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else np.nan
    return popt, r2

# ====== FIT ALL MODES ======
fit_results = {}
for m in MODE_ORDER:
    sub = df[df["mode"] == m]
    popt, r2 = fit_mode(sub)
    fit_results[m] = {"params": popt, "r2": r2}

# ====== PLOTTING ======
sns.set_theme(style="whitegrid", font_scale=1.25)
palette = sns.color_palette("tab10", n_colors=len(MODE_ORDER))

fig, axes = plt.subplots(2, 1, figsize=(12, 10), sharex=True)

# ---- TOP: LOWESS (if available), else simple line ----
ax = axes[0]
ax.set_title("TLS 1.3 Handshake Throughput vs Network Delay (LOWESS / empirical)", pad=12)
for m, color in zip(MODE_ORDER, palette):
    sub = df[df["mode"] == m]
    x = sub["delay_ms"].to_numpy()
    y = sub["handshakes_sec"].to_numpy()
    ax.scatter(x, y, s=50, color=color, alpha=0.85, label=f"{m} data")

# Try LOWESS if statsmodels exists
used_lowess = False
try:
    from statsmodels.nonparametric.smoothers_lowess import lowess
    used_lowess = True
    for m, color in zip(MODE_ORDER, palette):
        sub = df[df["mode"] == m]
        xy = lowess(sub["handshakes_sec"], sub["delay_ms"], frac=0.6, it=0, return_sorted=True)
        ax.plot(xy[:, 0], xy[:, 1], color=color, lw=2.5, label=f"{m} LOWESS")
except Exception:
    # Fallback: just a connected line (sorted)
    for m, color in zip(MODE_ORDER, palette):
        sub = df[df["mode"] == m].sort_values("delay_ms")
        ax.plot(sub["delay_ms"], sub["handshakes_sec"], color=color, lw=2.0, label=f"{m} line")

ax.set_ylabel("Handshake throughput [H/sec]")
ax.legend(title="TLS 1.3 mode", ncol=2)

# ---- BOTTOM: Inverse+offset fit (analytic) ----
ax2 = axes[1]
ax2.set_title("TLS 1.3 Handshake Throughput vs Network Delay (Analytic inverse + offset fit)", pad=12)

for m, color in zip(MODE_ORDER, palette):
    sub = df[df["mode"] == m]
    x = sub["delay_ms"].to_numpy()
    y = sub["handshakes_sec"].to_numpy()

    # data points
    ax2.scatter(x, y, s=50, color=color, alpha=0.85, label=f"{m} data")

    # fitted curve
    A, B, C = fit_results[m]["params"]
    x_fit = np.linspace(x.min(), x.max(), 400)
    y_fit = inv_offset_model(x_fit, A, B, C)
    ax2.plot(x_fit, y_fit, color=color, lw=2.5, label=f"{m} fit (R²={fit_results[m]['r2']:.3f})")

ax2.set_xlabel("Simulated network delay [ms]")
ax2.set_ylabel("Handshake throughput [H/sec]")
ax2.legend(title="TLS 1.3 mode", ncol=2)

plt.tight_layout()
plt.savefig(OUT_PNG, dpi=300, bbox_inches="tight")
plt.savefig(OUT_PDF, bbox_inches="tight")
plt.show()

# ====== PRINT FIT SUMMARY ======
print("\n=== Inverse+Offset Fit Parameters  y = A / (1 + B·x) + C ===")
for m in MODE_ORDER:
    A, B, C = fit_results[m]["params"]
    r2 = fit_results[m]["r2"]
    print(f"{m:12s}:  A = {A:8.2f},  B = {B:8.5f},  C = {C:8.2f},  R² = {r2:.4f}")

if not used_lowess:
    print("\nℹ️ LOWESS smoothing not available (statsmodels missing). Install with:")
    print("   pip install statsmodels  # or: sudo apt install python3-statsmodels")
print(f"\nSaved: {OUT_PNG} and {OUT_PDF}")

