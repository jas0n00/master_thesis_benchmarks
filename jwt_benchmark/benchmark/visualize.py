"""
Generate publication-ready charts from benchmark results.
Mirrors the figure style from the reference paper (Fig. 3 & Fig. 4):
  (a) Token generation time (log scale)
  (b) Token verification time
  (c) Request header & response body size
  (d) Response time
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Style
plt.rcParams.update({
    'font.size': 11,
    'font.family': 'serif',
    'figure.dpi': 150,
    'savefig.bbox': 'tight',
    'axes.grid': True,
    'grid.alpha': 0.3,
})

# Color palette
# Replace your COLORS + ALGO_ORDER with this version

# Color palette
COLORS = {
    # Classical algorithms → gray shades
    "ECDSA-P256":        "#7f7f7f",
    "RSA-2048":          "#3f3f3f",

    # ML-DSA family → blue shades
    "ML-DSA-44":         "#1f77b4",
    "ML-DSA-65":         "#4fa3d9",
    "ML-DSA-87":         "#0d3b66",

    # Falcon family → red shades
    "Falcon-512":        "#d62728",
    "Falcon-1024":       "#ff6b6b",

    # Hybrid ML-DSA pair → purple shades (same family, different tones)
    "P256+ML-DSA-44":    "#9467bd",   # medium purple
    "P256>>ML-DSA-44":   "#c5a3e0",   # lighter purple

    # Hybrid Falcon pair → brown/red shades (same family, different tones)
    "P256+Falcon-512":   "#8c564b",   # medium brown-red
    "P256>>Falcon-512":  "#c49c94",   # lighter brown-red
}


# Preferred algorithm order:
# only hybrid pairs are grouped next to each other
ALGO_ORDER = [
    "ECDSA-P256",
    "RSA-2048",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",

    "Falcon-512",
    "Falcon-1024",

    "P256+ML-DSA-44",
    "P256>>ML-DSA-44",

    "P256+Falcon-512",
    "P256>>Falcon-512",
]


def load_summary():
    df = pd.read_csv("results/summary.csv", index_col="algorithm")
    ordered = [a for a in ALGO_ORDER if a in df.index]
    remaining = [a for a in df.index if a not in ordered]
    return df.loc[ordered + remaining]


def _algo_colors(algos):
    return [COLORS.get(a, "#333333") for a in algos]


def plot_token_gen_time(summary):
    """Fig (a): Average token generation time (log scale)."""
    fig, ax = plt.subplots(figsize=(10, 5))
    algos = summary.index.tolist()
    vals = summary["token_gen_mean"].values
    colors = _algo_colors(algos)

    bars = ax.barh(algos, vals, color=colors, edgecolor='black', linewidth=0.5)
    ax.set_xscale('log')
    ax.set_xlabel('Time (ms) — log scale')
    ax.set_title('Average Token Generation Time')
    ax.invert_yaxis()

    for bar, val in zip(bars, vals):
        ax.text(val * 1.1, bar.get_y() + bar.get_height() / 2,
                f'{val:.2f} ms', va='center', fontsize=9)

    os.makedirs("charts", exist_ok=True)
    plt.savefig("charts/token_gen_time.png")
    print("✓ charts/token_gen_time.png")
    plt.close()


def plot_token_ver_time(summary):
    """Fig (b): Average token verification time."""
    fig, ax = plt.subplots(figsize=(10, 5))
    algos = summary.index.tolist()
    vals = summary["token_ver_mean"].values
    colors = _algo_colors(algos)

    bars = ax.barh(algos, vals, color=colors, edgecolor='black', linewidth=0.5)
    ax.set_xlabel('Time (ms)')
    ax.set_title('Average Token Verification Time')
    ax.invert_yaxis()

    for bar, val in zip(bars, vals):
        ax.text(val + 0.01, bar.get_y() + bar.get_height() / 2,
                f'{val:.2f} ms', va='center', fontsize=9)

    plt.savefig("charts/token_ver_time.png")
    print("✓ charts/token_ver_time.png")
    plt.close()


def plot_sizes(summary):
    """Fig (c): Average request header size & response body size."""
    fig, ax = plt.subplots(figsize=(10, 5))
    algos = summary.index.tolist()
    y_pos = np.arange(len(algos))
    bar_height = 0.35

    req_h = summary["req_header_mean"].values
    resp_b = summary["resp_body_mean"].values

    ax.barh(y_pos - bar_height / 2, req_h, bar_height,
            label='Request Header', color='#4c72b0', edgecolor='black', linewidth=0.5)
    ax.barh(y_pos + bar_height / 2, resp_b, bar_height,
            label='Response Body', color='#dd8452', edgecolor='black', linewidth=0.5)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(algos)
    ax.set_xlabel('Size (bytes)')
    ax.set_title('Average Request Header & Response Body Size')
    ax.legend()
    ax.invert_yaxis()

    plt.savefig("charts/sizes.png")
    print("✓ charts/sizes.png")
    plt.close()


def plot_response_time(summary):
    """Fig (d): Average response time."""
    fig, ax = plt.subplots(figsize=(10, 5))
    algos = summary.index.tolist()
    vals = summary["resp_time_mean"].values
    colors = _algo_colors(algos)

    bars = ax.barh(algos, vals, color=colors, edgecolor='black', linewidth=0.5)
    ax.set_xlabel('Time (ms)')
    ax.set_title('Average Response Time')
    ax.invert_yaxis()

    for bar, val in zip(bars, vals):
        ax.text(val + 0.05, bar.get_y() + bar.get_height() / 2,
                f'{val:.2f} ms', va='center', fontsize=9)

    plt.savefig("charts/response_time.png")
    print("✓ charts/response_time.png")
    plt.close()


def plot_combined_comparison(summary):
    """Combined 2x2 figure like Fig. 3 in the paper."""
    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    algos = summary.index.tolist()
    colors = _algo_colors(algos)

    # (a) Token Gen — log scale
    ax = axes[0, 0]
    ax.barh(algos, summary["token_gen_mean"], color=colors, edgecolor='black', linewidth=0.5)
    ax.set_xscale('log')
    ax.set_xlabel('Time (ms) — log scale')
    ax.set_title('(a) Avg Token Generation Time')
    ax.invert_yaxis()

    # (b) Token Ver
    ax = axes[0, 1]
    ax.barh(algos, summary["token_ver_mean"], color=colors, edgecolor='black', linewidth=0.5)
    ax.set_xlabel('Time (ms)')
    ax.set_title('(b) Avg Token Verification Time')
    ax.invert_yaxis()

    # (c) Sizes
    ax = axes[1, 0]
    y = np.arange(len(algos))
    bh = 0.35
    ax.barh(y - bh / 2, summary["req_header_mean"], bh, label='Request Header',
            color='#4c72b0', edgecolor='black', linewidth=0.5)
    ax.barh(y + bh / 2, summary["resp_body_mean"], bh, label='Response Body',
            color='#dd8452', edgecolor='black', linewidth=0.5)
    ax.set_yticks(y)
    ax.set_yticklabels(algos)
    ax.set_xlabel('Size (bytes)')
    ax.set_title('(c) Avg Request Header & Response Body Size')
    ax.legend(fontsize=9)
    ax.invert_yaxis()

    # (d) Response Time
    ax = axes[1, 1]
    ax.barh(algos, summary["resp_time_mean"], color=colors, edgecolor='black', linewidth=0.5)
    ax.set_xlabel('Time (ms)')
    ax.set_title('(d) Avg Response Time')
    ax.invert_yaxis()

    plt.suptitle('PQC JWT/JOSE Benchmark — OAuth2 IAM Migration', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig("charts/combined_benchmark.png", dpi=200)
    print("✓ charts/combined_benchmark.png")
    plt.close()


def plot_token_size_comparison(summary):
    """Extra chart: JWT token size comparison (important for OAuth2 bearer tokens)."""
    fig, ax = plt.subplots(figsize=(10, 5))
    algos = summary.index.tolist()
    vals = summary["token_size_mean"].values
    colors = _algo_colors(algos)

    bars = ax.barh(algos, vals, color=colors, edgecolor='black', linewidth=0.5)
    ax.set_xlabel('Token Size (bytes)')
    ax.set_title('Average JWT Token Size (Bearer Token)')
    ax.invert_yaxis()

    ax.axvline(x=4096, color='red', linestyle='--', linewidth=1.5, label='Cookie limit (4096 B)')
    ax.legend()

    for bar, val in zip(bars, vals):
        ax.text(val + 10, bar.get_y() + bar.get_height() / 2,
                f'{val:.0f} B', va='center', fontsize=9)

    plt.savefig("charts/token_sizes.png")
    print("✓ charts/token_sizes.png")
    plt.close()

def plot_latency_grouped(summary):
    """
    Extra chart: grouped vertical bars for JWT generation, verification,
    and response time for each algorithm.
    """
    fig, ax = plt.subplots(figsize=(14, 6))

    algos = summary.index.tolist()
    x = np.arange(len(algos))
    width = 0.24

    gen_vals = summary["token_gen_mean"].values
    ver_vals = summary["token_ver_mean"].values
    resp_vals = summary["resp_time_mean"].values

    ax.bar(x - width, gen_vals, width, label='Generation', edgecolor='black', linewidth=0.5)
    ax.bar(x,         ver_vals, width, label='Verification', edgecolor='black', linewidth=0.5)
    ax.bar(x + width, resp_vals, width, label='Response', edgecolor='black', linewidth=0.5)

    ax.set_xticks(x)
    ax.set_xticklabels(algos, rotation=45, ha='right')
    ax.set_ylabel('Time (ms)')
    ax.set_title('JWT Latency Comparison: Generation, Verification, and Response')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig("charts/latency_grouped.png")
    print("✓ charts/latency_grouped.png")
    plt.close()
    
def generate_all_charts():
    print("\n📊 Generating charts...")
    summary = load_summary()
    plot_token_gen_time(summary)
    plot_token_ver_time(summary)
    plot_sizes(summary)
    plot_response_time(summary)
    plot_combined_comparison(summary)
    plot_token_size_comparison(summary)
    plot_latency_grouped(summary)
    print("✓ All charts saved to charts/")


if __name__ == "__main__":
    generate_all_charts()
