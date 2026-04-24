#!/usr/bin/env python3
# spider_charts.py — Security vs Throughput vs Memory radar plots
# Author: Jakub (Master Thesis PQ IAM)
# Date: 2025-11-07

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

# Ensure output folder exists
os.makedirs("figures", exist_ok=True)

# ---------------------------
# Load and prepare data
# ---------------------------
df = pd.read_csv("logs/pqc_benchmark.csv")
df.columns = [c.strip().upper() for c in df.columns]

# ---------------------------
# Algorithm classification
# ---------------------------
def classify_type(alg, op):
    a = alg.lower()
    if any(x in a for x in ["mlkem", "kyber", "x25519"]):
        return "KEM"
    elif any(x in a for x in ["ecdsa", "rsa"]):
        return "CLASSIC"
    elif any(x in a for x in ["mldsa", "falcon"]):
        return "PQ_SIG"
    else:
        return "OTHER"

df["TYPE"] = df.apply(lambda x: classify_type(x["ALG"], x["OP"]), axis=1)

# ---------------------------
# Security level estimation
# ---------------------------
def get_security_level(alg):
    a = alg.lower()
    # PQC families
    if "mlkem" in a or "kyber" in a:
        if "512" in a: return 128
        if "768" in a: return 192
        if "1024" in a: return 256
    if "mldsa" in a:
        if "1" in a or "44" in a: return 128
        if "2" in a or "65" in a: return 192
        if "3" in a or "87" in a: return 256
    if "falcon" in a:
        if "512" in a: return 128
        if "1024" in a: return 256
    # Classical
    if "ecdsa" in a or "ecdh" in a or "x25519" in a:
        if "256" in a or "p-256" in a or "x25519" in a: return 128
        if "384" in a or "p-384" in a: return 192
        if "521" in a or "p-521" in a: return 256
    if "rsa" in a:
        if "2048" in a: return 112
        if "3072" in a: return 128
        if "4096" in a: return 152
    return None

# ---------------------------
# Throughput weighting logic
# ---------------------------
throughput_weights = {
    "keygen": 0.1,
    "sign": 0.5,
    "verify": 0.4,
    "encaps": 0.5,
    "decaps": 0.5,
    "dh": 0.5
}

# Aggregate by algorithm and library
records = []
for alg in df["ALG"].unique():
    subset = df[df["ALG"] == alg]
    ops_weighted = 0
    for _, row in subset.iterrows():
        op = row["OP"].lower()
        weight = throughput_weights.get(op, 0)
        ops_weighted += row["OPS"] * weight

    records.append({
        "ALG": alg,
        "LIB": subset["LIB"].iloc[0],
        "TYPE": subset["TYPE"].iloc[0],
        "THROUGHPUT": ops_weighted,
        "SECURITY": get_security_level(alg)
    })

merged = pd.DataFrame(records)

# ---------------------------
# Memory estimates (bytes)
# ---------------------------
memory_map = {
    # Classical
    "ecdsa-p256": 160, "ecdsa-p384": 208, "ecdsa-p521": 256,
    "rsa-2048": 550, "rsa-3072": 800, "rsa-4096": 1100,
    "x25519": 96,
    # PQC KEM
    "mlkem512": 1632 + 800 + 768,
    "mlkem768": 2400 + 1184 + 1088,
    "mlkem1024": 3168 + 1568 + 1568,
    # PQC Signature
    "mldsa-44": 1312 + 2420 + 1312,
    "mldsa-65": 1952 + 3309 + 1952,
    "mldsa-87": 2592 + 4627 + 2592,
    "falcon-512": 1281 + 666 + 666,
    "falcon-1024": 2305 + 1280 + 1280,
}

def get_memory(alg):
    a = alg.lower().replace("(", "").replace(")", "").replace(" ", "")
    for key in memory_map:
        if key in a:
            return memory_map[key]
    return None

merged["MEMORY"] = merged["ALG"].apply(get_memory)

# ---------------------------
# Normalization logic
# ---------------------------
def normalize_group(df, shared_df=None):
    df = df.copy()
    sec_max = merged["SECURITY"].max()
    df["SECURITY_NORM"] = df["SECURITY"] / sec_max

    if shared_df is not None:
        t_max = shared_df["THROUGHPUT"].max()
        m_max = shared_df["MEMORY"].max()
    else:
        t_max = df["THROUGHPUT"].max()
        m_max = df["MEMORY"].max()

    df["THROUGHPUT_NORM"] = df["THROUGHPUT"] / t_max
    df["MEM_EFF_NORM"] = 1 - (df["MEMORY"] / m_max)
    return df

# KEMs normalized separately
kem_df = merged[merged["TYPE"] == "KEM"]
kem_df = normalize_group(kem_df)

# Classical + PQ signatures normalized together
shared_df = merged[merged["TYPE"].isin(["CLASSIC", "PQ_SIG"])]
shared_df = normalize_group(shared_df, shared_df)

classic_df = shared_df[shared_df["TYPE"] == "CLASSIC"]
sig_df = shared_df[shared_df["TYPE"] == "PQ_SIG"]

# ---------------------------
# Radar plot function
# ---------------------------
def plot_radar(df, title, filename):
    labels = ["Security", "Throughput", "Memory efficiency"]
    num_vars = len(labels)
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))

    for _, row in df.iterrows():
        values = [
            row["SECURITY_NORM"],
            row["THROUGHPUT_NORM"],
            row["MEM_EFF_NORM"]
        ]
        values += values[:1]
        ax.plot(angles, values, label=f"{row['ALG']}", linewidth=1.8)
        # no fill for clarity
        plt.rcParams.update({
    "axes.edgecolor": "#999999",
    "axes.linewidth": 0.4,
    "font.size": 11,
})



    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    plt.xticks(angles[:-1], labels)
    ax.set_title(title, y=1.1)
    ax.legend(bbox_to_anchor=(1.05, 1), loc="upper left", fontsize="small")
    plt.tight_layout()
    plt.savefig(f"figures/{filename}", dpi=300)
    plt.close(fig)

# ---------------------------
# Plot generation
# ---------------------------
plot_radar(classic_df, "Security vs Throughput vs Memory (Classical Algorithms)", "spider_classical.png")
plot_radar(kem_df, "Security vs Throughput vs Memory (KEMs + X25519)", "spider_kem.png")
plot_radar(sig_df, "Security vs Throughput vs Memory (PQC Signatures)", "spider_sig_pq.png")

print("Spider charts generated in ./figures/")

