import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

# ==========================================================
# SETUP
# ==========================================================
os.makedirs("figures", exist_ok=True)

# Load benchmark data
df = pd.read_csv("logs/pqc_benchmark.csv")

# Normalize columns
df.columns = [c.strip().upper() for c in df.columns]

# ==========================================================
# CLASSIFY ALGORITHM TYPE
# ==========================================================
def classify_type(alg, op):
    op = op.lower()
    if op in ["encaps", "decaps", "keygen"] and "kem" in alg.lower():
        return "KEM"
    elif op in ["sign", "verify", "keygen"] and ("dsa" in alg.lower() or "falcon" in alg.lower()):
        return "Signature"
    else:
        return "Other"

df["TYPE"] = df.apply(lambda x: classify_type(x["ALG"], x["OP"]), axis=1)

# ==========================================================
# SECURITY STRENGTH (BITS)
# ==========================================================
def get_security_strength_bits(alg: str):
    a = alg.lower()

    # PQC mappings (NIST categories)
    if "mlkem" in a or "kyber" in a:
        if "512" in a:   return 128
        if "768" in a:   return 192
        if "1024" in a:  return 256

    if "mldsa" in a or "ml-dsa" in a:
        if "44" in a or "mldsa-1" in a: return 128
        if "65" in a or "mldsa-2" in a: return 192
        if "87" in a or "mldsa-3" in a: return 256

    if "falcon" in a:
        if "512" in a:   return 128
        if "1024" in a:  return 256

    # Classical mappings
    if "ecdsa" in a or "ecdh" in a or "x25519" in a:
        if "256" in a or "p-256" in a or "x25519" in a: return 128
        if "384" in a or "p-384" in a: return 192
        if "521" in a or "p-521" in a: return 256

    if "rsa" in a:
        if "2048" in a: return 112
        if "3072" in a: return 128
        if "4096" in a: return 152

    return None

# ==========================================================
# COLOR MAP FOR LIBRARIES
# ==========================================================
LIB_COLORS = {"SymCrypt": "#007ACC", "liboqs": "#FF7F0E"}

# ==========================================================
# PQ KEM THROUGHPUT
# ==========================================================
kem_df = df[df["TYPE"] == "KEM"]
kem_algs = kem_df["ALG"].unique()

fig, ax = plt.subplots(figsize=(12, 5))
x = np.arange(len(kem_algs))
width = 0.25

for i, op in enumerate(["keygen", "encaps", "decaps"]):
    subset = kem_df[kem_df["OP"].str.lower() == op]
    y = [subset[subset["ALG"] == alg]["OPS"].mean() if alg in subset["ALG"].values else 0 for alg in kem_algs]
    ax.bar(x + i * width, y, width, label=op)

ax.set_xticks(x + width)
ax.set_xticklabels(kem_algs, rotation=45, ha="right")
ax.set_ylabel("Throughput (ops/sec)")
ax.set_title("PQ KEM Throughput")
ax.legend()
plt.tight_layout()
plt.savefig("figures/pq_kem_throughput.png", dpi=300)
plt.close(fig)
print("Saved: figures/pq_kem_throughput.png")

# ==========================================================
# PQ KEM SECURITY EFFICIENCY
# ==========================================================
encaps_df = kem_df[kem_df["OP"].str.lower() == "encaps"].copy()
encaps_df["SEC_LVL"] = encaps_df["ALG"].apply(get_security_strength_bits)
encaps_df = encaps_df.dropna(subset=["SEC_LVL"])
encaps_df["SEC_EFF"] = encaps_df["OPS"] / encaps_df["SEC_LVL"]

colors = encaps_df["LIB"].map(LIB_COLORS).fillna("#888888")

fig, ax = plt.subplots(figsize=(12, 5))
ax.bar(encaps_df["ALG"], encaps_df["SEC_EFF"], color=colors)
ax.set_xticks(np.arange(len(encaps_df["ALG"])))
ax.set_xticklabels(encaps_df["ALG"], rotation=45, ha="right")
ax.set_ylabel("Security-Adjusted Encapsulation Throughput (OPS / bit)")
ax.set_title("PQ KEM Security Efficiency")

# Legend
handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in LIB_COLORS.values()]
ax.legend(handles, LIB_COLORS.keys())
plt.tight_layout()
plt.savefig("figures/pq_kem_efficiency.png", dpi=300)
plt.close(fig)
print("Saved: figures/pq_kem_efficiency.png")

# ==========================================================
# PQ SIGNATURE THROUGHPUT (LOG SCALE)
# ==========================================================
sig_df = df[df["TYPE"] == "Signature"]
sig_algs = sig_df["ALG"].unique()

fig, ax = plt.subplots(figsize=(12, 5))
x = np.arange(len(sig_algs))
width = 0.25

for i, op in enumerate(["keygen", "sign", "verify"]):
    subset = sig_df[sig_df["OP"].str.lower() == op]
    y = [subset[subset["ALG"] == alg]["OPS"].mean() if alg in subset["ALG"].values else 0 for alg in sig_algs]
    ax.bar(x + i * width, y, width, label=op)

ax.set_xticks(x + width)
ax.set_xticklabels(sig_algs, rotation=45, ha="right")
#ax.set_yscale("log")  # <-- log scale for wide range
ax.set_ylabel("Throughput (ops/sec)")
ax.set_ylabel("Throughput (ops/sec)")
ax.set_title("PQ Signature Throughput")
ax.legend()
plt.tight_layout()
plt.savefig("figures/pq_signature_throughput.png", dpi=300)
plt.close(fig)
print("Saved: figures/pq_signature_throughput.png")

# ==========================================================
# PQ SIGNATURE SECURITY EFFICIENCY
# ==========================================================
sign_df = sig_df[sig_df["OP"].str.lower() == "sign"].copy()
sign_df["SEC_LVL"] = sign_df["ALG"].apply(get_security_strength_bits)
sign_df = sign_df.dropna(subset=["SEC_LVL"])
sign_df["SEC_EFF"] = sign_df["OPS"] / sign_df["SEC_LVL"]

colors = sign_df["LIB"].map(LIB_COLORS).fillna("#888888")

fig, ax = plt.subplots(figsize=(12, 5))
ax.bar(sign_df["ALG"], sign_df["SEC_EFF"], color=colors)
ax.set_xticks(np.arange(len(sign_df["ALG"])))
ax.set_xticklabels(sign_df["ALG"], rotation=45, ha="right")
ax.set_ylabel("Security-Adjusted Sign Throughput (OPS / bit)")
ax.set_title("PQ Signature Security Efficiency")






# ==========================================================
# SUMMARY TABLES
# ==========================================================

# Signature Throughput Table
sig_summary = (
    sig_df.groupby(["ALG", "OP"])["OPS"]
    .mean()
    .unstack("OP")[["keygen", "sign", "verify"]]
    .fillna(0)
    .round(2)
    .sort_index()
)

print("\n📋 Signature Throughput Table (ops/sec):")
print(sig_summary)

sig_summary.to_csv("figures/pq_signature_throughput_table.csv")
print("Saved: figures/pq_signature_throughput_table.csv")

# KEM Throughput Table
kem_summary = (
    kem_df.groupby(["ALG", "OP"])["OPS"]
    .mean()
    .unstack("OP")[["keygen", "encaps", "decaps"]]
    .fillna(0)
    .round(2)
    .sort_index()
)

print("\n📋 KEM Throughput Table (ops/sec):")
print(kem_summary)




handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in LIB_COLORS.values()]
ax.legend(handles, LIB_COLORS.keys())
plt.tight_layout()
plt.savefig("figures/pq_signature_efficiency.png", dpi=300)
plt.close(fig)
print("Saved: figures/pq_signature_efficiency.png")

print("\nAll plots successfully generated and saved in 'figures/' folder.")

