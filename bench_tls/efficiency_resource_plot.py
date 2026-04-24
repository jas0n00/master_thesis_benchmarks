#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# === 1. Load dataset ===
file_path = "log_ns/results_tls_bench_ns.csv"   # adjust if needed
df = pd.read_csv(file_path)

# === 2. Map environments automatically ===
def map_environment(row):
    d, r, mtu = row["delay_ms"], row["rate_mbit"], row["mtu"]
    if d == 1 and r == 1000:
        return "LAN / AD"
    elif d == 20 and r == 100:
        return "Home + VPN"
    elif d == 40 and r == 50:
        return "4G"
    elif d == 10 and r == 300:
        return "5G"
    elif d == 60 and r == 200:
        return "Cloud-to-Cloud"
    elif d == 15 and r == 200 and mtu == 1350:
        return "Zero-Trust Edge"
    else:
        return "Other"

df["environment"] = df.apply(map_environment, axis=1)

# === 3. Compute throughput efficiency ===
df["throughput_eff"] = df["handshakes_sec"] / df["cpu_per_handshake_s"]

# === 4. Filter only relevant environments and modes ===
env_focus = ["LAN / AD", "Home + VPN", "4G"]
mode_order = ["classic", "classic-rsa", "hybrid-kem", "hybrid-full", "pqc"]

df_focus = df[df["environment"].isin(env_focus) & df["mode"].isin(mode_order)]
df_focus["mode"] = pd.Categorical(df_focus["mode"], categories=mode_order, ordered=True)

# === 5. Plot ===
sns.set_theme(style="whitegrid", font_scale=1.3)
palette = ["#66c2a5", "#fc8d62", "#8da0cb"]  # consistent LAN/VPN/4G colors

plt.figure(figsize=(10, 6))
sns.barplot(
    data=df_focus,
    x="mode",
    y="throughput_eff",
    hue="environment",
    palette=palette
)

plt.title("Resource Efficiency Impact: Throughput per CPU-Second", fontsize=16, pad=14)
plt.xlabel("")
plt.ylabel("Throughput efficiency [handshakes / CPU-second]", fontsize=13)
plt.legend(title="Environment", fontsize=11, title_fontsize=12, loc="upper right")

plt.tight_layout()
plt.savefig("figure_resource_efficiency.png", dpi=300, bbox_inches="tight")
plt.savefig("figure_resource_efficiency.pdf", bbox_inches="tight")
plt.show()

print("Saved: figure_resource_efficiency.[png|pdf]")

