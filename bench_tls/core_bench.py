#!/usr/bin/env python3
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# === 1. Load Data ===
file_path = "log_ns/results_tls_bench_ns.csv"
df = pd.read_csv(file_path)

# === 1a. Total CPU per handshake (client + server) ===
df["total_cpu_per_handshake_s"] = (
    df["client_cpu_per_handshake_s"] + df["server_cpu_per_handshake_s"]
)

# === 2. Map environments ===
def map_environment(row):
    d, r, mtu = row["delay_ms"], row["rate_mbit"], row["mtu"]
    if d == 1 and r == 1000:
        return "LAN / AD"
    elif d == 20 and r == 100:
        return "Home + VPN"
    elif d == 40 and r == 50:
        return "4G"
    elif d == 60 and r == 200:
        return "Cloud-to-Cloud"
    elif d == 10 and r == 300:
        return "SD-WAN / 5G"
    elif d == 15 and r == 200 and mtu == 1350:
        return "Zero-Trust Edge"
    else:
        return "Other"

df["environment"] = df.apply(map_environment, axis=1)

# === 3. Focused subset ===
env_focus = ["LAN / AD", "Home + VPN", "4G"]
modes_focus = ["classic", "classic-rsa", "hybrid-kem", "hybrid-full", "pqc"]
df_focus = df[df["environment"].isin(env_focus) & df["mode"].isin(modes_focus)]

# === 4. Plotting style ===
sns.set_theme(style="whitegrid", font_scale=1.3)

# Use exactly as many colors as environments actually present to avoid the warning
n_envs = df_focus["environment"].nunique()
palette = sns.color_palette("Set2", n_colors=n_envs)

# === 5. Create figure ===
fig, axes = plt.subplots(3, 1, figsize=(13, 18))

# --- (a) Handshakes per second ---
sns.barplot(
    data=df_focus, x="mode", y="handshakes_sec",
    hue="environment", palette=palette, ax=axes[0]
)
axes[0].set_title("TLS 1.3 Handshake Performance — Handshakes per Second", fontsize=16, pad=15)
axes[0].set_xlabel("")
axes[0].set_ylabel("Handshakes per second", fontsize=13)
axes[0].legend(title="Environment", loc="upper right", fontsize=11, title_fontsize=12)

# --- (b) Latency ---
sns.barplot(
    data=df_focus, x="mode", y="latency_ms",
    hue="environment", palette=palette, ax=axes[1]
)
axes[1].set_title("TLS 1.3 Handshake Latency", fontsize=16, pad=15)
axes[1].set_xlabel("")
axes[1].set_ylabel("Latency [ms]", fontsize=13)
axes[1].legend(title="Environment", loc="upper right", fontsize=11, title_fontsize=12)

# --- (c) Total CPU per handshake (client + server) ---
sns.barplot(
    data=df_focus, x="mode", y="total_cpu_per_handshake_s",
    hue="environment", palette=palette, ax=axes[2]
)
axes[2].set_title("TLS 1.3 Handshake Resource Cost — Total CPU per Handshake", fontsize=16, pad=15)
axes[2].set_xlabel("")
axes[2].set_ylabel("Total CPU time per handshake [s] (client + server)", fontsize=13)
axes[2].legend(title="Environment", loc="upper right", fontsize=11, title_fontsize=12)

# === 6. Layout & Save ===
plt.tight_layout(pad=3.0)
plt.savefig("figure_core_performance.png", dpi=300, bbox_inches="tight")
plt.savefig("figure_core_performance.pdf", bbox_inches="tight")
plt.show()

print("Saved as 'figure_core_performance.png' and 'figure_core_performance.pdf'")
