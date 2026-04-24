#!/usr/bin/env python3
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# === Load ===
file_path = "log_ns/results_tls_bench_ns.csv"
df = pd.read_csv(file_path)

# === Derive total CPU cost (client + server) per handshake ===
# Assumes CSV columns from updated bash script:
#   client_cpu_per_handshake_s, server_cpu_per_handshake_s
df["total_cpu_per_handshake_s"] = (
    df["client_cpu_per_handshake_s"] + df["server_cpu_per_handshake_s"]
)

# === Map environments ===
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

# === Focused subset ===
modes = ["classic", "classic-rsa", "hybrid-kem", "hybrid-full", "pqc"]
envs  = ["LAN / AD", "Home + VPN", "4G", "5G", "Cloud-to-Cloud", "Zero-Trust Edge"]
df_focus = df[df["mode"].isin(modes) & df["environment"].isin(envs)].copy()
df_focus["mode"] = pd.Categorical(df_focus["mode"], categories=modes, ordered=True)

# === Marker shapes for environments ===
markers = {
    "LAN / AD": "o",
    "Home + VPN": "s",
    "4G": "^",
    "5G": "P",
    "Cloud-to-Cloud": "D",
    "Zero-Trust Edge": "X",
}

# === Plot ===
sns.set_theme(style="whitegrid", font_scale=1.25)
palette_mode = sns.color_palette("tab10", n_colors=len(modes))

plt.figure(figsize=(11, 8))
sns.scatterplot(
    data=df_focus,
    x="total_cpu_per_handshake_s",
    y="handshakes_sec",
    hue="mode",
    style="environment",
    markers=markers,
    s=160,
    palette=palette_mode,
    alpha=0.9,
)

plt.title("Handshake Efficiency: Total CPU Cost vs Throughput across Network Environments",
          fontsize=16, pad=14)
plt.xlabel("Total CPU time per handshake [s] (client + server)", fontsize=13)
plt.ylabel("Handshakes per second", fontsize=13)
plt.legend(title="Mode / Environment", loc="best", fontsize=11, title_fontsize=12)
plt.tight_layout()
plt.savefig("figure_efficiency_cpu_vs_throughput.png", dpi=300, bbox_inches="tight")
plt.savefig("figure_efficiency_cpu_vs_throughput.pdf", bbox_inches="tight")
plt.show()

print("Saved: figure_efficiency_cpu_vs_throughput.[png|pdf]")
