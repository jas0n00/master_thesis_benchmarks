# TLS 1.3 Network Namespace Benchmark

## What this benchmark is about

This benchmark evaluates how classical, post-quantum, and hybrid cryptography affect TLS 1.3 handshakes under different network conditions. It uses Linux network namespaces to create a local client/server topology and applies delay, bandwidth, and MTU constraints with Linux traffic control.

The benchmark compares these TLS modes:

| Mode | Meaning |
|---|---|
| `classic` | ECDSA P-256 certificate/signature with X25519 key exchange. |
| `classic-rsa` | RSA-3072 certificate/signature with X25519 key exchange. |
| `hybrid-kem` | ECDSA P-256 with hybrid X25519 + ML-KEM-768 key exchange. |
| `hybrid-full` | Hybrid P-256 + ML-DSA certificate/signature with hybrid X25519 + ML-KEM-768 key exchange. |
| `pqc` | ML-DSA certificate/signature with ML-KEM-768 key exchange. |

The benchmark measures:

- completed TLS handshakes,
- handshakes per second,
- estimated latency per handshake,
- client CPU cost per handshake,
- server CPU cost per handshake,
- memory cost per handshake,
- captured TLS handshake bytes per connection,
- certificate and private key size.

## Folder structure

```text
bench_tls/
├── tls_bench_ns/                 # Main namespace-based TLS benchmark scripts
│   ├── tls_bench_ns.sh           # Runs one benchmark configuration
│   └── run.sh                    # Runs all predefined network environments and TLS modes
├── log_ns/                       # CSV benchmark logs
├── graphs_ns/                    # Generated graph outputs
├── core_bench.py                 # Core performance plots
├── CPU_Throughput.py             # CPU cost vs throughput plot
├── delay_bench.py                # Delay impact model and plots
└── efficiency_resource_plot.py   # Resource-efficiency plot
```

## Prerequisites

This benchmark requires Linux and must usually be run with `sudo`, because it creates network namespaces and configures traffic shaping.

Install system tools:

```bash
sudo apt update
sudo apt install -y iproute2 iputils-ping tcpdump tshark time python3 python3-pip
pip install pandas matplotlib seaborn scipy statsmodels
```

The script expects an OQS-enabled OpenSSL binary and provider module at:

```text
/usr/local/openssl/bin/openssl
/usr/local/openssl/lib64/ossl-modules/oqsprovider.so
```

If your OQS OpenSSL installation is somewhere else, edit these variables in `tls_bench_ns/tls_bench_ns.sh`:

```bash
OQS=/usr/local/openssl/bin/openssl
OQS_MOD=/usr/local/openssl/lib64/ossl-modules
```

## How to run one benchmark configuration

From this folder:

```bash
cd bench_tls/tls_bench_ns
chmod +x tls_bench_ns.sh run.sh
```

Run a single mode and network condition:

```bash
sudo ./tls_bench_ns.sh --mode classic --delay-ms 1 --rate-mbit 1000 --mtu 1500 --time 5
```

Example with a hybrid KEM mode:

```bash
sudo ./tls_bench_ns.sh --mode hybrid-kem --delay-ms 20 --rate-mbit 100 --mtu 1400 --time 5
```

Supported modes are:

```text
classic
classic-rsa
hybrid-kem
hybrid-full
pqc
```

## How to run the full benchmark batch

The batch script runs all five TLS modes across the predefined network profiles:

- LAN / AD,
- Home + VPN,
- 4G,
- 5G,
- Cloud-to-Cloud,
- Zero-Trust Edge.

Run:

```bash
cd bench_tls/tls_bench_ns
sudo ./run.sh
```

Results are appended to:

```text
bench_tls/log_ns/results_tls_bench_ns.csv
```

The CSV columns are:

```text
mode,connections,handshakes_sec,latency_ms,client_cpu_per_handshake_s,server_cpu_per_handshake_s,client_mem_per_handshake_kb,handshake_bytes_per_conn,cert_bytes,key_bytes,delay_ms,rate_mbit,mtu
```

## How to generate plots

Run the plotting scripts from the `bench_tls/` folder:

```bash
cd bench_tls
python3 core_bench.py
python3 CPU_Throughput.py
python3 delay_bench.py
python3 efficiency_resource_plot.py
```

The scripts read from:

```text
log_ns/results_tls_bench_ns.csv
log_ns/delay_data.csv
```

and generate PNG/PDF figures, such as:

- `figure_core_performance.png`,
- `figure_efficiency_cpu_vs_throughput.png`,
- `figure_delay_impact_comparison.png`,
- `figure_resource_efficiency.png`.

The repository also contains previously generated versions under:

```text
graphs_ns/
```

## Notes

`delay_bench.py` expects `log_ns/delay_data.csv`, while the main namespace script writes to `log_ns/results_tls_bench_ns.csv`. If you want to model delay impact from a new run, prepare a CSV named `delay_data.csv` containing at least these columns:

```text
mode,delay_ms,handshakes_sec
```

`efficiency_resource_plot.py` currently calculates throughput efficiency from a column named `cpu_per_handshake_s`. The current namespace CSV stores client and server CPU separately. If this script fails, add a combined CPU column to the CSV or adjust the script to use:

```python
df["client_cpu_per_handshake_s"] + df["server_cpu_per_handshake_s"]
```

## Troubleshooting

If you see `OQS OpenSSL not found`, confirm that the OQS-enabled OpenSSL binary exists or update the `OQS` path in `tls_bench_ns.sh`.

If namespace setup fails, run the benchmark with `sudo` and make sure `iproute2` is installed.

If packet-size metrics are zero, install `tshark`. The benchmark can still run without it, but TLS handshake byte counting may not be available.
