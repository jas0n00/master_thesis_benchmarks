# JWT/JOSE Benchmark for OAuth2 IAM

## What this benchmark is about

This benchmark measures the performance and size impact of classical, post-quantum, and hybrid signatures when used for JWT/JOSE-style bearer tokens in an OAuth2-like IAM workflow.

It simulates a small API using Flask's test client and measures token and HTTP-flow overhead for common IAM scenarios such as:

- user registration,
- duplicate registration rejection,
- login,
- failed login,
- authenticated task creation,
- unauthenticated request rejection,
- task read/update/delete operations.

The benchmark evaluates token generation, token verification, token size, request header size, response body size, public key size, and response time.

## Algorithms included

The configured algorithms are defined in `benchmark/config.py`.

Classical algorithms:

- `ECDSA-P256`,
- `RSA-2048`.

Pure post-quantum algorithms:

- `ML-DSA-44`,
- `ML-DSA-65`,
- `ML-DSA-87`,
- `Falcon-512`,
- `Falcon-1024`.

Hybrid composite algorithms:

- `P256+ML-DSA-44`,
- `P256+Falcon-512`.

Nested hybrid JWT configurations:

- `P256>>ML-DSA-44`,
- `P256>>Falcon-512`.

The benchmark produces real compact JWS/JWT strings and verifies the generated signatures during the test run.

## Folder structure

```text
jwt_benchmark/
├── benchmark/              # Python benchmark package
│   ├── config.py           # Algorithm and scenario configuration
│   ├── crypto_engines.py   # Classical, PQC, and hybrid signing engines
│   ├── jwt_engine.py       # Compact JWS/JWT generation and verification
│   ├── http_simulator.py   # Flask API simulation
│   ├── runner.py           # Main benchmark runner
│   └── visualize.py        # Chart generation
├── results/                # Raw and summarized CSV outputs
├── charts/                 # Generated benchmark charts
├── requirements.txt        # Python package requirements
├── prerequisites.sh        # Full setup helper
└── run_benchmark.sh        # End-to-end benchmark runner
```

## Prerequisites

The benchmark requires Python 3 and the packages listed in `requirements.txt`:

```text
cryptography
liboqs-python
flask
pandas
matplotlib
numpy
```

For classical signatures, the benchmark uses Python `cryptography`. For PQC signatures, it uses `liboqs-python`.

Install system dependencies on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y python3-dev python3-pip python3-venv libssl-dev libffi-dev pkg-config
```

## Recommended setup

From this folder:

```bash
cd jwt_benchmark
chmod +x prerequisites.sh run_benchmark.sh
./prerequisites.sh
source .venv/bin/activate
```

If `liboqs-python` cannot be installed from pip in your environment, install or build liboqs/liboqs-python manually and then rerun the verification commands printed by `prerequisites.sh`.

## How to run the full benchmark

After the environment is ready:

```bash
./run_benchmark.sh
```

The script performs these steps:

1. checks the Python and cryptography environment,
2. installs Python dependencies from `requirements.txt`,
3. runs the benchmark with `python3 -m benchmark.runner`,
4. generates charts with `python3 -m benchmark.visualize`,
5. prints the summary table.

## Manual run commands

You can also run the benchmark manually:

```bash
python3 -m benchmark.runner
python3 -m benchmark.visualize
```

## Output files

The benchmark writes raw and summarized CSV results to:

```text
results/raw_results.csv
results/raw.csv
results/summary.csv
```


