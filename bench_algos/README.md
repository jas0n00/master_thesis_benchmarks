# Algorithm-Level Cryptographic Benchmark

## What this benchmark is about

This benchmark measures the raw performance of individual cryptographic algorithms used in classical, post-quantum, and hybrid migration scenarios. It focuses on low-level operation costs before the algorithms are placed into higher-level protocols such as TLS or JWT/JOSE.

The benchmark records average execution time, CPU cycles, and throughput for operations such as:

- key generation,
- signing and verification,
- encapsulation and decapsulation,
- Diffie-Hellman / key agreement.

The included C benchmark sources cover:

- SymCrypt ML-DSA signatures,
- SymCrypt ML-KEM KEMs,
- SymCrypt ECDSA,
- SymCrypt RSA signing and verification,
- SymCrypt X25519,
- liboqs KEMs,
- liboqs ML-DSA and Falcon signatures.

The output format is a CSV table with the columns:

```text
ALG,LIB,OP,US,CYC,OPS
```

where `US` is average microseconds per operation, `CYC` is average CPU cycles per operation, and `OPS` is operations per second.

## Folder structure

```text
bench_algos/
├── symcrypt_scripts/       # SymCrypt-based C benchmarks
├── oqs_scripts/            # liboqs-based C benchmarks
├── logs/                   # Raw and cleaned CSV benchmark results
├── figures/                # Generated plots and tables
├── run_and_log.sh          # Helper script for running a compiled benchmark and appending results
├── data_fix.py             # Normalizes raw CSV naming into logs/pqc_benchmark.csv
├── analyze_benchmark1.py   # Generates KEM/signature throughput and efficiency charts
└── plot_spider_pqc.py      # Generates radar/spider charts
```

## Prerequisites

Install the required native and Python dependencies before running the benchmark:

```bash
sudo apt update
sudo apt install -y build-essential python3 python3-pip libssl-dev pkg-config
pip install pandas matplotlib numpy
```

You also need the cryptographic libraries used by the C files:

- SymCrypt development headers and library for files in `symcrypt_scripts/`,
- liboqs development headers and library for files in `oqs_scripts/`,
- OpenSSL development headers for the RSA benchmark.

The exact compiler flags can differ depending on where SymCrypt and liboqs are installed. If the headers or libraries are not in standard system paths, add `-I/path/to/include` and `-L/path/to/lib` to the compile commands.

## How to build the benchmarks

From this folder:

```bash
cd bench_algos
```

Example compilation commands:

```bash
# SymCrypt benchmarks
 gcc symcrypt_scripts/mlkem_bench.c      -o mlkem_bench      -lsymcrypt
 gcc symcrypt_scripts/benchmark_mldsa.c  -o mldsa_bench      -lsymcrypt
 gcc symcrypt_scripts/ecdsa_bench.c      -o ecdsa_bench      -lsymcrypt
 gcc symcrypt_scripts/x25519_bench.c     -o x25519_bench     -lsymcrypt
 gcc symcrypt_scripts/rsa_bench.c        -o rsa_bench        -lsymcrypt -lcrypto

# liboqs benchmarks
 gcc oqs_scripts/kem_libsqs.c            -o kem_liboqs       -loqs
 gcc oqs_scripts/oqs_sig_bench.c         -o oqs_sig_bench    -loqs
```

If compilation fails because a header or library cannot be found, compile with explicit paths, for example:

```bash
gcc oqs_scripts/oqs_sig_bench.c -I/usr/local/include -L/usr/local/lib -o oqs_sig_bench -loqs
```

## How to run the benchmark

The benchmark binaries accept the number of iterations as their first argument. The helper script appends the output to a date-stamped CSV file under `logs/`.

```bash
chmod +x run_and_log.sh

./run_and_log.sh mlkem_bench 1000
./run_and_log.sh mldsa_bench 1000
./run_and_log.sh ecdsa_bench 1000
./run_and_log.sh rsa_bench 1000
./run_and_log.sh x25519_bench 1000
./run_and_log.sh kem_liboqs 1000
./run_and_log.sh oqs_sig_bench 1000
```

The helper writes results to:

```text
logs/results_YYYYMMDD.csv
```

## How to prepare data for plotting

The analysis scripts expect the cleaned input file:

```text
logs/pqc_benchmark.csv
```

There are two common ways to create it.

Option 1: copy the date-stamped CSV directly:

```bash
cp logs/results_YYYYMMDD.csv logs/pqc_benchmark.csv
```

Option 2: use the normalization helper:

```bash
python3 data_fix.py
```

`data_fix.py` currently reads from `logs/results_20251113.csv`. If your result file has a different date, update the `INPUT_FILE` variable inside `data_fix.py` or rename your result file before running it.

## How to generate charts

After `logs/pqc_benchmark.csv` exists, run:

```bash
python3 analyze_benchmark1.py
python3 plot_spider_pqc.py
```

The charts and generated tables are saved under:

```text
figures/
```

Important generated outputs include:

- `figures/pq_kem_throughput.png`,
- `figures/pq_kem_efficiency.png`,
- `figures/pq_signature_throughput.png`,
- `figures/pq_signature_efficiency.png`,
- `figures/pq_signature_throughput_table.csv`,
- `figures/spider_classical.png`,
- `figures/spider_kem.png`,
- `figures/spider_sig_pq.png`.

