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

## Troubleshooting

If the benchmark binary does not run, check that it is located directly inside `bench_algos/`, because `run_and_log.sh` executes it as `./BINARY_NAME`.

If charts fail with a missing file error, confirm that `logs/pqc_benchmark.csv` exists and has the columns `ALG`, `LIB`, `OP`, `US`, `CYC`, and `OPS`.

If liboqs algorithms are reported as unavailable, rebuild or reinstall liboqs with the required algorithms enabled.# Algorithm-Level Cryptographic Benchmark

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

### SymCrypt include-path note

The SymCrypt benchmarks require both the SymCrypt header file and the SymCrypt shared library. On some Linux installations, the header is installed as:

```text
/usr/local/include/symcrypt/symcrypt.h
```

In that case, the correct include path is:

```bash
-I/usr/local/include/symcrypt
```

not only:

```bash
-I/usr/local/include
```

This is necessary because the benchmark source files use:

```c
#include <symcrypt.h>
```

and GCC must be given the directory that directly contains `symcrypt.h`.

You can verify the header location with:

```bash
find /usr /usr/local /opt ~/ -name "symcrypt.h" 2>/dev/null
```

You can verify that the SymCrypt library is visible with:

```bash
ldconfig -p | grep symcrypt
```

### Example compilation commands

If SymCrypt is installed under `/usr/local/include/symcrypt` and `/usr/local/lib`, use:

```bash
# SymCrypt benchmarks
gcc symcrypt_scripts/mlkem_bench.c      -I/usr/local/include/symcrypt -L/usr/local/lib -Wl,-rpath,/usr/local/lib -o mlkem_bench  -lsymcrypt
gcc symcrypt_scripts/benchmark_mldsa.c  -I/usr/local/include/symcrypt -L/usr/local/lib -Wl,-rpath,/usr/local/lib -o mldsa_bench  -lsymcrypt
gcc symcrypt_scripts/ecdsa_bench.c      -I/usr/local/include/symcrypt -L/usr/local/lib -Wl,-rpath,/usr/local/lib -o ecdsa_bench  -lsymcrypt
gcc symcrypt_scripts/x25519_bench.c     -I/usr/local/include/symcrypt -L/usr/local/lib -Wl,-rpath,/usr/local/lib -o x25519_bench -lsymcrypt
gcc symcrypt_scripts/rsa_bench.c        -I/usr/local/include/symcrypt -L/usr/local/lib -Wl,-rpath,/usr/local/lib -o rsa_bench    -lsymcrypt -lcrypto

# liboqs benchmarks
gcc oqs_scripts/kem_libsqs.c            -o kem_liboqs       -loqs
gcc oqs_scripts/oqs_sig_bench.c         -o oqs_sig_bench    -loqs
```

If your SymCrypt header is located in the source tree, for example:

```text
/home/jakub/SymCrypt/inc/symcrypt.h
```

then use this include path instead:

```bash
-I/home/jakub/SymCrypt/inc
```

For example:

```bash
gcc symcrypt_scripts/mlkem_bench.c \
  -I/home/jakub/SymCrypt/inc \
  -L/usr/local/lib \
  -Wl,-rpath,/usr/local/lib \
  -o mlkem_bench \
  -lsymcrypt
```

If linking fails because the system provides only a versioned shared library such as `libsymcrypt.so.103`, compile with the explicit library name:

```bash
gcc symcrypt_scripts/mlkem_bench.c \
  -I/usr/local/include/symcrypt \
  -L/usr/local/lib \
  -Wl,-rpath,/usr/local/lib \
  -o mlkem_bench \
  -l:libsymcrypt.so.103
```

Alternatively, create a standard `libsymcrypt.so` symlink:

```bash
sudo ln -s /usr/local/lib/libsymcrypt.so.103 /usr/local/lib/libsymcrypt.so
sudo ldconfig
```

If compilation fails because a liboqs header or library cannot be found, compile with explicit paths, for example:

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

## Troubleshooting

If a SymCrypt benchmark fails to compile with:

```text
fatal error: symcrypt.h: No such file or directory
```

then GCC cannot find the SymCrypt header. Use `find` to locate it:

```bash
find /usr /usr/local /opt ~/ -name "symcrypt.h" 2>/dev/null
```

If the result is `/usr/local/include/symcrypt/symcrypt.h`, add this flag to the compile command:

```bash
-I/usr/local/include/symcrypt
```

If the result is `/home/jakub/SymCrypt/inc/symcrypt.h`, add this flag instead:

```bash
-I/home/jakub/SymCrypt/inc
```

If the benchmark binary does not run, check that it is located directly inside `bench_algos/`, because `run_and_log.sh` executes it as `./BINARY_NAME`.

If charts fail with a missing file error, confirm that `logs/pqc_benchmark.csv` exists and has the columns `ALG`, `LIB`, `OP`, `US`, `CYC`, and `OPS`.

If liboqs algorithms are reported as unavailable, rebuild or reinstall liboqs with the required algorithms enabled.
