# Benchmark Suite

This folder contains three separate benchmark areas used to evaluate the performance impact of classical, post-quantum, and hybrid cryptographic mechanisms in different layers of an IAM / Zero Trust environment.

## Folder overview

| Folder | Purpose |
|---|---|
| `bench_algos/` | Low-level cryptographic algorithm benchmark for signatures, KEMs, and key agreement. |
| `bench_tls/` | TLS 1.3 handshake benchmark using Linux network namespaces and simulated network conditions. |
| `jwt_benchmark/` | JWT/JOSE benchmark for OAuth2-style IAM API flows using classical, PQC, and hybrid signatures. |

Each benchmark folder contains its own `README.md` with a short introduction, prerequisites, run commands, and expected outputs.

## General notes

These benchmarks are Linux-oriented. Some scripts use Linux-specific features such as `rdtsc`, Linux network namespaces, `tc`, and `tcpdump`. The TLS benchmark also assumes an OQS-enabled OpenSSL installation at `/usr/local/openssl/bin/openssl` unless the script is modified.

The benchmark outputs already included in the repository are stored under folders such as `logs/`, `log_ns/`, `results/`, `figures/`, `graphs_ns/`, and `charts/`.
