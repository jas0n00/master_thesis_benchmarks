#!/bin/bash
set -e

echo "=============================================="
echo "  PQC JWT/JOSE Benchmark for OAuth2 IAM       "
echo "=============================================="
echo ""

# ── Check dependencies ──
echo "[1/5] Checking environment..."
python3 -c "import oqs; print(f'  liboqs-python: OK (algorithms: {len(oqs.get_enabled_sig_mechanisms())} sigs enabled)')"
python3 -c "import cryptography; print(f'  cryptography: {cryptography.__version__}')"
python3 -c "
from cryptography.hazmat.backends.openssl import backend
print(f'  OpenSSL backend: {backend.openssl_version_text()}')
"
openssl version
echo "  OQS Provider:"
openssl list -signature-algorithms 2>/dev/null | grep -i -E "mldsa|falcon" | head -6 || echo "  (check OQS provider is loaded)"
echo ""

# ── Install Python deps ──
echo "[2/5] Installing Python dependencies..."
pip install -q -r requirements.txt
pip install -q liboqs-python 2>/dev/null || echo "  (liboqs-python may need manual install from source)"
echo ""

# ── Run benchmark ──
echo "[3/5] Running benchmark..."
python3 -m benchmark.runner
echo ""

# ── Generate charts ──
echo "[4/5] Generating charts..."
python3 -m benchmark.visualize
echo ""

# ── Print summary ──
echo "[5/5] Summary:"
echo ""
cat results/summary.csv | python3 -c "
import sys, pandas as pd
df = pd.read_csv(sys.stdin, index_col=0)
print(df.to_string())
"

echo ""
echo "✅ Benchmark complete!"
echo "   Results:  results/raw_results.csv"
echo "   Summary:  results/summary.csv"
echo "   Charts:   charts/"