#!/bin/bash

set -e

 

echo "=== PQC JWT Benchmark: Full Setup ==="

 

# 1. System deps

echo "[1/4] System packages..."

sudo apt install -y python3-dev python3-pip python3-venv libssl-dev libffi-dev pkg-config

 

# 2. Virtual environment

echo "[2/4] Python virtual environment..."

python3 -m venv .venv

source .venv/bin/activate

 

# 3. Python packages

echo "[3/4] Python packages..."

pip install --upgrade pip

pip install cryptography flask pandas matplotlib numpy

pip install liboqs-python || echo "⚠️  liboqs-python failed via pip, try building from source"

 

# 4. Verify

echo "[4/4] Verification..."

python3 -c "

from cryptography.hazmat.backends.openssl import backend

print(f'✅ cryptography → {backend.openssl_version_text()}')

"

python3 -c "

import oqs

sigs = oqs.get_enabled_sig_mechanisms()

for a in ['ML-DSA-44','ML-DSA-65','ML-DSA-87','Falcon-512','Falcon-1024']:

    print(f\"  {'✅' if a in sigs else '❌'} {a}\")

"

python3 -c "import flask; print(f'✅ Flask {flask.__version__}')"

python3 -c "import pandas; print(f'✅ pandas {pandas.__version__}')"

python3 -c "import matplotlib; print(f'✅ matplotlib {matplotlib.__version__}')"

 

echo ""

echo "✅ Setup complete! Run: ./run_benchmark.sh"
