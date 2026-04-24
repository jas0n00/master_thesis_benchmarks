#!/bin/bash

BIN=$1
ITERS=$2

mkdir -p logs
OUT="logs/results_$(date +%Y%m%d).csv"

# Create header if missing
if [ ! -f "$OUT" ]; then
    echo "ALG,LIB,OP,US,CYC,OPS" > "$OUT"
fi

# Append results (skip program header)
./$BIN $ITERS | tail -n +2 >> "$OUT"

echo "Results appended to $OUT"

