import pandas as pd

# Input and output file paths
INPUT_FILE = "logs/results_20251113.csv"
OUTPUT_FILE = "logs/pqc_benchmark.csv"

# Load the CSV
df = pd.read_csv(INPUT_FILE)

# --- 1. Normalize Kyber → MLKEM naming -------------------------------------
kyber_map = {
    "Kyber512": "MLKEM512",
    "Kyber768": "MLKEM768",
    "Kyber1024": "MLKEM1024",
}
df['ALG'] = df['ALG'].replace(kyber_map)

# --- 2. Normalize ML-DSA → MLDSA naming -------------------------------------
mldsa_map = {
    "ML-DSA-44": "MLDSA-44",
    "ML-DSA-65": "MLDSA-65",
    "ML-DSA-87": "MLDSA-87",
}
df['ALG'] = df['ALG'].replace(mldsa_map)

# --- 3. Append (SymCrypt) or (liboqs) to ALG based on library --------------
df['ALG'] = df.apply(lambda row: f"{row['ALG']} ({row['LIB']})", axis=1)

# --- 4. Save cleaned data ---------------------------------------------------
df.to_csv(OUTPUT_FILE, index=False)

print(f"Data cleaned and saved to: {OUTPUT_FILE}")

