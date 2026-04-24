"""
Main benchmark runner.
"""

import os
import json
import time
import base64
import pandas as pd

from benchmark.config import (
    ALGORITHMS,
    NESTED_CONFIGS,
    TEST_SCENARIOS,
    NUM_WARMUP,
    NUM_MEASURED,
)
from benchmark.crypto_engines import generate_keys
from benchmark import jwt_engine as je
from benchmark.http_simulator import create_app


PRINT_SIGNATURE_CHECKS = True


def _b64json(segment: str):
    """Decode one Base64url JWS segment as JSON."""
    segment += "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment.encode("ascii")).decode("utf-8"))


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _series_stats_nonzero(series: pd.Series):
    """Mean / median / std over values that are strictly > 0."""
    vals = series[series > 0]
    if vals.empty:
        return 0.0, 0.0, 0.0
    std = float(vals.std()) if len(vals) > 1 else 0.0
    return float(vals.mean()), float(vals.median()), std


def _mean_or_zero(series: pd.Series):
    """Mean over a possibly empty filtered series."""
    if series.empty:
        return 0.0
    return float(series.mean())


def _iteration_user_email(i: int) -> str:
    """Stable per-iteration identity for register/login scenarios."""
    return f"user_{i}_1@test.com"


def print_token_signature_check(name, cfg, keys, token, label="token"):
    """Print a compact signature-validation summary for plain, composite, and nested JWS."""
    overall_ok, _ = je.verify_token(name, cfg, keys, token)

    parts = token.split(".")
    if len(parts) != 3:
        print(f"[SIG-CHECK] {name} | {label} | INVALID JWS FORMAT")
        return

    outer_header = _b64json(parts[0])

    if cfg["type"] == "hybrid_nested":
        try:
            inner_token = _b64json(parts[1])  # outer payload is the inner JWT string
            inner_parts = inner_token.split(".")
            inner_header = _b64json(inner_parts[0]) if len(inner_parts) == 3 else {}
        except Exception:
            print(
                f"[SIG-CHECK] {name} | {label} | "
                f"outer_alg={outer_header.get('alg')} cty={outer_header.get('cty')} | "
                f"inner_payload_decode=FAIL | overall={'OK' if overall_ok else 'FAIL'}"
            )
            return

        outer_ok = je._verify_compact_jws(
            cfg["outer_algo"],
            je.ALGORITHMS[cfg["outer_algo"]],
            keys.pqc_keys,
            token,
        )
        inner_ok = je._verify_compact_jws(
            cfg["inner_algo"],
            je.ALGORITHMS[cfg["inner_algo"]],
            keys.classical_keys,
            inner_token,
        )

        print(
            f"[SIG-CHECK] {name} | {label} | "
            f"outer_alg={outer_header.get('alg')} cty={outer_header.get('cty')} "
            f"inner_alg={inner_header.get('alg')} | "
            f"outer_sig={'OK' if outer_ok else 'FAIL'} | "
            f"inner_sig={'OK' if inner_ok else 'FAIL'} | "
            f"overall={'OK' if overall_ok else 'FAIL'}"
        )

    elif cfg["type"] == "hybrid":
        print(
            f"[SIG-CHECK] {name} | {label} | "
            f"alg={outer_header.get('alg')} | "
            f"composite_sig={'OK' if overall_ok else 'FAIL'}"
        )

    else:
        print(
            f"[SIG-CHECK] {name} | {label} | "
            f"alg={outer_header.get('alg')} | "
            f"sig={'OK' if overall_ok else 'FAIL'}"
        )


def run_single_algorithm(name, cfg):
    keys = generate_keys(name, cfg)
    app = create_app(je, name, cfg, keys)
    client = app.test_client()
    pub_key_bytes = len(keys.public_key_bytes)

    # One preflight token and signature check for console visibility.
    preflight_token, _ = je.generate_token(name, cfg, keys)
    if PRINT_SIGNATURE_CHECKS:
        print_token_signature_check(name, cfg, keys, preflight_token, label="preflight")

    records = []
    printed_labels = set()

    for i in range(NUM_WARMUP + NUM_MEASURED):
        warm = i < NUM_WARMUP
        registered_email = _iteration_user_email(i)

        for sc in TEST_SCENARIOS:
            headers = {}
            body = None
            token_gen_ms = 0.0
            token_ver_ms = 0.0
            token_size = 0.0
            token_response = False

            # For authenticated scenarios, generate a fresh token and use it.
            if sc["auth"]:
                token, token_gen_ms = je.generate_token(name, cfg, keys)
                headers = {"Authorization": f"Bearer {token}"}
                token_ver_ok, token_ver_ms = je.verify_token(name, cfg, keys, token)
                if not token_ver_ok:
                    raise RuntimeError(
                        f"Pre-request token verification failed for {name} in scenario {sc['id']}"
                    )
                token_size = float(je.get_token_sizes(token)["total_token_bytes"])

            if sc["method"] in ("POST", "PUT"):
                if sc["endpoint"] == "/auth/register":
                    # Scenario 1: register new user
                    # Scenario 2: try to register the SAME user again -> true duplicate
                    body = json.dumps({
                        "email": registered_email,
                        "password": "pass"
                    })
                elif sc["endpoint"] == "/auth/login":
                    # Login with the user created in scenario 1 of the same iteration
                    body = json.dumps({
                        "email": registered_email,
                        "password": "pass"
                    })
                else:
                    body = json.dumps({"title": "task"})

            start = time.perf_counter_ns()
            resp = client.open(
                sc["endpoint"],
                method=sc["method"],
                headers=headers,
                data=body,
                content_type="application/json"
            )
            elapsed = (time.perf_counter_ns() - start) / 1e6

            req_header_size = _safe_float(resp.headers.get("X-Request-Header-Size"))
            resp_body_size = _safe_float(
                resp.headers.get("X-Response-Body-Size"),
                float(len(resp.get_data()))
            )

            # For token-issuing endpoints, use the actually returned token for token metrics.
            if resp.is_json:
                data = resp.get_json(silent=True)
                if isinstance(data, dict):
                    issued_token = data.get("token")
                    if issued_token:
                        token_response = True
                        token_gen_ms = _safe_float(data.get("gen_time_ms"), token_gen_ms)
                        token_ver_ok, token_ver_ms = je.verify_token(name, cfg, keys, issued_token)
                        if not token_ver_ok:
                            raise RuntimeError(
                                f"Issued token verification failed for {name} in scenario {sc['id']}"
                            )
                        token_size = float(je.get_token_sizes(issued_token)["total_token_bytes"])

                        if PRINT_SIGNATURE_CHECKS and sc["name"] not in printed_labels:
                            print_token_signature_check(name, cfg, keys, issued_token, label=sc["name"])
                            printed_labels.add(sc["name"])

            if not warm:
                records.append({
                    "algorithm": name,
                    "scenario": sc["id"],
                    "status": resp.status_code,
                    "auth_scenario": bool(sc["auth"]),
                    "token_response": token_response,
                    "token_gen": token_gen_ms,
                    "token_ver": token_ver_ms,
                    "req_header_size": req_header_size,
                    "resp_body_size": resp_body_size,
                    "resp_time": elapsed,
                    "token_size": token_size,
                    "pub_key_bytes": pub_key_bytes,
                })

    return pd.DataFrame(records)


def _summarize_group(g: pd.DataFrame) -> pd.Series:
    token_gen_mean, token_gen_median, token_gen_std = _series_stats_nonzero(g["token_gen"])
    token_ver_mean, token_ver_median, token_ver_std = _series_stats_nonzero(g["token_ver"])

    token_sizes = g.loc[g["token_size"] > 0, "token_size"]
    req_headers_auth_only = g.loc[g["auth_scenario"], "req_header_size"]
    resp_bodies_token_only = g.loc[g["token_response"], "resp_body_size"]

    return pd.Series({
        "token_gen_mean": token_gen_mean,
        "token_gen_median": token_gen_median,
        "token_gen_std": token_gen_std,

        "token_ver_mean": token_ver_mean,
        "token_ver_median": token_ver_median,
        "token_ver_std": token_ver_std,

        # More meaningful size aggregates:
        # - authenticated requests only for request header
        # - token-issuing responses only for response body
        "req_header_mean": _mean_or_zero(req_headers_auth_only),
        "resp_body_mean": _mean_or_zero(resp_bodies_token_only),

        "resp_time_mean": float(g["resp_time"].mean()),
        "resp_time_median": float(g["resp_time"].median()),
        "resp_time_std": float(g["resp_time"].std()) if len(g) > 1 else 0.0,

        "token_size_mean": _mean_or_zero(token_sizes),
        "pub_key_bytes": int(g["pub_key_bytes"].iloc[0]),
    })


def run_all():
    dfs = []

    for name, cfg in ALGORITHMS.items():
        dfs.append(run_single_algorithm(name, cfg))

    for name, cfg in NESTED_CONFIGS.items():
        dfs.append(run_single_algorithm(name, cfg))

    df = pd.concat(dfs, ignore_index=True)
    os.makedirs("results", exist_ok=True)

    df.to_csv("results/raw_results.csv", index=False)
    # Keep the old filename too if anything else still references it.
    df.to_csv("results/raw.csv", index=False)

    summary = (
        df.groupby("algorithm", group_keys=False)
          .apply(_summarize_group)
          .reset_index()
    )

    summary.to_csv("results/summary.csv", index=False)
    print("Done.")


if __name__ == "__main__":
    run_all()
