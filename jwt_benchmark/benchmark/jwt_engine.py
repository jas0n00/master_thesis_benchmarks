"""
JWS (JSON Web Signature) Compact Serialization engine.
Builds real JWT tokens: BASE64URL(header).BASE64URL(payload).BASE64URL(signature)

Supports:
  - classical compact JWS
  - PQC compact JWS
  - composite hybrid compact JWS
  - nested hybrid compact JWS

Token generation and verification follow the formulas from the reference paper:
  Signature = Sign(EncodeToken(Header+Payload), PrivateKey)
  TokenGenTime = T_encode_key + T_encode_token + T_sign + T_decode
  TokenVerTime = T_encode_pubkey + T_encode_sig + T_retrieve + T_verify
"""

import base64
import json
import time
from typing import Any, Optional, Tuple

from benchmark.config import ALGORITHMS, JWT_PAYLOAD
from benchmark.crypto_engines import (
    KeyMaterial, OQSEngine, ECDSAEngine, RSAEngine, HybridEngine
)


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode('ascii'))


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  JWS Algorithm Identifiers (for the JWT header "alg" field)            ║
# ║  Using draft / experimental identifiers where IANA hasn't registered   ║
# ║  them yet.                                                             ║
# ╚══════════════════════════════════════════════════════════════════════════╝

JWS_ALG_MAP = {
    "ML-DSA-44":       "MLDSA44",
    "ML-DSA-65":       "MLDSA65",
    "ML-DSA-87":       "MLDSA87",
    "Falcon-512":      "FALCON512",
    "Falcon-1024":     "FALCON1024",
    "P256+ML-DSA-44":  "P256-MLDSA44",   # composite compact hybrid
    "P256+Falcon-512": "P256-FALCON512", # composite compact hybrid
    "ECDSA-P256":      "ES256",
    "RSA-2048":        "RS256",
}


def _build_header(algo_name: str, *, cty: Optional[str] = None) -> dict:
    header = {
        "alg": JWS_ALG_MAP.get(algo_name, algo_name),
        "typ": "JWT",
    }
    if cty is not None:
        header["cty"] = cty
    return header


def _json_compact_b64(value: Any) -> str:
    return _b64url_encode(
        json.dumps(value, separators=(',', ':')).encode('utf-8')
    )


def _payload_to_b64(payload: Any) -> str:
    """
    Encode payload for JWS Compact Serialization.

    Regular JWT payloads are JSON objects.
    Nested outer payload is the raw inner JWT string, encoded as a JSON string so
    the compact JWS remains valid JSON-based JWS while carrying the full inner JWT.
    """
    if isinstance(payload, str):
        return _json_compact_b64(payload)
    return _json_compact_b64(payload)


def _decode_json_segment(segment_b64: str) -> Any:
    return json.loads(_b64url_decode(segment_b64).decode('utf-8'))


def _sign_bytes(algo_name: str, algo_config: dict, keys: KeyMaterial, signing_input: bytes) -> bytes:
    """Sign raw JWS signing input for any non-nested algorithm."""
    if algo_config["type"] == "oqs":
        return OQSEngine.sign(
            algo_config["oqs_name"], keys.private_key_bytes, signing_input
        )

    if algo_config["type"] == "classical_ec":
        return ECDSAEngine.sign(keys.private_key_obj, signing_input)

    if algo_config["type"] == "classical_rsa":
        return RSAEngine.sign(keys.private_key_obj, signing_input)

    if algo_config["type"] == "hybrid":
        pqc_config = ALGORITHMS[algo_config["pqc_algo"]]
        return HybridEngine.sign(
            keys.classical_keys.private_key_obj,
            pqc_config["oqs_name"],
            keys.pqc_keys.private_key_bytes,
            signing_input,
        )

    raise ValueError(f"Unsupported signing type: {algo_config['type']}")


def _verify_bytes(
    algo_name: str,
    algo_config: dict,
    keys: KeyMaterial,
    signing_input: bytes,
    sig_bytes: bytes,
) -> bool:
    """Verify raw JWS signing input for any non-nested algorithm."""
    if algo_config["type"] == "oqs":
        return OQSEngine.verify(
            algo_config["oqs_name"], keys.public_key_bytes, signing_input, sig_bytes
        )

    if algo_config["type"] == "classical_ec":
        return ECDSAEngine.verify(keys.public_key_obj, signing_input, sig_bytes)

    if algo_config["type"] == "classical_rsa":
        return RSAEngine.verify(keys.public_key_obj, signing_input, sig_bytes)

    if algo_config["type"] == "hybrid":
        pqc_config = ALGORITHMS[algo_config["pqc_algo"]]
        return HybridEngine.verify(
            keys.classical_keys.public_key_obj,
            pqc_config["oqs_name"],
            keys.pqc_keys.public_key_bytes,
            signing_input,
            sig_bytes,
        )

    raise ValueError(f"Unsupported verification type: {algo_config['type']}")


def _generate_compact_jws(
    algo_name: str,
    algo_config: dict,
    keys: KeyMaterial,
    payload: Any,
    *,
    cty: Optional[str] = None,
) -> str:
    """Generate a compact JWS for any non-nested algorithm."""
    header = _build_header(algo_name, cty=cty)

    header_b64 = _json_compact_b64(header)
    payload_b64 = _payload_to_b64(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode('ascii')

    sig_bytes = _sign_bytes(algo_name, algo_config, keys, signing_input)
    sig_b64 = _b64url_encode(sig_bytes)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _verify_compact_jws(
    algo_name: str,
    algo_config: dict,
    keys: KeyMaterial,
    token: str,
) -> bool:
    """Verify a normal compact JWS for any non-nested algorithm."""
    parts = token.split('.')
    if len(parts) != 3:
        return False

    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode('ascii')
    sig_bytes = _b64url_decode(sig_b64)

    return _verify_bytes(algo_name, algo_config, keys, signing_input, sig_bytes)


def generate_token(
    algo_name: str,
    algo_config: dict,
    keys: KeyMaterial,
    payload: dict = None,
) -> Tuple[str, float]:
    """
    Generate a JWS Compact Serialization token.

    For hybrid_nested:
      - inner token is signed with inner_algo
      - outer token payload is the complete inner JWS string
      - outer token header sets cty="JWT"
      - the outer header uses only the outer PQC alg identifier; no special nested label

    Returns: (token_string, generation_time_ms)
    """
    if payload is None:
        payload = JWT_PAYLOAD

    start = time.perf_counter_ns()

    if algo_config["type"] == "hybrid_nested":
        inner_algo_name = algo_config["inner_algo"]
        outer_algo_name = algo_config["outer_algo"]

        inner_config = ALGORITHMS[inner_algo_name]
        outer_config = ALGORITHMS[outer_algo_name]

        inner_keys = keys.classical_keys
        outer_keys = keys.pqc_keys

        if inner_keys is None or outer_keys is None:
            raise ValueError("Nested hybrid keys are incomplete: missing inner or outer key material")

        inner_token = _generate_compact_jws(
            inner_algo_name,
            inner_config,
            inner_keys,
            payload,
        )

        token = _generate_compact_jws(
            outer_algo_name,
            outer_config,
            outer_keys,
            inner_token,
            cty="JWT",
        )
    else:
        token = _generate_compact_jws(algo_name, algo_config, keys, payload)

    elapsed_ns = time.perf_counter_ns() - start
    elapsed_ms = elapsed_ns / 1_000_000

    return token, elapsed_ms


def verify_token(
    algo_name: str,
    algo_config: dict,
    keys: KeyMaterial,
    token: str,
) -> Tuple[bool, float]:
    """
    Verify a JWS Compact Serialization token.

    For hybrid_nested:
      1. parse and verify the outer token using the outer PQC algorithm
      2. require outer header cty == "JWT"
      3. decode the outer payload as the inner JWT string
      4. verify the inner JWT independently with the classical key

    Returns: (is_valid, verification_time_ms)
    """
    start = time.perf_counter_ns()

    if algo_config["type"] == "hybrid_nested":
        outer_algo_name = algo_config["outer_algo"]
        inner_algo_name = algo_config["inner_algo"]

        outer_config = ALGORITHMS[outer_algo_name]
        inner_config = ALGORITHMS[inner_algo_name]

        outer_keys = keys.pqc_keys
        inner_keys = keys.classical_keys

        if inner_keys is None or outer_keys is None:
            elapsed_ns = time.perf_counter_ns() - start
            return False, elapsed_ns / 1_000_000

        parts = token.split('.')
        if len(parts) != 3:
            elapsed_ns = time.perf_counter_ns() - start
            return False, elapsed_ns / 1_000_000

        header_b64, outer_payload_b64, _ = parts

        try:
            outer_header = _decode_json_segment(header_b64)
        except Exception:
            elapsed_ns = time.perf_counter_ns() - start
            return False, elapsed_ns / 1_000_000

        outer_valid = _verify_compact_jws(
            outer_algo_name,
            outer_config,
            outer_keys,
            token,
        )
        if not outer_valid:
            elapsed_ns = time.perf_counter_ns() - start
            return False, elapsed_ns / 1_000_000

        if outer_header.get("cty") != "JWT":
            elapsed_ns = time.perf_counter_ns() - start
            return False, elapsed_ns / 1_000_000

        try:
            nested_jws = _decode_json_segment(outer_payload_b64)
        except Exception:
            elapsed_ns = time.perf_counter_ns() - start
            return False, elapsed_ns / 1_000_000

        if not isinstance(nested_jws, str):
            elapsed_ns = time.perf_counter_ns() - start
            return False, elapsed_ns / 1_000_000

        is_valid = _verify_compact_jws(
            inner_algo_name,
            inner_config,
            inner_keys,
            nested_jws,
        )
    else:
        is_valid = _verify_compact_jws(algo_name, algo_config, keys, token)

    elapsed_ns = time.perf_counter_ns() - start
    elapsed_ms = elapsed_ns / 1_000_000

    return is_valid, elapsed_ms


def get_token_sizes(token: str) -> dict:
    """Compute outer compact JWS component sizes."""
    parts = token.split('.')
    if len(parts) != 3:
        return {
            "header_b64_bytes": 0,
            "payload_b64_bytes": 0,
            "signature_b64_bytes": 0,
            "total_token_bytes": len(token),
        }

    header_b64, payload_b64, sig_b64 = parts
    return {
        "header_b64_bytes": len(header_b64),
        "payload_b64_bytes": len(payload_b64),
        "signature_b64_bytes": len(sig_b64),
        "total_token_bytes": len(token),
    }
