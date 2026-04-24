"""
Algorithm registry and benchmark configuration.
"""

# ---------------------------------------------------------------------------
# Benchmark parameters
# ---------------------------------------------------------------------------

NUM_WARMUP = 5
NUM_MEASURED = 50

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
BASE_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"

# ---------------------------------------------------------------------------
# Algorithm definitions
# ---------------------------------------------------------------------------

ALGORITHMS = {
    # ── Pure PQC ──────────────────────────────────────────────────────────
    "ML-DSA-44": {
        "type": "oqs",
        "oqs_name": "ML-DSA-44",
        "openssl_name": "mldsa44",
        "security_level": 2,
        "category": "pqc",
    },
    "ML-DSA-65": {
        "type": "oqs",
        "oqs_name": "ML-DSA-65",
        "openssl_name": "mldsa65",
        "security_level": 3,
        "category": "pqc",
    },
    "ML-DSA-87": {
        "type": "oqs",
        "oqs_name": "ML-DSA-87",
        "openssl_name": "mldsa87",
        "security_level": 5,
        "category": "pqc",
    },
    "Falcon-512": {
        "type": "oqs",
        "oqs_name": "Falcon-512",
        "openssl_name": "falcon512",
        "security_level": 1,
        "category": "pqc",
    },
    "Falcon-1024": {
        "type": "oqs",
        "oqs_name": "Falcon-1024",
        "openssl_name": "falcon1024",
        "security_level": 5,
        "category": "pqc",
    },

    # ── Hybrid composite ──────────────────────────────────────────────────
    "P256+ML-DSA-44": {
        "type": "hybrid",
        "classical_curve": "P-256",
        "pqc_algo": "ML-DSA-44",
        "security_level": 2,
        "category": "hybrid",
    },
    "P256+Falcon-512": {
        "type": "hybrid",
        "classical_curve": "P-256",
        "pqc_algo": "Falcon-512",
        "security_level": 1,
        "category": "hybrid",
    },

    # ── Classical ─────────────────────────────────────────────────────────
    "ECDSA-P256": {
        "type": "classical_ec",
        "curve": "P-256",
        "security_level": 0,
        "category": "classical",
    },
    "RSA-2048": {
        "type": "classical_rsa",
        "key_size": 2048,
        "security_level": 0,
        "category": "classical",
    },
}

# ---------------------------------------------------------------------------
# Nested benchmark cases
# ---------------------------------------------------------------------------
# These are benchmark/runtime configurations, not JWT "alg" labels.
# The JWT itself is signaled as nested by the outer header's `cty: "JWT"`.

NESTED_CONFIGS = {
    "P256>>ML-DSA-44": {
        "type": "hybrid_nested",
        "inner_algo": "ECDSA-P256",
        "outer_algo": "ML-DSA-44",
        "security_level": 2,
        "category": "hybrid",
    },
    "P256>>Falcon-512": {
        "type": "hybrid_nested",
        "inner_algo": "ECDSA-P256",
        "outer_algo": "Falcon-512",
        "security_level": 1,
        "category": "hybrid",
    },
}

# ---------------------------------------------------------------------------
# JWT payload
# ---------------------------------------------------------------------------

JWT_PAYLOAD = {
    "iss": "https://auth.example.com",
    "sub": "248289761001",
    "aud": "https://api.example.com",
    "client_id": "task-manager-client",
    "iat": 1700000000,
    "nbf": 1700000000,
    "exp": 1700003600,
    "jti": "550e8400-e29b-41d4-a716-446655440000",
    "scope": "openid profile tasks.read tasks.write",
    "username": "jakub",
    "email": "jakub@example.com",
    "role": "user"
}

# ---------------------------------------------------------------------------
# Test scenarios
# ---------------------------------------------------------------------------

TEST_SCENARIOS = [
    {"id": 1, "name": "Register new user", "method": "POST", "endpoint": "/auth/register", "auth": False, "expect_status": 201},
    {"id": 2, "name": "Reject duplicate registration", "method": "POST", "endpoint": "/auth/register", "auth": False, "expect_status": 400},
    {"id": 3, "name": "Login with correct credentials", "method": "POST", "endpoint": "/auth/login", "auth": False, "expect_status": 200},
    {"id": 4, "name": "Reject login with wrong password", "method": "POST", "endpoint": "/auth/login-bad", "auth": False, "expect_status": 401},
    {"id": 5, "name": "Create a task", "method": "POST", "endpoint": "/tasks", "auth": True, "expect_status": 201},
    {"id": 6, "name": "Reject create task without auth", "method": "POST", "endpoint": "/tasks", "auth": False, "expect_status": 401},
    {"id": 7, "name": "Get tasks", "method": "GET", "endpoint": "/tasks", "auth": True, "expect_status": 200},
    {"id": 8, "name": "Reject get tasks", "method": "GET", "endpoint": "/tasks", "auth": False, "expect_status": 401},
    {"id": 9, "name": "Update a task", "method": "PUT", "endpoint": "/tasks/1", "auth": True, "expect_status": 200},
    {"id": 10, "name": "Reject update", "method": "PUT", "endpoint": "/tasks/1", "auth": False, "expect_status": 401},
    {"id": 11, "name": "Reject delete", "method": "DELETE", "endpoint": "/tasks/1", "auth": False, "expect_status": 401},
    {"id": 12, "name": "Delete a task", "method": "DELETE", "endpoint": "/tasks/1", "auth": True, "expect_status": 200},
]
