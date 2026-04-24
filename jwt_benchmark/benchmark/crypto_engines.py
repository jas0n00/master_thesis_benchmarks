"""
Cryptographic engines for key generation, signing, and verification.
Uses liboqs directly for PQC algorithms, and Python cryptography lib
(bound to system OpenSSL 3.5.0) for classical + hybrid.
"""

from dataclasses import dataclass
from typing import Optional, Tuple

# --- liboqs Python wrapper ---
# If you have the oqs-python package installed: pip install liboqs-python
try:
    import oqs
    HAS_OQS_PYTHON = True
except ImportError:
    HAS_OQS_PYTHON = False

from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Data Classes                                                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@dataclass
class KeyMaterial:
    """Holds key material for any algorithm."""
    algo_name: str
    algo_type: str  # "oqs", "classical_ec", "classical_rsa", "hybrid", "hybrid_nested"
    public_key_bytes: bytes = b""
    private_key_bytes: bytes = b""
    public_key_obj: object = None    # For classical: cryptography key object
    private_key_obj: object = None
    # For hybrid / nested hybrid
    classical_keys: Optional['KeyMaterial'] = None
    pqc_keys: Optional['KeyMaterial'] = None


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  OQS (PQC) Engine                                                      ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class OQSEngine:
    """PQC sign/verify via liboqs."""

    @staticmethod
    def generate_keypair(oqs_name: str) -> Tuple[bytes, bytes]:
        """Returns (public_key, private_key) as raw bytes."""
        if not HAS_OQS_PYTHON:
            raise RuntimeError("liboqs-python not installed. Run: pip install liboqs-python")
        signer = oqs.Signature(oqs_name)
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
        return bytes(public_key), bytes(private_key)

    @staticmethod
    def sign(oqs_name: str, private_key: bytes, message: bytes) -> bytes:
        signer = oqs.Signature(oqs_name, private_key)
        signature = signer.sign(message)
        return bytes(signature)

    @staticmethod
    def verify(oqs_name: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        verifier = oqs.Signature(oqs_name)
        return verifier.verify(message, signature, public_key)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Classical EC Engine (ECDSA P-256)                                     ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class ECDSAEngine:
    """ECDSA P-256 sign/verify via cryptography (OpenSSL backend)."""

    @staticmethod
    def generate_keypair():
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        priv_bytes = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        pub_bytes = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pub_bytes, priv_bytes, public_key, private_key

    @staticmethod
    def sign(private_key_obj, message: bytes) -> bytes:
        return private_key_obj.sign(message, ec.ECDSA(hashes.SHA256()))

    @staticmethod
    def verify(public_key_obj, message: bytes, signature: bytes) -> bool:
        try:
            public_key_obj.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Classical RSA Engine (RSA-2048)                                       ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class RSAEngine:
    """RSA-2048 with PKCS1v15 + SHA-256 (mimics RS256 in JWS)."""

    @staticmethod
    def generate_keypair(key_size: int = 2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        priv_bytes = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        pub_bytes = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pub_bytes, priv_bytes, public_key, private_key

    @staticmethod
    def sign(private_key_obj, message: bytes) -> bytes:
        return private_key_obj.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    @staticmethod
    def verify(public_key_obj, message: bytes, signature: bytes) -> bool:
        try:
            public_key_obj.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception:
            return False


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Hybrid Engine (P-256 + PQC concatenated signatures)                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class HybridEngine:
    """
    Composite hybrid signature: ECDSA-P256 signature || PQC signature.
    Verification requires BOTH signatures to be valid.

    Wire format:
      [4-byte big-endian length of ECDSA sig] [ECDSA sig] [PQC sig]
    """

    @staticmethod
    def sign(
        ec_private_key_obj,
        pqc_oqs_name: str,
        pqc_private_key: bytes,
        message: bytes,
    ) -> bytes:
        ec_sig = ECDSAEngine.sign(ec_private_key_obj, message)
        pqc_sig = OQSEngine.sign(pqc_oqs_name, pqc_private_key, message)
        ec_len = len(ec_sig).to_bytes(4, "big")
        return ec_len + ec_sig + pqc_sig

    @staticmethod
    def verify(
        ec_public_key_obj,
        pqc_oqs_name: str,
        pqc_public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        if len(signature) < 4:
            return False

        ec_len = int.from_bytes(signature[:4], "big")
        if len(signature) < 4 + ec_len:
            return False

        ec_sig = signature[4:4 + ec_len]
        pqc_sig = signature[4 + ec_len:]

        ec_ok = ECDSAEngine.verify(ec_public_key_obj, message, ec_sig)
        pqc_ok = OQSEngine.verify(pqc_oqs_name, pqc_public_key, message, pqc_sig)
        return ec_ok and pqc_ok


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Unified Key Generation                                                ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def generate_keys(algo_name: str, algo_config: dict) -> KeyMaterial:
    """Generate keys for any configured algorithm."""
    km = KeyMaterial(algo_name=algo_name, algo_type=algo_config["type"])

    if algo_config["type"] == "oqs":
        pub, priv = OQSEngine.generate_keypair(algo_config["oqs_name"])
        km.public_key_bytes = pub
        km.private_key_bytes = priv

    elif algo_config["type"] == "classical_ec":
        pub_b, priv_b, pub_obj, priv_obj = ECDSAEngine.generate_keypair()
        km.public_key_bytes = pub_b
        km.private_key_bytes = priv_b
        km.public_key_obj = pub_obj
        km.private_key_obj = priv_obj

    elif algo_config["type"] == "classical_rsa":
        pub_b, priv_b, pub_obj, priv_obj = RSAEngine.generate_keypair(
            algo_config["key_size"]
        )
        km.public_key_bytes = pub_b
        km.private_key_bytes = priv_b
        km.public_key_obj = pub_obj
        km.private_key_obj = priv_obj

    elif algo_config["type"] == "hybrid":
        from benchmark.config import ALGORITHMS

        # Classical part (P-256)
        ec_pub_b, ec_priv_b, ec_pub_obj, ec_priv_obj = ECDSAEngine.generate_keypair()
        km.classical_keys = KeyMaterial(
            algo_name="ECDSA-P256",
            algo_type="classical_ec",
            public_key_bytes=ec_pub_b,
            private_key_bytes=ec_priv_b,
            public_key_obj=ec_pub_obj,
            private_key_obj=ec_priv_obj,
        )

        # PQC part
        pqc_config = ALGORITHMS[algo_config["pqc_algo"]]
        pqc_pub, pqc_priv = OQSEngine.generate_keypair(pqc_config["oqs_name"])
        km.pqc_keys = KeyMaterial(
            algo_name=algo_config["pqc_algo"],
            algo_type="oqs",
            public_key_bytes=pqc_pub,
            private_key_bytes=pqc_priv,
        )

        # Combined key material size for reporting
        km.public_key_bytes = ec_pub_b + pqc_pub
        km.private_key_bytes = ec_priv_b + pqc_priv

    elif algo_config["type"] == "hybrid_nested":
        from benchmark.config import ALGORITHMS

        inner_algo_name = algo_config["inner_algo"]
        outer_algo_name = algo_config["outer_algo"]

        inner_config = ALGORITHMS[inner_algo_name]
        outer_config = ALGORITHMS[outer_algo_name]

        # Current nested design assumption:
        # inner = classical ECDSA, outer = PQC
        if inner_config["type"] != "classical_ec":
            raise ValueError(
                f"Nested hybrid inner algorithm must be classical_ec, got {inner_config['type']}"
            )
        if outer_config["type"] != "oqs":
            raise ValueError(
                f"Nested hybrid outer algorithm must be oqs, got {outer_config['type']}"
            )

        # Inner classical key
        ec_pub_b, ec_priv_b, ec_pub_obj, ec_priv_obj = ECDSAEngine.generate_keypair()
        km.classical_keys = KeyMaterial(
            algo_name=inner_algo_name,
            algo_type="classical_ec",
            public_key_bytes=ec_pub_b,
            private_key_bytes=ec_priv_b,
            public_key_obj=ec_pub_obj,
            private_key_obj=ec_priv_obj,
        )

        # Outer PQC key
        pqc_pub, pqc_priv = OQSEngine.generate_keypair(outer_config["oqs_name"])
        km.pqc_keys = KeyMaterial(
            algo_name=outer_algo_name,
            algo_type="oqs",
            public_key_bytes=pqc_pub,
            private_key_bytes=pqc_priv,
        )

        # Combined key material for reporting
        km.public_key_bytes = ec_pub_b + pqc_pub
        km.private_key_bytes = ec_priv_b + pqc_priv

    else:
        raise ValueError(f"Unsupported algorithm type: {algo_config['type']}")

    return km
