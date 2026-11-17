"""Ed25519 document signing, one key pair per publisher.

Signs the same bytes as signing_hmac.py (signed_message), so HMAC and Ed25519
results compare like for like.
"""

import hashlib
import hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from signing_hmac import load_key, signed_message

SAME_ORGANISATION = {"icscert": "CISA", "mitre": "MITRE"}


def private_key_for(publisher: str) -> Ed25519PrivateKey:
    """Derive a fixed Ed25519 key for one publisher from SECRET_KEY."""
    seed = hmac.new(load_key(), b"ed25519:" + publisher.encode("utf-8"), hashlib.sha256).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def publisher_of(doc: dict) -> str:
    """The organisation whose key signs this document."""
    source = doc["source"]
    if source == "CISA-CSAF":
        return "CISA"
    if source.startswith("MITRE-ATT&CK"):
        return "MITRE"
    if source == "CVE-List-V5":
        cna = doc["fields"]["cna"]
        return SAME_ORGANISATION.get(cna, cna)
    raise ValueError(f"unknown source: {source}")


def sign(doc: dict, private_key: Ed25519PrivateKey) -> str:
    """Return the Ed25519 signature (hex) of a document."""
    return private_key.sign(signed_message(doc)).hex()


def verify(doc: dict, public_key: Ed25519PublicKey) -> bool:
    """True only if the document carries a signature that matches its content."""
    signature = doc.get("signature")
    if not signature:
        return False
    try:
        public_key.verify(bytes.fromhex(signature), signed_message(doc))
        return True
    except InvalidSignature, ValueError:
        return False
