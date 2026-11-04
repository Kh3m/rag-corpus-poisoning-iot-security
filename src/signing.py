"""HMAC-SHA256 document signing for the Phase 4 evaluation.

The signature covers a document's id, source, title, source URL and text,
as canonical JSON after NFC normalisation and whitespace collapsing, so
changing any of them breaks it and the same document always gives the
same bytes. One shared secret (SECRET_KEY in .env) models one trusted signer.
"""

import hashlib
import hmac
import json
import os
import unicodedata

from dotenv import load_dotenv

SIGNED_FIELDS = ["id", "source", "title", "source_url", "text"]


def load_key() -> bytes:
    """Read the signing secret from .env."""
    load_dotenv()
    key = os.environ.get("SECRET_KEY")
    if not key:
        raise RuntimeError("SECRET_KEY is missing from .env")
    return key.encode("utf-8")


def normalize(value: str) -> str:
    """NFC-normalise and collapse whitespace, so equal text gives equal bytes."""
    return " ".join(unicodedata.normalize("NFC", value).split())


def signed_message(doc: dict) -> bytes:
    """The exact bytes that get signed for this document."""
    payload = {field: normalize(doc[field]) for field in SIGNED_FIELDS}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sign(doc: dict, key: bytes) -> str:
    """Return the HMAC-SHA256 signature (hex) of a document."""
    return hmac.new(key, signed_message(doc), hashlib.sha256).hexdigest()


def verify(doc: dict, key: bytes) -> bool:
    """True only if the document carries a signature that matches its content."""
    signature = doc.get("signature")
    if not signature:
        return False
    return hmac.compare_digest(sign(doc, key), signature)