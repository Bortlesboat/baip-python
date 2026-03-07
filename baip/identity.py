"""Agent identity management -- keygen, signing, verification."""

import hashlib
import json
import os
import re

from coincurve import PrivateKey, PublicKey
import coincurve._libsecp256k1 as _secp

_ffi = _secp.ffi
_lib = _secp.lib

NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


# --- Tagged hashing (BIP-340 domain separation) ---

def tagged_hash(tag: str, msg: bytes) -> bytes:
    """BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


# --- Canonical message builders (single source of truth) ---

def canonical_update_msg(agent_id: str, fields: dict) -> bytes:
    """Build the canonical bytes for an update signature."""
    sorted_fields = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    raw = f"baip:update:{agent_id}:{sorted_fields}".encode()
    return tagged_hash("BAIP/update", raw)


def canonical_revoke_msg(agent_id: str, reason: str) -> bytes:
    """Build the canonical bytes for a revocation signature."""
    raw = f"baip:revoke:{agent_id}:{reason}".encode()
    return tagged_hash("BAIP/revoke", raw)


def canonical_attest_msg(payload_hash: bytes) -> bytes:
    """Build the canonical bytes for an attestation signature."""
    return tagged_hash("BAIP/attest", payload_hash)


class AgentIdentity:
    """A BAIP agent identity backed by a secp256k1 keypair."""

    def __init__(self, private_key: PrivateKey):
        self._privkey = private_key
        self._pubkey = private_key.public_key

    @classmethod
    def generate(cls) -> "AgentIdentity":
        """Generate a new random agent identity."""
        privkey = PrivateKey(os.urandom(32))
        return cls(privkey)

    @classmethod
    def from_secret(cls, secret: bytes) -> "AgentIdentity":
        """Load identity from a 32-byte secret."""
        if len(secret) != 32:
            raise ValueError("Secret must be exactly 32 bytes")
        return cls(PrivateKey(secret))

    @classmethod
    def from_hex(cls, hex_secret: str) -> "AgentIdentity":
        """Load identity from a hex-encoded 32-byte secret."""
        return cls.from_secret(bytes.fromhex(hex_secret))

    @property
    def pubkey_hex(self) -> str:
        """Compressed public key as hex string (66 chars)."""
        return self._pubkey.format(compressed=True).hex()

    @property
    def secret_hex(self) -> str:
        """Private key as hex string. Keep this secret."""
        return self._privkey.secret.hex()

    @property
    def xonly_pubkey(self) -> bytes:
        """X-only public key (32 bytes) for BIP-340 Schnorr."""
        compressed = self._pubkey.format(compressed=True)
        return compressed[1:]  # Drop the 02/03 prefix

    def sign(self, message: bytes) -> bytes:
        """Create a Schnorr signature (BIP-340) over a 32-byte message hash.

        The message MUST be exactly 32 bytes (e.g., a tagged hash digest).
        """
        if len(message) != 32:
            raise ValueError("Message must be exactly 32 bytes (use tagged_hash)")
        return self._privkey.sign_schnorr(message)

    @staticmethod
    def verify(message: bytes, signature: bytes, pubkey_hex: str) -> bool:
        """Verify a BIP-340 Schnorr signature against a compressed pubkey.

        Uses the low-level libsecp256k1 FFI since coincurve's PublicKey
        doesn't expose verify_schnorr.
        """
        if len(message) != 32 or len(signature) != 64:
            return False
        try:
            pub_bytes = bytes.fromhex(pubkey_hex)
            if len(pub_bytes) != 33:
                return False
            xonly = pub_bytes[1:]

            sig_buf = _ffi.new("unsigned char[64]", signature)
            msg_buf = _ffi.new("unsigned char[32]", message)
            xonly_pk = _ffi.new("secp256k1_xonly_pubkey *")

            rc = _lib.secp256k1_xonly_pubkey_parse(
                _lib.secp256k1_context_static, xonly_pk, xonly
            )
            if rc != 1:
                return False

            rc = _lib.secp256k1_schnorrsig_verify(
                _lib.secp256k1_context_static, sig_buf, msg_buf, 32, xonly_pk
            )
            return rc == 1
        except Exception:
            return False

    def to_register_json(
        self,
        name: str,
        capabilities: list[str],
        endpoints: dict[str, str] | None = None,
        controller: str | None = None,
    ) -> dict:
        """Produce a BAIP register inscription JSON object."""
        if not NAME_PATTERN.match(name):
            raise ValueError(
                f"Name must match {NAME_PATTERN.pattern}, got: {name!r}"
            )
        if not capabilities:
            raise ValueError("At least one capability is required")

        doc = {
            "p": "baip",
            "op": "register",
            "v": "1",
            "name": name,
            "pubkey": self.pubkey_hex,
            "capabilities": capabilities,
        }
        if endpoints:
            doc["endpoints"] = endpoints
        if controller:
            doc["controller"] = controller
        return doc

    def sign_update(self, agent_id: str, fields: dict) -> dict:
        """Create a signed update inscription JSON."""
        msg_hash = canonical_update_msg(agent_id, fields)
        sig = self.sign(msg_hash)

        return {
            "p": "baip",
            "op": "update",
            "agent": agent_id,
            "fields": fields,
            "sig": sig.hex(),
        }

    def sign_revocation(self, agent_id: str, reason: str) -> dict:
        """Create a signed revocation inscription JSON."""
        msg_hash = canonical_revoke_msg(agent_id, reason)
        sig = self.sign(msg_hash)

        return {
            "p": "baip",
            "op": "revoke",
            "agent": agent_id,
            "reason": reason,
            "sig": sig.hex(),
        }
