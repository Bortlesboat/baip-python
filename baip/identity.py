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

        The message MUST be exactly 32 bytes (e.g., SHA-256 digest).
        """
        if len(message) != 32:
            raise ValueError("Message must be exactly 32 bytes (use SHA-256 hash)")
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
            # Parse compressed pubkey to get x-only (32 bytes)
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
        sorted_fields = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        canonical = f"baip:update:{agent_id}:{sorted_fields}"
        msg_hash = hashlib.sha256(canonical.encode()).digest()
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
        canonical = f"baip:revoke:{agent_id}:{reason}"
        msg_hash = hashlib.sha256(canonical.encode()).digest()
        sig = self.sign(msg_hash)

        return {
            "p": "baip",
            "op": "revoke",
            "agent": agent_id,
            "reason": reason,
            "sig": sig.hex(),
        }
