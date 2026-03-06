"""Tests for agent identity -- keygen, signing, verification."""

import hashlib

import pytest
from baip.identity import AgentIdentity


def h(msg: str | bytes) -> bytes:
    """SHA-256 hash helper for 32-byte messages."""
    if isinstance(msg, str):
        msg = msg.encode()
    return hashlib.sha256(msg).digest()


class TestKeygen:
    def test_generate_creates_valid_identity(self):
        agent = AgentIdentity.generate()
        assert len(agent.pubkey_hex) == 66
        assert agent.pubkey_hex[:2] in ("02", "03")
        assert len(agent.secret_hex) == 64

    def test_generate_unique_keys(self):
        a = AgentIdentity.generate()
        b = AgentIdentity.generate()
        assert a.pubkey_hex != b.pubkey_hex

    def test_from_hex_roundtrip(self):
        original = AgentIdentity.generate()
        restored = AgentIdentity.from_hex(original.secret_hex)
        assert restored.pubkey_hex == original.pubkey_hex

    def test_from_secret_wrong_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            AgentIdentity.from_secret(b"too short")

    def test_xonly_pubkey_is_32_bytes(self):
        agent = AgentIdentity.generate()
        assert len(agent.xonly_pubkey) == 32


class TestSigning:
    def test_sign_and_verify(self):
        agent = AgentIdentity.generate()
        msg = h("hello world")
        sig = agent.sign(msg)
        assert len(sig) == 64
        assert AgentIdentity.verify(msg, sig, agent.pubkey_hex)

    def test_sign_rejects_non_32_byte_message(self):
        agent = AgentIdentity.generate()
        with pytest.raises(ValueError, match="32 bytes"):
            agent.sign(b"short")

    def test_verify_wrong_message(self):
        agent = AgentIdentity.generate()
        sig = agent.sign(h("correct message"))
        assert not AgentIdentity.verify(h("wrong message"), sig, agent.pubkey_hex)

    def test_verify_wrong_pubkey(self):
        agent = AgentIdentity.generate()
        other = AgentIdentity.generate()
        msg = h("test")
        sig = agent.sign(msg)
        assert not AgentIdentity.verify(msg, sig, other.pubkey_hex)

    def test_verify_invalid_pubkey(self):
        agent = AgentIdentity.generate()
        msg = h("test")
        sig = agent.sign(msg)
        assert not AgentIdentity.verify(msg, sig, "ff" * 33)

    def test_verify_garbage_sig(self):
        agent = AgentIdentity.generate()
        assert not AgentIdentity.verify(h("test"), b"\x00" * 64, agent.pubkey_hex)

    def test_verify_wrong_length_message(self):
        assert not AgentIdentity.verify(b"short", b"\x00" * 64, "02" + "aa" * 32)


class TestRegisterJson:
    def test_valid_register(self):
        agent = AgentIdentity.generate()
        doc = agent.to_register_json(
            name="TestAgent",
            capabilities=["analysis"],
            endpoints={"mcp": "https://example.com"},
            controller="bc1qtest",
        )
        assert doc["p"] == "baip"
        assert doc["op"] == "register"
        assert doc["v"] == "1"
        assert doc["name"] == "TestAgent"
        assert doc["pubkey"] == agent.pubkey_hex
        assert doc["capabilities"] == ["analysis"]
        assert doc["endpoints"] == {"mcp": "https://example.com"}
        assert doc["controller"] == "bc1qtest"

    def test_register_no_optional_fields(self):
        agent = AgentIdentity.generate()
        doc = agent.to_register_json("Agent1", ["cap1"])
        assert "endpoints" not in doc
        assert "controller" not in doc

    def test_register_invalid_name(self):
        agent = AgentIdentity.generate()
        with pytest.raises(ValueError, match="Name must match"):
            agent.to_register_json("invalid name!", ["cap1"])

    def test_register_empty_capabilities(self):
        agent = AgentIdentity.generate()
        with pytest.raises(ValueError, match="At least one capability"):
            agent.to_register_json("Agent1", [])

    def test_register_name_with_hyphens_underscores(self):
        agent = AgentIdentity.generate()
        doc = agent.to_register_json("My-Agent_v2", ["cap1"])
        assert doc["name"] == "My-Agent_v2"


class TestUpdateAndRevoke:
    def test_sign_update(self):
        agent = AgentIdentity.generate()
        update = agent.sign_update("abc123i0", {"capabilities": ["new-cap"]})
        assert update["p"] == "baip"
        assert update["op"] == "update"
        assert update["agent"] == "abc123i0"
        assert len(update["sig"]) == 128  # 64 bytes hex

    def test_sign_revocation(self):
        agent = AgentIdentity.generate()
        revoke = agent.sign_revocation("abc123i0", "compromised")
        assert revoke["p"] == "baip"
        assert revoke["op"] == "revoke"
        assert revoke["reason"] == "compromised"
        assert len(revoke["sig"]) == 128
