"""Tests for attestation creation and verification."""

import hashlib

from baip.identity import AgentIdentity
from baip.attestation import (
    create_attestation,
    verify_attestation,
    verify_attestation_payload,
)


class TestCreateAttestation:
    def test_create_from_string(self):
        agent = AgentIdentity.generate()
        att = create_attestation(agent, "hello world", "abc123i0")
        assert att["p"] == "baip"
        assert att["op"] == "attest"
        assert att["agent"] == "abc123i0"
        expected_hash = hashlib.sha256(b"hello world").hexdigest()
        assert att["payload_hash"] == expected_hash
        assert len(att["sig"]) == 128
        assert isinstance(att["ts"], int)

    def test_create_from_bytes(self):
        agent = AgentIdentity.generate()
        att = create_attestation(agent, b"\x00\x01\x02", "abc123i0")
        expected_hash = hashlib.sha256(b"\x00\x01\x02").hexdigest()
        assert att["payload_hash"] == expected_hash

    def test_custom_timestamp(self):
        agent = AgentIdentity.generate()
        att = create_attestation(agent, "test", "abc123i0", timestamp=1700000000)
        assert att["ts"] == 1700000000

    def test_timestamp_zero_preserved(self):
        agent = AgentIdentity.generate()
        att = create_attestation(agent, "test", "abc123i0", timestamp=0)
        assert att["ts"] == 0


class TestVerifyAttestation:
    def test_valid_attestation(self):
        agent = AgentIdentity.generate()
        att = create_attestation(agent, "analysis output", "abc123i0")
        assert verify_attestation(att, agent.pubkey_hex)

    def test_wrong_pubkey(self):
        agent = AgentIdentity.generate()
        other = AgentIdentity.generate()
        att = create_attestation(agent, "analysis output", "abc123i0")
        assert not verify_attestation(att, other.pubkey_hex)

    def test_tampered_payload_hash(self):
        agent = AgentIdentity.generate()
        att = create_attestation(agent, "analysis output", "abc123i0")
        att["payload_hash"] = "ff" * 32
        assert not verify_attestation(att, agent.pubkey_hex)

    def test_wrong_protocol(self):
        agent = AgentIdentity.generate()
        att = create_attestation(agent, "test", "abc123i0")
        att["p"] = "wrong"
        assert not verify_attestation(att, agent.pubkey_hex)

    def test_missing_fields(self):
        assert not verify_attestation({}, "02" + "aa" * 32)
        assert not verify_attestation({"p": "baip", "op": "attest"}, "02" + "aa" * 32)


class TestVerifyAttestationPayload:
    def test_valid_payload(self):
        agent = AgentIdentity.generate()
        payload = "BTC mempool: 45K unconfirmed"
        att = create_attestation(agent, payload, "abc123i0")
        assert verify_attestation_payload(att, agent.pubkey_hex, payload)

    def test_wrong_payload(self):
        agent = AgentIdentity.generate()
        att = create_attestation(agent, "original output", "abc123i0")
        assert not verify_attestation_payload(att, agent.pubkey_hex, "tampered output")

    def test_bytes_payload(self):
        agent = AgentIdentity.generate()
        data = b"\xde\xad\xbe\xef"
        att = create_attestation(agent, data, "abc123i0")
        assert verify_attestation_payload(att, agent.pubkey_hex, data)
