"""Tests for inscription building and ord CLI integration."""

import json

import pytest

from baip.identity import AgentIdentity
from baip.inscription import (
    create_register_inscription,
    create_update_inscription,
    create_attest_inscription_json,
    inscribe,
)
from baip.attestation import create_attestation


class TestCreateRegisterInscription:
    def test_produces_valid_json(self):
        agent = AgentIdentity.generate()
        json_str = create_register_inscription(
            agent, "TestBot", ["chain-analysis", "fee-estimation"],
            endpoints={"mcp": "https://example.com/mcp"},
        )
        doc = json.loads(json_str)
        assert doc["p"] == "baip"
        assert doc["op"] == "register"
        assert doc["name"] == "TestBot"
        assert len(doc["capabilities"]) == 2

    def test_minimal_inscription(self):
        agent = AgentIdentity.generate()
        json_str = create_register_inscription(agent, "Bot", ["cap1"])
        doc = json.loads(json_str)
        assert "endpoints" not in doc
        assert "controller" not in doc


class TestCreateUpdateInscription:
    def test_produces_signed_json(self):
        agent = AgentIdentity.generate()
        json_str = create_update_inscription(
            agent, "abc123i0", {"capabilities": ["new-cap"]}
        )
        doc = json.loads(json_str)
        assert doc["op"] == "update"
        assert doc["agent"] == "abc123i0"
        assert len(doc["sig"]) == 128


class TestCreateAttestInscriptionJson:
    def test_serializes_attestation(self):
        agent = AgentIdentity.generate()
        att = create_attestation(agent, "test output", "abc123i0")
        json_str = create_attest_inscription_json(att)
        doc = json.loads(json_str)
        assert doc["op"] == "attest"
        assert doc["payload_hash"] == att["payload_hash"]


class TestInscribeDryRun:
    def test_dry_run_returns_command(self):
        agent = AgentIdentity.generate()
        json_str = create_register_inscription(agent, "Bot", ["cap1"])
        result = inscribe(json_str, fee_rate=10, dry_run=True)
        assert "command" in result
        assert "ord" in result["command"][0]
        assert "--fee-rate" in result["command"]
        assert "10" in result["command"]
        assert result["content"] == json_str

    def test_dry_run_no_fee_rate(self):
        agent = AgentIdentity.generate()
        json_str = create_register_inscription(agent, "Bot", ["cap1"])
        result = inscribe(json_str, dry_run=True)
        assert "--fee-rate" not in result["command"]
