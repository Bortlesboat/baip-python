"""Tests for agent resolution and state management."""

from baip.identity import AgentIdentity
from baip.resolver import (
    resolve_agent,
    validate_update,
    validate_revocation,
    get_current_state,
    get_agent_history,
)


def make_register(agent, name="TestAgent", caps=None):
    return agent.to_register_json(name, caps or ["analysis"])


class TestResolveAgent:
    def test_valid_register(self):
        agent = AgentIdentity.generate()
        reg = make_register(agent)
        result = resolve_agent(reg)
        assert result is not None
        assert result["name"] == "TestAgent"

    def test_wrong_protocol(self):
        agent = AgentIdentity.generate()
        reg = make_register(agent)
        reg["p"] = "brc-20"
        assert resolve_agent(reg) is None

    def test_wrong_op(self):
        agent = AgentIdentity.generate()
        reg = make_register(agent)
        reg["op"] = "update"
        assert resolve_agent(reg) is None

    def test_missing_name(self):
        reg = {"p": "baip", "op": "register", "v": "1",
               "pubkey": "02" + "aa" * 32, "capabilities": ["x"]}
        assert resolve_agent(reg) is None

    def test_empty_capabilities(self):
        agent = AgentIdentity.generate()
        reg = make_register(agent)
        reg["capabilities"] = []
        assert resolve_agent(reg) is None

    def test_bad_pubkey_length(self):
        reg = {"p": "baip", "op": "register", "v": "1",
               "name": "Test", "pubkey": "02abcd", "capabilities": ["x"]}
        assert resolve_agent(reg) is None


class TestValidateUpdate:
    def test_valid_update(self):
        agent = AgentIdentity.generate()
        update = agent.sign_update("abc123i0", {"capabilities": ["new"]})
        assert validate_update(update, agent.pubkey_hex)

    def test_wrong_signer(self):
        agent = AgentIdentity.generate()
        other = AgentIdentity.generate()
        update = agent.sign_update("abc123i0", {"capabilities": ["new"]})
        assert not validate_update(update, other.pubkey_hex)

    def test_tampered_fields(self):
        agent = AgentIdentity.generate()
        update = agent.sign_update("abc123i0", {"capabilities": ["new"]})
        update["fields"]["capabilities"] = ["tampered"]
        assert not validate_update(update, agent.pubkey_hex)


class TestValidateRevocation:
    def test_valid_revocation(self):
        agent = AgentIdentity.generate()
        revoke = agent.sign_revocation("abc123i0", "compromised")
        assert validate_revocation(revoke, agent.pubkey_hex)

    def test_wrong_signer(self):
        agent = AgentIdentity.generate()
        other = AgentIdentity.generate()
        revoke = agent.sign_revocation("abc123i0", "compromised")
        assert not validate_revocation(revoke, other.pubkey_hex)

    def test_tampered_reason(self):
        agent = AgentIdentity.generate()
        revoke = agent.sign_revocation("abc123i0", "compromised")
        revoke["reason"] = "stolen"
        assert not validate_revocation(revoke, agent.pubkey_hex)


class TestGetCurrentState:
    def test_no_updates(self):
        agent = AgentIdentity.generate()
        reg = make_register(agent)
        state = get_current_state(reg, [])
        assert state["name"] == "TestAgent"
        assert state["capabilities"] == ["analysis"]

    def test_capability_update(self):
        agent = AgentIdentity.generate()
        reg = make_register(agent)
        update = agent.sign_update("abc123i0", {"capabilities": ["trading", "analysis"]})
        state = get_current_state(reg, [update])
        assert state["capabilities"] == ["trading", "analysis"]

    def test_key_rotation(self):
        agent = AgentIdentity.generate()
        new_agent = AgentIdentity.generate()
        reg = make_register(agent)

        # Rotate key
        update1 = agent.sign_update("abc123i0", {"pubkey": new_agent.pubkey_hex})
        state = get_current_state(reg, [update1])
        assert state["pubkey"] == new_agent.pubkey_hex

    def test_update_after_key_rotation_uses_new_key(self):
        agent = AgentIdentity.generate()
        new_agent = AgentIdentity.generate()
        reg = make_register(agent)

        # Rotate key
        update1 = agent.sign_update("abc123i0", {"pubkey": new_agent.pubkey_hex})
        # Update with new key
        update2 = new_agent.sign_update("abc123i0", {"name": "RenamedAgent"})

        state = get_current_state(reg, [update1, update2])
        assert state["name"] == "RenamedAgent"
        assert state["pubkey"] == new_agent.pubkey_hex

    def test_update_with_old_key_after_rotation_rejected(self):
        agent = AgentIdentity.generate()
        new_agent = AgentIdentity.generate()
        reg = make_register(agent)

        update1 = agent.sign_update("abc123i0", {"pubkey": new_agent.pubkey_hex})
        # Try to update with OLD key -- should be ignored
        update2 = agent.sign_update("abc123i0", {"name": "Hacked"})

        state = get_current_state(reg, [update1, update2])
        assert state["name"] == "TestAgent"  # Not changed

    def test_revocation_returns_none(self):
        agent = AgentIdentity.generate()
        reg = make_register(agent)
        revoke = agent.sign_revocation("abc123i0", "compromised")
        state = get_current_state(reg, [], [revoke])
        assert state is None


class TestGetAgentHistory:
    def test_history_with_updates(self):
        agent = AgentIdentity.generate()
        reg = make_register(agent)
        update = agent.sign_update("abc123i0", {"capabilities": ["new"]})

        history = get_agent_history(reg, [update])
        assert len(history) == 2
        assert history[0]["op"] == "register"
        assert history[0]["valid"] is True
        assert history[1]["op"] == "update"
        assert history[1]["valid"] is True

    def test_history_invalid_update(self):
        agent = AgentIdentity.generate()
        other = AgentIdentity.generate()
        reg = make_register(agent)
        # Signed by wrong key
        bad_update = other.sign_update("abc123i0", {"name": "Hacked"})

        history = get_agent_history(reg, [bad_update])
        assert history[1]["valid"] is False
