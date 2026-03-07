"""Resolve agent identity from inscription data."""

import copy

from baip.identity import (
    AgentIdentity,
    canonical_attest_msg,
    canonical_revoke_msg,
    canonical_update_msg,
)


def resolve_agent(inscription_data: dict) -> dict | None:
    """Parse and validate a register inscription.

    Args:
        inscription_data: Parsed JSON from an inscription.

    Returns:
        The register data if valid, None otherwise.
    """
    if inscription_data.get("p") != "baip":
        return None
    if inscription_data.get("op") != "register":
        return None
    if inscription_data.get("v") != "1":
        return None

    required = ["name", "pubkey", "capabilities"]
    for field in required:
        if field not in inscription_data:
            return None

    if not isinstance(inscription_data["capabilities"], list):
        return None
    if len(inscription_data["capabilities"]) == 0:
        return None
    if len(inscription_data["pubkey"]) != 66:
        return None

    return inscription_data


def validate_update(update_data: dict, current_pubkey: str) -> bool:
    """Validate an update inscription's signature.

    Args:
        update_data: Parsed JSON of the update inscription.
        current_pubkey: The agent's current pubkey hex.

    Returns:
        True if the update signature is valid.
    """
    if update_data.get("p") != "baip" or update_data.get("op") != "update":
        return False

    try:
        agent_id = update_data["agent"]
        fields = update_data["fields"]
        sig = bytes.fromhex(update_data["sig"])
    except (KeyError, ValueError):
        return False

    msg_hash = canonical_update_msg(agent_id, fields)
    return AgentIdentity.verify(msg_hash, sig, current_pubkey)


def validate_revocation(revoke_data: dict, current_pubkey: str) -> bool:
    """Validate a revocation inscription's signature."""
    if revoke_data.get("p") != "baip" or revoke_data.get("op") != "revoke":
        return False

    try:
        agent_id = revoke_data["agent"]
        reason = revoke_data["reason"]
        sig = bytes.fromhex(revoke_data["sig"])
    except (KeyError, ValueError):
        return False

    msg_hash = canonical_revoke_msg(agent_id, reason)
    return AgentIdentity.verify(msg_hash, sig, current_pubkey)


def get_current_state(
    register_data: dict,
    ops: list[dict],
) -> dict | None:
    """Apply operations to a register inscription to get current agent state.

    Args:
        register_data: The parsed register inscription.
        ops: List of update/revoke inscriptions, ordered by inscription number.
            Each must have an "op" field ("update" or "revoke").

    Returns:
        Current agent state dict, or None if revoked.
    """
    agent = resolve_agent(register_data)
    if agent is None:
        return None

    state = copy.deepcopy(agent)
    current_pubkey = state["pubkey"]

    for op_data in ops:
        op_type = op_data.get("op")
        if op_type == "revoke":
            if validate_revocation(op_data, current_pubkey):
                return None
        elif op_type == "update":
            if validate_update(op_data, current_pubkey):
                fields = op_data["fields"]
                for key, value in fields.items():
                    if key in ("pubkey", "capabilities", "endpoints", "name"):
                        state[key] = value
                if "pubkey" in fields:
                    current_pubkey = fields["pubkey"]

    return state


def get_agent_history(
    register_data: dict,
    ops: list[dict],
) -> list[dict]:
    """Return the full history of valid operations for an agent.

    Args:
        register_data: The parsed register inscription.
        ops: List of update/revoke inscriptions, ordered by inscription number.

    Returns:
        List of dicts with 'op', 'data', and 'valid' fields.
    """
    agent = resolve_agent(register_data)
    if agent is None:
        return []

    current_pubkey = agent["pubkey"]
    history = [{"op": "register", "data": register_data, "valid": True}]

    for op_data in ops:
        op_type = op_data.get("op")
        if op_type == "update":
            valid = validate_update(op_data, current_pubkey)
            history.append({"op": "update", "data": op_data, "valid": valid})
            if valid and "pubkey" in op_data.get("fields", {}):
                current_pubkey = op_data["fields"]["pubkey"]
        elif op_type == "revoke":
            valid = validate_revocation(op_data, current_pubkey)
            history.append({"op": "revoke", "data": op_data, "valid": valid})

    return history
