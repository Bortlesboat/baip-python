"""Resolve agent identity from inscription data."""

import hashlib
import json

from baip.identity import AgentIdentity


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

    sorted_fields = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    canonical = f"baip:update:{agent_id}:{sorted_fields}"
    msg_hash = hashlib.sha256(canonical.encode()).digest()

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

    canonical = f"baip:revoke:{agent_id}:{reason}"
    msg_hash = hashlib.sha256(canonical.encode()).digest()

    return AgentIdentity.verify(msg_hash, sig, current_pubkey)


def get_current_state(
    register_data: dict,
    updates: list[dict],
    revocations: list[dict] | None = None,
) -> dict | None:
    """Apply updates to a register inscription to get current agent state.

    Args:
        register_data: The parsed register inscription.
        updates: List of update inscriptions, ordered by inscription number.
        revocations: List of revocation inscriptions, ordered by inscription number.

    Returns:
        Current agent state dict, or None if revoked.
    """
    agent = resolve_agent(register_data)
    if agent is None:
        return None

    current_pubkey = agent["pubkey"]
    state = dict(agent)

    # Interleave updates and revocations by their position in the list
    # (caller must provide them in inscription-number order)
    all_ops = []
    for u in updates:
        all_ops.append(("update", u))
    for r in (revocations or []):
        all_ops.append(("revoke", r))

    for op_type, op_data in all_ops:
        if op_type == "revoke":
            if validate_revocation(op_data, current_pubkey):
                return None  # Agent is revoked
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
    updates: list[dict],
    revocations: list[dict] | None = None,
) -> list[dict]:
    """Return the full history of valid operations for an agent.

    Returns list of dicts with 'op', 'data', and 'valid' fields.
    """
    agent = resolve_agent(register_data)
    if agent is None:
        return []

    current_pubkey = agent["pubkey"]
    history = [{"op": "register", "data": register_data, "valid": True}]

    for u in updates:
        valid = validate_update(u, current_pubkey)
        history.append({"op": "update", "data": u, "valid": valid})
        if valid and "pubkey" in u.get("fields", {}):
            current_pubkey = u["fields"]["pubkey"]

    for r in (revocations or []):
        valid = validate_revocation(r, current_pubkey)
        history.append({"op": "revoke", "data": r, "valid": valid})

    return history
