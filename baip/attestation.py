"""Create and verify signed attestations for agent outputs."""

import hashlib
import time

from baip.identity import AgentIdentity, canonical_attest_msg


def create_attestation(
    identity: AgentIdentity,
    payload: bytes | str,
    agent_inscription_id: str,
    timestamp: int | None = None,
) -> dict:
    """Create a signed attestation over a payload.

    Args:
        identity: The agent's identity (must hold private key).
        payload: The output to attest. Strings are UTF-8 encoded.
        agent_inscription_id: The inscription ID of the agent's register op.
        timestamp: Optional unix timestamp. Defaults to current time.

    Returns:
        BAIP attest JSON object with signature.
    """
    if isinstance(payload, str):
        payload = payload.encode()

    payload_hash = hashlib.sha256(payload).digest()
    msg = canonical_attest_msg(payload_hash)
    sig = identity.sign(msg)

    return {
        "p": "baip",
        "op": "attest",
        "agent": agent_inscription_id,
        "payload_hash": payload_hash.hex(),
        "sig": sig.hex(),
        "ts": timestamp if timestamp is not None else int(time.time()),
    }


def verify_attestation(attestation: dict, pubkey_hex: str) -> bool:
    """Verify an attestation signature against a known pubkey.

    Args:
        attestation: A BAIP attest JSON object.
        pubkey_hex: The agent's compressed pubkey (from resolved identity).

    Returns:
        True if signature is valid.
    """
    if attestation.get("p") != "baip" or attestation.get("op") != "attest":
        return False

    try:
        payload_hash = bytes.fromhex(attestation["payload_hash"])
        sig = bytes.fromhex(attestation["sig"])
    except (KeyError, ValueError):
        return False

    msg = canonical_attest_msg(payload_hash)
    return AgentIdentity.verify(msg, sig, pubkey_hex)


def verify_attestation_payload(
    attestation: dict, pubkey_hex: str, payload: bytes | str
) -> bool:
    """Verify attestation signature AND that payload_hash matches the given payload.

    Args:
        attestation: A BAIP attest JSON object.
        pubkey_hex: The agent's compressed pubkey.
        payload: The original payload to check against.

    Returns:
        True if signature is valid AND payload_hash matches.
    """
    if isinstance(payload, str):
        payload = payload.encode()

    expected_hash = hashlib.sha256(payload).hexdigest()
    if attestation.get("payload_hash") != expected_hash:
        return False

    return verify_attestation(attestation, pubkey_hex)
