"""BAIP - Bitcoin Agent Identity Protocol SDK."""

__version__ = "0.1.0"

from baip.identity import AgentIdentity
from baip.attestation import create_attestation, verify_attestation
from baip.inscription import create_register_inscription, inscribe, get_inscription
from baip.resolver import resolve_agent, get_agent_history, get_current_state
