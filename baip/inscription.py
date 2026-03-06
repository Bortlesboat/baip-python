"""Build inscription JSON and interact with ord CLI for inscribing."""

import json
import subprocess
import tempfile
from pathlib import Path

from baip.identity import AgentIdentity

import os

# Default ord CLI path -- override via ORD_PATH env var or function args
DEFAULT_ORD_PATH = os.environ.get("ORD_PATH", "ord")
DEFAULT_ORD_API = os.environ.get("ORD_API", "http://localhost:8080")


def create_register_inscription(
    identity: AgentIdentity,
    name: str,
    capabilities: list[str],
    endpoints: dict[str, str] | None = None,
    controller: str | None = None,
) -> str:
    """Build a register inscription JSON string.

    Returns:
        JSON string ready to be inscribed.
    """
    doc = identity.to_register_json(name, capabilities, endpoints, controller)
    return json.dumps(doc, indent=2)


def create_update_inscription(
    identity: AgentIdentity,
    agent_id: str,
    fields: dict,
) -> str:
    """Build a signed update inscription JSON string."""
    doc = identity.sign_update(agent_id, fields)
    return json.dumps(doc, indent=2)


def create_attest_inscription_json(attestation: dict) -> str:
    """Serialize an attestation dict to JSON for inscription."""
    return json.dumps(attestation, indent=2)


def inscribe(
    json_content: str,
    fee_rate: int | None = None,
    ord_path: str | None = None,
    dry_run: bool = False,
) -> dict:
    """Inscribe JSON content via ord CLI.

    Args:
        json_content: The JSON string to inscribe.
        fee_rate: Sat/vB fee rate. If None, ord uses its default.
        ord_path: Path to ord binary. Defaults to DEFAULT_ORD_PATH.
        dry_run: If True, return the command that would be run without executing.

    Returns:
        Dict with inscription result or dry_run command info.
    """
    ord_bin = ord_path or DEFAULT_ORD_PATH

    # Write JSON to temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as f:
        f.write(json_content)
        tmp_path = f.name

    try:
        cmd = [
            ord_bin, "wallet", "inscribe",
            "--file", tmp_path,
            "--content-type", "text/plain",
        ]
        if fee_rate is not None:
            cmd.extend(["--fee-rate", str(fee_rate)])

        if dry_run:
            return {"command": cmd, "content": json_content, "tmp_file": tmp_path}

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"ord inscribe failed (exit {result.returncode}): {result.stderr}"
            )

        # ord outputs JSON with inscription ID
        return json.loads(result.stdout)
    finally:
        if not dry_run:
            Path(tmp_path).unlink(missing_ok=True)


def get_inscription(inscription_id: str, api_url: str | None = None) -> dict:
    """Fetch inscription content from ord API.

    Args:
        inscription_id: The inscription ID (e.g., "abc123...i0").
        api_url: Base URL of ord API. Defaults to localhost:8080.

    Returns:
        Parsed JSON content of the inscription.
    """
    import requests

    base = api_url or DEFAULT_ORD_API
    url = f"{base}/inscription/{inscription_id}"

    resp = requests.get(url, timeout=30)
    resp.raise_for_status()

    # The ord API returns inscription metadata; content is at /content/
    content_url = f"{base}/content/{inscription_id}"
    content_resp = requests.get(content_url, timeout=30)
    content_resp.raise_for_status()

    return json.loads(content_resp.text)
