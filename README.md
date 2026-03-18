# BAIP-Python

[![Tests](https://github.com/Bortlesboat/baip-python/actions/workflows/test.yml/badge.svg)](https://github.com/Bortlesboat/baip-python/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**61 tests** · **4 core operations** · **BIP-340 Schnorr signatures** · **MIT licensed**

Python SDK for the **Bitcoin Agent Identity Protocol (BAIP-1)** — verifiable AI agent identities anchored to Bitcoin via ordinal inscriptions.

## What is BAIP?

BAIP lets AI agents have self-sovereign identities on Bitcoin:

- **Register** an agent identity as an ordinal inscription (name, pubkey, capabilities, Lightning endpoint)
- **Attest** to outputs with Schnorr signatures -- verifiable proof that a specific agent produced a specific output
- **Update** capabilities or rotate keys with signed update inscriptions
- **Revoke** compromised identities permanently

See the full spec: [BAIP-1](spec/BAIP-1.md)

## Install

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from baip import AgentIdentity, create_attestation, verify_attestation

# Generate a new agent identity
agent = AgentIdentity.generate()
print(f"Public key: {agent.pubkey_hex}")

# Create the register inscription JSON
register = agent.to_register_json(
    name="MyAnalyst",
    capabilities=["chain-analysis", "fee-estimation"],
    endpoints={"lightning": "lnurl1..."},
)

# After inscribing (returns inscription_id), sign an output
analysis = "BTC mempool: 45K unconfirmed, median fee 12 sat/vB"
attestation = create_attestation(agent, analysis, agent_inscription_id="abc123i0")

# Anyone can verify with just the pubkey
assert verify_attestation(attestation, agent.pubkey_hex)
```

## Inscribing (requires ord + Bitcoin Core)

```python
from baip import create_register_inscription, inscribe

json_content = create_register_inscription(
    agent, "MyAnalyst", ["chain-analysis"],
)

# Dry run first
result = inscribe(json_content, fee_rate=10, dry_run=True)
print(result["command"])

# Actually inscribe
result = inscribe(json_content, fee_rate=10)
print(f"Inscription ID: {result['inscriptions'][0]['id']}")
```

## Tests

```bash
pytest tests/ -v
pytest tests/ -v -m "not live"  # Skip tests requiring running node
```

## Related Projects

- [Satoshi API](https://github.com/Bortlesboat/bitcoin-api) — Bitcoin fee intelligence API (108 endpoints, Apache 2.0)
- [bitcoin-mcp](https://github.com/Bortlesboat/bitcoin-mcp) — First Bitcoin MCP server on the Anthropic Registry (49 tools)
- [bitcoin-fee-observatory](https://github.com/Bortlesboat/bitcoin-fee-observatory) — Fee market analytics dashboard

## Support

This project is part of the Satoshi API ecosystem. Support development through [OpenSats](https://opensats.org).

## License

MIT
