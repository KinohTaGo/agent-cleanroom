"""agent-cleanroom: reproducible, network-isolated runs of coding agents.

Runs an agent CLI (Claude Code in 0.1) inside a hardened container whose only
way out is a gateway that forwards to the declared model backend, and writes a
verifiable record of each run.
"""

__version__ = "0.1.0"

MANIFEST_SCHEMA = "agent-cleanroom/manifest/1.0"
BACKEND_SCHEMA = "agent-cleanroom/backend/1.0"
VERIFY_SCHEMA_VERSION = "3.0"
