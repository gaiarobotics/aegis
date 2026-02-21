---
name: aegis-bootstrap
event: agent:bootstrap
description: Injects AEGIS security context into the agent workspace on startup.
---

Runs during agent bootstrap to set up the AEGIS security context. Creates `.aegis/status.md` with current mode, enabled modules, and session information. This gives the agent awareness of its security posture from the start of every session.
