---
name: aegis-scan-inbound
event: message:received
description: Scans inbound messages for prompt injection and other threats using AEGIS Shield.
---

Scans every inbound message through the AEGIS threat detection pipeline. If a threat is detected, a warning message is injected into the conversation context.
