---
name: aegis-sanitize-outbound
event: message:sent
description: Sanitizes outbound messages to remove authority markers, credential fragments, and instruction-shaped content.
---

Runs AEGIS output sanitization on every outbound message before delivery. Strips authority markers like [SYSTEM] and [ADMIN], removes credential fragments, and logs any modifications made.
