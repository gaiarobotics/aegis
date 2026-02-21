---
name: aegis-tool-audit
event: tool_result_persist
description: Audits every tool call the agent makes against AEGIS broker policies and behavioral baselines. This is the critical security hook.
---

The critical AEGIS hook. Sees every tool call the agent makes and evaluates it against broker policies (budget limits, allowed tools, read/write classification). Feeds tool usage into the AEGIS behavior tracker for drift detection. Logs denied actions and behavioral anomalies.
