# AEGIS Security Remediation

Scores use CVSS 3.1-style severity estimates based on the reachable AEGIS
deployment boundary. They should be recalculated for a specific production
topology. The optional, explicitly enabled monitor open mode is not treated as
a vulnerability.

| Finding | Score | Status | Remediation and regression coverage |
|---|---:|---|---|
| Agent credential could submit telemetry for another identity and poison monitor state | 9.1 Critical | Fixed | Bind agent API keys to `agent_id`/`operator_id`; validate timestamps and identifiers; reject durable `report_id` replays; prevent agent-authored trust and heartbeat fields from overwriting authoritative compromise/quarantine state. Monitor auth and endpoint tests cover impersonation, replay after cache loss, roles, and unknown agents. |
| Compromise reports mutated graph/quarantine state before quorum validation | 8.6 High | Fixed | Validate first, retain pending/rejected reports only as audit events, and mutate durable/live state only for confirmed independent quorum. Hashless reports now also require quorum. |
| OpenClaw tool policy ran after execution rather than at the enforcement boundary | 9.1 Critical | Fixed | Replace the audit hook with an installable native `before_tool_call` plugin. Killswitch, quarantine, and broker denials return a terminal block; evaluator errors and timeouts fail closed. Static packaging tests and Node syntax validation cover the plugin entry point. |
| Broker controls were bypassable through alternate I/O APIs, path prefixes, or ignored argument schemas | 7.8 High | Mitigated | Cover Requests, HTTPX, urllib, subprocess/Popen, `os.system`, `os.popen`, built-in/OS/pathlib writes; use resolved path ancestry; enforce the manifest JSON-schema subset. The native pre-tool plugin remains the primary boundary because in-process monkey patches cannot cover every direct socket or third-party client. |
| Skill manifests did not reliably bind the exact loaded artifact or publisher | 8.1 High | Fixed | Require an exact filename hash, enforce maximum size before reading, verify optional Ed25519 publisher signatures against configured trusted keys, honor static-analysis settings, and require manual approval when automatic approval is disabled. Loader tests cover missing/mismatched hashes, size, analysis, and approval behavior. |
| Remote killswitch/quarantine/threat-intel clients accepted error responses as valid state or lacked monitor authentication | 8.1 High | Fixed | Send the configured bearer credential, require 2xx and typed response fields, preserve last-known state on failures, and fail enforce-mode initialization when configured security modules cannot start. Remote-control tests cover non-2xx state preservation. |
| Proxy defaulted to a network-wide unauthenticated listener and lacked resource bounds | 8.2 High | Fixed | Default to loopback; reject non-loopback binds unless separate proxy client keys are configured; authenticate all endpoints; bound body size, concurrent requests, socket/upstream time, and upstream response size; use daemon request threads. Proxy server tests cover defaults, remote-bind refusal, authentication, size, and health protection. |
| Dashboard interpolated attacker-controlled agent/rule data into HTML and inline handlers | 8.0 High | Fixed | Build dynamic UI with DOM nodes, `textContent`, and event listeners; validate identifiers; move login JavaScript out of HTML; add CSP, frame, MIME, and referrer headers. Static regression checks cover the removed agent-ID sink. |
| Provider/proxy scanning omitted tool-result content and mishandled multimodal envelopes | 8.1 High | Fixed | Treat OpenAI tool messages and Anthropic nested `tool_result` blocks as untrusted scanner input; safely tag list-based content. Provider, proxy extraction, and envelope tests cover these paths. |
| Persistent security state could silently use a restart-unstable key and escalation restoration was incomplete | 7.5 High | Fixed | Make persistence opt-in, require `AEGIS_STATE_KEY` when enabled, fail enforce mode without it, and restore persisted quarantine/escalation. Persistence regression tests cover missing keys and restart restoration. |
| Sentinel scanner exceptions were converted into clean observations | 6.5 Medium | Fixed | In enforce mode, emit a failed-scan threat result and report it; in observe mode, preserve ingestion but expose `scan_succeeded=false`. Sentinel tests cover both modes. |

## Follow-up hardening

- Add a pluggable state-key provider. Recommended backends are a workload-identity
  cloud secret manager, an OS keyring backed by DPAPI/Keychain/libsecret, or a
  permission-restricted external key file as the simplest fallback.
- Replace the monitor's in-process login limiter with a shared store for
  multi-instance deployments.
- Add end-to-end OpenClaw tests against a pinned gateway version; the local
  environment does not contain the OpenClaw CLI.
- Consider migrating the proxy to an async server with streaming byte limits at
  the transport layer. The current synchronous client bounds processing but an
  injected `HttpPool` implementation may buffer before AEGIS checks its size.
