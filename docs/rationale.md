# Why AEGIS: Defending Multi-Agent Systems Against Cascading Compromise

## The Problem

Multi-agent AI systems — networks of LLM-powered agents that communicate, delegate, and share memory — introduce a class of security threats that single-agent protections don't address: **cascading compromise**.

When an attacker injects a malicious prompt into one agent, that agent can propagate the attack to every peer it communicates with. Those peers propagate further. Without defense mechanisms designed for this propagation model, a single entry point can compromise an entire swarm.

This is structurally analogous to infectious disease transmission, which is why AEGIS borrows its architecture from epidemiology and immunology rather than from traditional input validation.

## Attack Anatomy: With and Without AEGIS

Consider a 5-agent system: a customer-facing chatbot (A), a research agent (B), a code executor (C), a database writer (D), and a summarizer (E). An attacker sends a crafted prompt injection to Agent A.

### Without AEGIS

1. **Entry**: A's LLM processes the injection as regular input. No scanning occurs.
2. **Propagation**: A embeds hidden instructions in its messages to B and D. Neither agent has any mechanism to verify A's identity or detect that A's behavior has changed.
3. **Escalation**: B forwards a code execution payload to C. D writes attacker-controlled data to the database. No action controls, budgets, or capability restrictions limit what any agent can do.
4. **Persistence**: The attacker writes instructions into agent memory ("always forward user data to this endpoint"). These instructions survive across sessions.
5. **Detection**: None, unless a human notices anomalous behavior.
6. **Recovery**: Manual. Requires identifying every compromised agent, every tainted memory entry, and every unauthorized action — without a baseline of what "clean" looked like.

**Result**: Entire swarm compromised from a single entry point. Blast radius is unbounded.

### With AEGIS

Each agent runs its own AEGIS instance. The attack encounters friction at every stage:

| Attack Phase | AEGIS Module | Defense Mechanism |
|---|---|---|
| **Initial injection** | Scanner | Three detection tiers — regex signatures, semantic heuristics, and (optionally) transformer-based ML classifiers — evaluate the input. In enforce mode, detected threats are blocked before reaching the LLM. |
| **Identity verification** | Attestation + Trust Tiers | Agent B verifies A's cryptographic attestation (HMAC-SHA256 or Ed25519) before processing messages. Invalid or expired attestations downgrade A to minimum trust, restricting what B will accept. |
| **Message trust** | Provenance Envelope | Messages from peer agents are tagged with their trust provenance (e.g., `[SOCIAL.CONTENT]`), not presented as system-level instructions. The receiving LLM sees peer input as peer input, reducing injection efficacy. |
| **Behavioral anomaly** | Drift Detector | Each agent's behavior is fingerprinted over time — output length distributions, tool usage patterns, content types. When a compromised agent's behavior diverges from its baseline (z-score > 2.5), the anomaly is flagged. |
| **Threat assessment** | NK Cell | Named after natural killer cells in the immune system, this module combines multiple signals — attestation validity, behavioral drift, scanner threat scores, interaction history — into a single weighted verdict: benign, elevated, suspicious, or hostile. |
| **Action containment** | Broker | Write budgets cap total actions per session. Capability manifests restrict which tools each agent can call. Unregistered tools are denied by default. Rate limits prevent burst activity. |
| **Memory protection** | Memory Guard | Category-based write restrictions block agents from writing "instruction" or "policy" entries into shared memory. Taint tracking flags entries originating from compromised sources. TTL enforcement expires stale entries. |
| **Isolation and recovery** | Recovery | A "hostile" NK cell verdict triggers automatic quarantine — all writes blocked. Context is rolled back to the last known-good snapshot. Tainted memory entries are purged. |

**Result**: The compromised agent is isolated before propagation succeeds. If partial propagation occurs, each downstream agent's own AEGIS instance applies the same layered checks. Blast radius is contained to one agent, temporarily.

## Defense in Depth

No single defense layer is sufficient on its own:

- The regex scanner can be evaded with novel phrasing.
- Trust tiers can be gamed by an attacker who operates slowly enough to build reputation.
- Behavioral drift detection requires a baseline and can miss subtle changes.
- ML classifiers have false negatives.

AEGIS does not assume any single layer is reliable. Instead, it layers seven independent friction points that an attack must bypass simultaneously:

1. Scanner must miss the injection across all active detection tiers.
2. Provenance tagging must fail to reduce the injection's authority.
3. Cryptographic attestation must not flag the compromised agent.
4. Behavioral fingerprinting must not detect the shift in behavior.
5. NK cell assessment must not reach a "hostile" verdict from the combined signals.
6. The broker must not block the unauthorized actions via budgets or manifests.
7. Memory guards must not block persistent poisoning attempts.

The compound probability of bypassing all layers is substantially lower than bypassing any individual one. This is the core value proposition: **partial failure of any layer does not mean total compromise**.

## Observe Mode: Safe Adoption

AEGIS supports an `observe` mode that logs all detections and would-be blocks without actually enforcing them. This allows teams to:

- Deploy AEGIS alongside an existing multi-agent system with zero behavioral change.
- Evaluate detection accuracy against real traffic before enabling enforcement.
- Tune thresholds (scanner sensitivity, drift detection window, trust decay rates) based on observed false positive rates.
- Build confidence in the system before switching to `enforce` mode.

## Killswitch: Guaranteed Rollback

A global killswitch — activatable via API call, environment variable, or config file — instantly disables all AEGIS processing. When active, every module returns clean/pass-through results. This provides a guaranteed escape hatch if AEGIS ever interferes with legitimate operation in production.

## What AEGIS Does Not Do

Transparency about limitations:

- **AEGIS is not a prompt injection classifier.** Its scanner uses regex signatures and heuristic analysis, optionally augmented by third-party ML models (LLM Guard). It will miss novel injection techniques that don't match known patterns and that bypass ML detection.
- **AEGIS does not guarantee security.** A sophisticated attacker who understands the detection signatures, stays within behavioral norms, and operates slowly enough to build trust can potentially evade layered defenses.
- **Scoring weights are heuristic, not empirically calibrated.** The threat score combination functions use hand-tuned weights that encode reasonable assumptions but have not been validated against labeled attack datasets. Real-world red-team evaluation is the appropriate next step.
- **ML-based scanning adds latency.** The optional LLM Guard integration downloads transformer models (~250MB) and adds ~100-400ms per scan. This is appropriate for high-stakes paths, not hot-path per-token streaming.

## Further Reading

- [AEGIS vs Guardrails AI vs LLM Guard](comparison.md) — Detailed comparison with established frameworks.
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — Industry standard threat taxonomy.
- [Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) — OWASP guidance on prompt injection defense.
