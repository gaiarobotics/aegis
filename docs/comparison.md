# AEGIS vs Guardrails AI vs LLM Guard

A comparative analysis of AEGIS against two established LLM security frameworks.

## Positioning

The three frameworks solve overlapping but distinct problems:

| | **Guardrails AI** | **LLM Guard** | **AEGIS** |
|---|---|---|---|
| **Core metaphor** | Validators on I/O | Security scanners | Immune system |
| **Primary concern** | Output quality & structure | Prompt injection & data leakage | Agent-to-agent attack propagation |
| **Target user** | LLM app developers | Security-focused teams | Multi-agent system builders |

## Architecture Comparison

**Guardrails AI** uses a validator/guard pattern. You compose validators from their [Hub](https://guardrailsai.com/hub) (150+ community validators) into Guards that check inputs and outputs. Validators return `PassResult`/`FailResult` with configurable failure actions (exception, fix, filter, reask). It also handles structured data extraction and output parsing. Think of it as a quality assurance layer.

**LLM Guard** uses a scanner pattern with separate input scanners (prompt injection, PII anonymization, toxicity, topic banning) and output scanners (content moderation, bias, sensitive data, regex). Each scanner returns `(sanitized_output, is_valid, risk_score)`. It's focused squarely on security -- closer to a WAF for LLMs.

**AEGIS** uses an epidemiological/immune system model with 8 interconnected modules. It's not just scanning I/O -- it models agent identity, trust relationships, behavioral fingerprints, and immune-like threat responses.

 A shared embedding layer (`all-MiniLM-L6-v2`) powers behavioral fingerprinting, inter-agent contagion detection, and indirect injection detection from a single model load.
 
## What AEGIS Does Differently

### 1. Direct and Indirect Prompt Injection Detection via Shared Embedding Layer

AEGIS uses a shared embedding model to power three interconnected defense mechanisms from a single model load: behavioral content hash fingerprinting, inter-agent contagion detection (SimHash Hamming distance), and intent-context divergence scoring (cosine similarity). The intent-divergence detector catches indirect prompt injection — malicious instructions hidden in tool outputs or retrieved documents — by measuring how far external content diverges from the user's actual intent, amplified by proximity to known-compromised agent signatures. Neither Guardrails nor LLM Guard addresses indirect injection or embedding-based contagion detection.

Because the embeddings are shared, this not only protects the individual agent, but other agents in the network as well.

### 2. Agent Identity and Trust Tiers

Neither Guardrails nor LLM Guard tracks *who* an agent is. AEGIS has cryptographic attestation (HMAC-SHA256/Ed25519), a 4-tier progressive trust model with logarithmic growth and decay, and an NK cell module that combines multiple signals into a threat verdict. This matters in multi-agent systems where you need to know if a peer agent has been compromised.

### 3. Behavioral Drift Detection

AEGIS fingerprints agent behavior over time (output length distributions, tool usage patterns, content types) and uses z-score analysis to detect when an agent starts acting abnormally. Guardrails and LLM Guard are stateless -- they evaluate each request independently.

### 4. Action Brokering

The Broker module acts as an actuator firewall with capability manifests, write budgets, rate limits, and automatic quarantine triggers. This goes beyond I/O validation into controlling what actions an agent can take. Guardrails AI has nothing comparable; LLM Guard partially covers this through its input scanners but without budgets or manifests.

### 5. Recovery Mechanisms

Context rollback, memory purge, and quarantine management. If an agent is compromised, AEGIS can restore to a known-good state. The other two frameworks don't address recovery.

### 6. Memory Protection

Category-based write guards, taint tracking, and TTL enforcement on agent memory. Prevents persistent memory poisoning attacks where an attacker injects instructions that survive across sessions.

## What AEGIS Lacks Compared to Them

### vs Guardrails AI

- No structured output validation or parsing (Guardrails' primary strength)
- No validator marketplace/hub ecosystem
- No `reask` pattern (ask the LLM to regenerate on failure)
- No server mode for deployment as a standalone service
- Much smaller community and validator library

### vs LLM Guard

- No PII anonymization/deanonymization with vault storage
- No toxicity classification (though supported via LLM Guard adapter when `aegis-shield[ml]` is installed)
- Less mature as a production security tool

## Capability Matrix

| Capability | Guardrails AI | LLM Guard | AEGIS |
|---|:---:|:---:|:---:|
| Prompt injection detection | Hub validator | ML classifiers | Regex + heuristic + ML (LLM Guard/LLM screen) + embedding-based intent divergence |
| Output validation | Core feature | Scanners | Sanitizer only |
| Structured output parsing | Core feature | - | - |
| PII detection/redaction | Hub validator | Built-in | Telemetry redaction only |
| Agent identity/attestation | - | - | Core feature |
| Trust tiers | - | - | Core feature |
| Behavioral drift detection | - | - | Core feature |
| Action brokering/budgets | - | - | Core feature |
| Memory protection | - | - | Core feature |
| Quarantine & recovery | - | - | Core feature |
| Skill/plugin sandboxing | - | - | Core feature |
| ML-based classifiers | Via Hub | Built-in | LLM Guard adapter + LLM screen + embedding-based intent divergence |
| Indirect injection detection | - | - | Intent-context divergence with contagion amplification |
| Drop-in wrapping | - | - | `aegis.wrap(client)` |
| Production maturity | High | High | Early |

## When to Use What

**Guardrails AI** -- You're building a single LLM application and need output quality guarantees: structured data extraction, format validation, content policy enforcement. Best ecosystem for composable validators.

**LLM Guard** -- You need production-grade security scanning with ML-powered detection. Best accuracy for prompt injection detection thanks to fine-tuned transformer classifiers. Good fit for security-conscious teams adding protection to existing LLM apps.

**AEGIS** -- You're building multi-agent systems where agents interact, delegate, and can potentially infect each other. AEGIS addresses cascading compromise, identity verification, behavioral anomaly detection, and recovery -- threats the other two don't model at all.

## References

- [Guardrails AI Documentation](https://guardrailsai.com/docs)
- [Guardrails AI GitHub](https://github.com/guardrails-ai/guardrails)
- [LLM Guard by Protect AI](https://protectai.com/llm-guard)
- [LLM Guard GitHub](https://github.com/protectai/llm-guard)
- [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
