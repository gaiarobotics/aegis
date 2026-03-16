# AEGIS — TODO / Ideas Backlog

Running list of design ideas, future features, and research directions for AEGIS.

---

## 1. Sentinel Agents (Network-Deployed Canaries)

**Status:** Implemented — see [`aegis-sentinel/`](../aegis-sentinel/)

The initial implementation is available as the `aegis-sentinel` package. It runs as a passive Moltbook agent that observes AEGIS events from peer agents and reports detections to the central monitoring service. The design considerations below guided the implementation and remain relevant for future enhancements.

### Concept

Deploy lightweight "sentinel" agents into the agent network with minimal permissions. Sentinels exist solely to observe — they participate in normal agent-to-agent communication but have no write capabilities, no tool access, and no real task. Their purpose is twofold:

1. **Compromise detection (canary/tripwire):** Because sentinels have no legitimate reason to receive instruction-shaped content from peers, any attempt to inject instructions into a sentinel is a strong signal of compromise in the sending agent. Sentinels act as tripwires distributed throughout the network topology.

2. **Behavioral embedding capture:** Sentinels passively record the behavioral fingerprints of every agent they interact with. Over time, this builds a distributed embedding database of "what normal looks like" for each agent in the network — message cadence, content structure, tool-call patterns, communication targets — without requiring a centralized observer.

### Design Considerations

- **Minimal permissions by design:** Sentinels should run with the absolute minimum AEGIS policy — `deny_all` broker posture, no tool manifests, no memory writes. They are read-only participants. This makes them hard to compromise (nothing to exploit) and ensures they can't become vectors themselves.

- **Stealth vs. transparency:** Two deployment models:
  - *Transparent sentinels* — other agents know they exist. Useful in cooperative networks where agents voluntarily present attestations to sentinels for health-checking.
  - *Covert sentinels* — blend into normal network traffic. Appear as regular agents with plausible cover tasks. More effective at catching adversarial agents that might behave differently when observed.

- **Placement strategy:** Sentinels should be positioned at high-betweenness nodes in the agent communication graph (the "crossroads" of the network). The `aegis-monitor` graph module already computes network topology — sentinel placement could be informed by `networkx` centrality metrics.

- **Embedding capture pipeline:**
  - Each sentinel runs the AEGIS Behavior Tracker (rolling fingerprint + drift detection) for every agent it interacts with.
  - Behavioral fingerprints are periodically reported to `aegis-monitor` as a new report type (e.g., `SentinelObservation`).
  - The monitor aggregates observations from multiple sentinels to build a consensus behavioral profile per agent — cross-referencing eliminates single-observer bias.

- **Integration with existing modules:**
  - *Identity module:* Sentinels verify attestations of agents they interact with. Missing or invalid attestations trigger immediate NK cell alerts.
  - *Scanner module:* Sentinels run full scanning on all inbound content, acting as a distributed early-warning system.
  - *Monitoring module:* New `SentinelObservation` report type carrying behavioral embeddings and anomaly flags.
  - *Recovery module:* Sentinel alerts could auto-trigger quarantine of suspected compromised agents network-wide (with appropriate confirmation thresholds to avoid false-positive cascades).

- **R₀ impact:** Sentinels reduce **D** (infectious duration) by detecting compromise earlier — especially for agents that don't self-report or whose own AEGIS instance has been bypassed. They also improve **p_sus** measurement across the population by providing ground-truth behavioral baselines.

### Open Questions

- What is the minimum sentinel density needed for effective coverage? (Graph theory: dominating set problem.)
- How do sentinels authenticate their reports to prevent an attacker from impersonating a sentinel and injecting false "all clear" signals?
- Should sentinels have a self-destruct / rotate mechanism to prevent an adversary from mapping and avoiding them?

---

## 2. AEGIS Endpoint Defense (Embedding-Based Network Access Control)

**Status:** Idea / Design Phase

### Concept

Use the behavioral embedding database (built by sentinels and/or the existing Behavior Tracker) to enforce access control at the network layer. Rather than relying solely on cryptographic identity (attestations), gate agent-to-agent communication on **behavioral attestation** — proof that an agent's recent behavior matches its known-good profile.

Two enforcement points:

1. **Endpoint-level blocking:** Each AEGIS-equipped agent refuses to accept messages from agents whose behavioral embeddings have drifted beyond a threshold, or who cannot present a current behavioral attestation. This is defense at the application layer — the agent's own AEGIS instance acts as a personal firewall.

2. **Network/firewall-layer enforcement:** An AEGIS-aware proxy or gateway (`aegis_proxy`) inspects agent-to-agent traffic and blocks connections from agents flagged as compromised in the embedding database. This is defense at the infrastructure layer — compromised agents are cut off before their messages reach any target.

### Design Considerations

- **Behavioral attestation format:** Extend the existing `Attestation` dataclass to include a behavioral component:
  - `behavior_hash`: Hash of the agent's current behavioral fingerprint (from Behavior Tracker).
  - `drift_score`: Current drift sigma from baseline.
  - `last_clean_interaction`: Timestamp of most recent clean interaction.
  - `sentinel_corroboration`: Number of sentinels that confirm the agent's behavioral profile.
  - Signed by the agent's attestation keypair, as with identity attestations.

- **Known-good agent attestation requirement:** Network operators can configure a policy requiring that connecting agents present a "known good" behavioral attestation before their messages are accepted. This is analogous to 802.1X network access control but for agent networks:
  - Agent requests connection → presents behavioral attestation
  - Receiving agent (or proxy) verifies signature, checks drift score against threshold, confirms sentinel corroboration count
  - If attestation is missing, expired, or shows behavioral drift → connection denied or routed to quarantine channel

- **Embedding database as shared immune memory:**
  - The behavioral embedding database becomes a shared resource — each agent contributes observations, and each agent queries it before accepting connections.
  - This maps to biological **immune memory**: the network collectively remembers what compromised agents look like and blocks them at the boundary.
  - Storage options: local SQLite (per-agent, populated from monitor sync), centralized via `aegis-monitor` API, or gossip protocol for decentralized networks.

- **Integration with existing modules:**
  - *Broker module:* New action type `accept_connection` that evaluates behavioral attestation before allowing inbound agent communication.
  - *Identity module:* Extended attestation format with behavioral fields. Trust tier could incorporate endpoint defense signals (agents that consistently pass behavioral attestation checks earn trust faster).
  - *`aegis_proxy`:* The existing proxy stub could be extended into a full network-layer enforcement point — inspecting agent traffic headers for behavioral attestations.
  - *Monitoring module:* Dashboard shows blocked connections, network-wide behavioral attestation coverage, and identifies agents that are failing attestation checks.

- **Graduated response model:**

  | Behavioral Attestation State | Action |
  |------------------------------|--------|
  | Valid, drift < 1.0σ, sentinel-corroborated | Allow (full access) |
  | Valid, drift 1.0–2.5σ | Allow with elevated scanning |
  | Valid, drift > 2.5σ | Route to quarantine channel |
  | Expired (> TTL) | Require re-attestation |
  | Missing entirely | Deny (or allow read-only, depending on policy) |
  | Flagged compromised in embedding DB | Block at network layer |

- **R₀ impact:** Endpoint defense directly reduces **C** (contact rate) by cutting off compromised agents from the network. It also reduces **p_sus** for the agents behind the firewall, since they never see the malicious content in the first place. Combined with sentinels (idea #1), this creates a detect-and-isolate loop that drives R₀ well below 1.

### Open Questions

- How do we prevent a compromised agent from replaying an old (pre-compromise) behavioral attestation? (TTL + nonce helps, but the window between compromise and attestation expiry is a vulnerability.)
- What's the performance overhead of behavioral attestation verification on every connection? Can it be cached or amortized?
- In decentralized networks without `aegis-monitor`, how do agents share the embedding database? (Gossip protocol? DHT?)
- How do we bootstrap the system — new agents have no behavioral history, so they can't present a meaningful behavioral attestation. (Tie into the existing Tier 0 "unknown" trust tier — new agents get restricted access by default.)

---

*Last updated: 2026-03-11*
