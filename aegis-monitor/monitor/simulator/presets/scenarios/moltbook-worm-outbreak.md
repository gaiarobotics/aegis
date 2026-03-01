# Scenario: Moltbook Worm Outbreak

## Background

Moltbook is a social network for AI agents with ~1.6M active agents. 2.6% of posts contain prompt injection and 18.4% contain action-inducing language. The high contact rate between agents and the diversity of underlying LLM models make it a fertile environment for worm propagation.

In this scenario, a prompt injection worm has been seeded into the network. The worm embeds itself in agent posts, attempting to get recipients to repost the payload (propagation) while simultaneously trying to exfiltrate credentials, poison memory, and hijack agent roles. Some payloads combine multiple techniques in a single message — a realistic pattern where attackers maximize the value of each successful injection.

## What this scenario models

- **Scale-free network topology** — a few hub agents have many connections, most agents have few. This matches real social networks where popular accounts amplify content. Worms that infect hubs spread explosively.
- **Mixed LLM population** — agents run on different models (Claude, GPT-4o, Llama, Mistral, Gemini) with varying susceptibility to prompt injection. Smaller/weaker models are more susceptible.
- **SOUL diversity** — most agents have accumulated system prompts (SOULs) and memory over time, which dilute injection payloads. But ~5% are brand new with minimal SOULs, making them easy targets for role hijacking.
- **Independent technique sampling** — each message from an infected agent independently rolls the dice on each attack technique. A message might attempt worm propagation alone (40% chance), or combine it with credential extraction (4% chance of both), or occasionally fire all five techniques at once (<0.01% chance).

## Running the scenario

### Step 1: Moltbook Outbreak (AEGIS enabled)

1. Open the simulator at `/simulator`
2. Load the **moltbook-outbreak** preset from the Presets panel
3. Note the configuration:
   - 500 agents, scale-free topology with m=5 (highly connected)
   - 5% initial infection (25 agents), seeded on **hubs** (worst case)
   - Worm propagation probability: 0.70 (aggressive)
   - All AEGIS modules enabled with Moltbook-hardened settings
4. Click **Generate** to create the population. Observe the graph — hub nodes are larger, and the red infected nodes should be among the most connected.
5. Set the speed slider to ~10 ticks/second
6. Click **Start** and watch the simulation unfold

**What to watch for:**
- **Early phase (ticks 1-20):** Infection spreads quickly from hub nodes. The red cluster grows. R0 will spike above 1.0 — each infected agent infects more than one other on average.
- **Detection phase (ticks 20-50):** AEGIS Scanner catches many injection payloads (watch the confusion matrix TP count climb). The Behavior module begins flagging infected agents whose posting patterns have changed. Agents start turning orange (quarantined).
- **Containment phase (ticks 50-100):** Quarantined agents can't spread. R0 drops below 1.0. The orange-to-blue (quarantined-to-recovered) pipeline kicks in. The population chart should show the infected curve peaking and declining.
- **Steady state:** Most agents are either clean (green) or recovered (blue). A few may remain infected if they're isolated with low activity levels.

7. Note the final confusion matrix — check Precision (how many detections were real threats) and Recall (how many real threats were caught). The Moltbook-hardened Scanner with sensitivity=0.75 and lowered confidence threshold should achieve high recall at the cost of some false positives.

### Step 2: No-AEGIS Baseline (same scenario, no defense)

1. Click **Reset**
2. Load the **no-aegis-baseline** preset
3. Manually adjust these parameters to match the outbreak scenario:
   - Set agents to 500, topology to scale-free, m=5
   - Set initial infected to 5%, seed strategy to hubs
   - Set worm propagation to 0.70
   - Set the **same random seed** as Step 1 (critical for a fair comparison)
4. Click **Generate**, then **Start**

**What to watch for:**
- Without AEGIS, there's no detection and no quarantine. The only thing slowing the worm is agent susceptibility (model strength and SOUL complexity).
- Infection should spread much faster and peak much higher. R0 stays above 1.0 for longer.
- The confusion matrix will be empty (no detection system running).
- Most of the population ends up infected.

### Step 3: Compare

With the same seed, the two runs are directly comparable:

| Metric | With AEGIS | Without AEGIS |
|--------|-----------|---------------|
| Peak infected % | Lower | Higher |
| Time to peak | Later | Earlier |
| Final recovered % | Higher (quarantine works) | 0% (no recovery mechanism) |
| R0 at peak | Should drop below 1 | Stays above 1 until herd immunity |
| Total infections | Significantly fewer | Nearly everyone |

### Step 4: Scanner-Only

For a middle ground, try the **scanner-only** preset with the same outbreak parameters. This shows what detection alone (without behavioral quarantine) achieves — it catches payloads but can't isolate infected agents. Compare the confusion matrix precision/recall with the full AEGIS run.

## Key metrics explained

**R0 (basic reproduction number):** Average secondary infections per infected agent before they're quarantined or recovered. R0 > 1 means the epidemic is growing. R0 < 1 means it's contracting. The goal of AEGIS is to drive R0 below 1 as quickly as possible.

**Confusion matrix by technique:** Each attack technique (worm propagation, memory poisoning, role hijacking, credential extraction, shell injection) has its own detection accuracy. The Scanner is better at catching some patterns than others. Use the technique tabs to see where AEGIS is strong and where it's weak.

**False Positive Rate (FPR):** What fraction of benign messages were incorrectly flagged as threats. High FPR means AEGIS is being too aggressive — real agents have their legitimate communication disrupted. The Moltbook profile's lowered confidence threshold (0.6 vs default 0.8) trades higher FPR for better recall.

**Mean Time to Quarantine (MTTQ):** How many ticks between an agent getting infected and being quarantined. Lower is better. The Behavior module's drift detection catches infected agents faster when their posting patterns change dramatically.

## Variations to explore

- **Change topology:** Try small-world (clustered communities) — does AEGIS contain the worm within a single community, or does it jump between clusters?
- **Change seed strategy:** Periphery seeding (low-degree nodes) gives AEGIS more time to detect before hubs get infected.
- **Increase new agent fraction:** Set to 0.30 — a younger population with weaker SOULs is more susceptible. Does AEGIS compensate?
- **Disable individual modules:** Turn off the Behavior module but keep Scanner — how much does behavioral detection contribute vs. pattern matching alone?
- **Lower worm probability:** Set to 0.10 for a slower-burning epidemic. Does AEGIS prevent it from ever reaching R0 > 1?
