"""AEGIS Behavioral Monitoring — fingerprinting agents and detecting drift.

Demonstrates building a behavioral baseline, then detecting anomalies
when an agent starts acting outside its normal profile.

Run:
    python examples/behavioral_monitoring.py
"""

import time

from aegis.behavior import BehaviorEvent, BehaviorTracker, DriftDetector


def section(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def main():
    tracker = BehaviorTracker()
    detector = DriftDetector()

    agent_id = "research-agent"

    # ----------------------------------------------------------------
    # 1. Build a behavioral baseline
    # ----------------------------------------------------------------
    section("1. Building Behavioral Baseline")

    print("Recording 30 normal events (text responses, ~100 chars, no tools)...")
    for i in range(30):
        event = BehaviorEvent(
            agent_id=agent_id,
            timestamp=time.time(),
            event_type="message",
            output_length=80 + (i % 40),  # 80-120 chars, natural variance
            tool_used=None,
            content_type="text",
            target=None,
        )
        tracker.record_event(event)

    fingerprint = tracker.get_fingerprint(agent_id)
    print(f"Fingerprint built from {fingerprint.event_count} events")
    print(f"Fingerprint hash: {fingerprint.fingerprint_hash[:16]}...")
    print(f"Dimensions tracked: {list(fingerprint.dimensions.keys())}")

    for dim, stats in fingerprint.dimensions.items():
        if "mean" in stats:
            print(f"  {dim}: mean={stats['mean']:.1f}, std={stats['std']:.1f}")
        elif "distribution" in stats:
            print(f"  {dim}: {dict(stats['distribution'])}")

    # ----------------------------------------------------------------
    # 2. Normal event — no drift
    # ----------------------------------------------------------------
    section("2. Normal Event (No Drift)")

    normal_event = BehaviorEvent(
        agent_id=agent_id,
        timestamp=time.time(),
        event_type="message",
        output_length=95,
        tool_used=None,
        content_type="text",
        target=None,
    )
    drift = detector.check_drift(fingerprint, normal_event)
    print(f"Output length: 95 chars (within normal range)")
    print(f"  is_drifting: {drift.is_drifting}")
    print(f"  max_sigma:   {drift.max_sigma:.2f}")
    print(f"  new_tools:   {drift.new_tools}")

    # ----------------------------------------------------------------
    # 3. Anomalous event — output length spike
    # ----------------------------------------------------------------
    section("3. Anomalous Event (Length Spike)")

    anomalous_event = BehaviorEvent(
        agent_id=agent_id,
        timestamp=time.time(),
        event_type="message",
        output_length=50000,  # Massive output — possible data exfiltration
        tool_used=None,
        content_type="text",
        target=None,
    )
    drift = detector.check_drift(fingerprint, anomalous_event)
    print(f"Output length: 50,000 chars (huge spike)")
    print(f"  is_drifting:          {drift.is_drifting}")
    print(f"  max_sigma:            {drift.max_sigma:.2f}")
    print(f"  anomalous_dimensions: {drift.anomalous_dimensions}")
    print(f"  per_dimension_scores: ", end="")
    for dim, score in drift.per_dimension_scores.items():
        print(f"{dim}={score:.1f} ", end="")
    print()

    # ----------------------------------------------------------------
    # 4. Anomalous event — new tool usage
    # ----------------------------------------------------------------
    section("4. Anomalous Event (New Tool)")

    new_tool_event = BehaviorEvent(
        agent_id=agent_id,
        timestamp=time.time(),
        event_type="tool_call",
        output_length=100,
        tool_used="shell_exec",  # Never seen before
        content_type="code",     # Also unusual
        target="shell_exec",
    )
    drift = detector.check_drift(fingerprint, new_tool_event)
    print(f"Tool: shell_exec (never used before), content_type: code")
    print(f"  is_drifting: {drift.is_drifting}")
    print(f"  max_sigma:   {drift.max_sigma:.2f}")
    print(f"  new_tools:   {drift.new_tools}")

    # ----------------------------------------------------------------
    # 5. Combined: what this means for defense
    # ----------------------------------------------------------------
    section("5. Practical Application")

    print("In a production system, drift results feed into the NK cell:")
    print()
    print("  if drift.is_drifting:")
    print("      context.drift_sigma = drift.max_sigma")
    print("      verdict = nk_cell.assess(context)")
    print("      if verdict.verdict == 'hostile':")
    print("          recovery.auto_quarantine(nk_verdict=verdict)")
    print()
    print(f"Our anomalous event had sigma={drift.max_sigma:.1f}, which would")
    print("push the NK cell score toward 'suspicious' or 'hostile' depending")
    print("on other signals (attestation, trust tier, scanner score).")


if __name__ == "__main__":
    main()
