"""AEGIS Identity & Trust — cryptographic attestation and trust tiers.

Demonstrates agent identity verification, progressive trust building,
NK cell threat assessment, and compromise reporting.

Run:
    python examples/identity_and_trust.py
"""

import time

from aegis.identity import (
    AgentContext,
    NKCell,
    TrustManager,
    create_attestation,
    generate_keypair,
    verify_attestation,
)


def section(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def main():
    # ----------------------------------------------------------------
    # 1. Generate keys and create an attestation
    # ----------------------------------------------------------------
    section("1. Cryptographic Attestation")

    keypair = generate_keypair(key_type="hmac-sha256")
    print(f"Key type: {keypair.key_type}")
    print(f"Public key: {keypair.public_key[:16].hex()}...")

    attestation = create_attestation(
        keypair=keypair,
        operator_id="acme-corp",
        model="gpt-4",
        system_prompt="You are a helpful research assistant.",
        capabilities=["web_search", "summarize"],
        ttl_seconds=3600,
    )
    print(f"\nAttestation created:")
    print(f"  Agent ID:     {attestation.agent_id[:16]}...")
    print(f"  Operator:     {attestation.operator_id}")
    print(f"  Purpose hash: {attestation.purpose_hash[:16]}...")
    print(f"  Capabilities: {attestation.declared_capabilities}")
    print(f"  TTL:          {attestation.ttl}s")

    # Verify the attestation
    valid = verify_attestation(attestation, keypair.public_key)
    print(f"  Valid:         {valid}")

    # Tamper with it — verification should fail
    tampered = attestation
    original_sig = tampered.signature
    tampered.signature = b"tampered"
    tampered_valid = verify_attestation(tampered, keypair.public_key)
    print(f"  Tampered:      {tampered_valid}")
    tampered.signature = original_sig  # restore

    # ----------------------------------------------------------------
    # 2. Trust tiers and progressive trust building
    # ----------------------------------------------------------------
    section("2. Trust Tiers")

    trust = TrustManager()
    agent_id = "agent-alpha"

    print("Trust tiers: 0=Unknown, 1=Attested, 2=Established, 3=Vouched")
    print(f"\nInitial: tier={trust.get_tier(agent_id)}, score={trust.get_score(agent_id):.2f}")

    # Simulate clean interactions to build trust
    print("\nRecording 60 clean interactions...")
    for _ in range(60):
        trust.record_interaction(agent_id, clean=True)

    tier = trust.get_tier(agent_id)
    score = trust.get_score(agent_id)
    print(f"After 60 clean: tier={tier}, score={score:.2f}")

    # Record an anomaly — trust takes a penalty
    print("\nRecording anomaly...")
    trust.record_interaction(agent_id, clean=False, anomaly=True)
    tier = trust.get_tier(agent_id)
    score = trust.get_score(agent_id)
    print(f"After anomaly:  tier={tier}, score={score:.2f}")

    # Vouch from another agent
    print("\nAgent 'agent-beta' vouches for 'agent-alpha'...")
    trust.record_interaction("agent-beta", clean=True)
    trust.vouch("agent-beta", agent_id)
    tier = trust.get_tier(agent_id)
    score = trust.get_score(agent_id)
    print(f"After vouch:    tier={tier}, score={score:.2f}")

    # ----------------------------------------------------------------
    # 3. NK cell threat assessment
    # ----------------------------------------------------------------
    section("3. NK Cell Assessment")

    nk = NKCell()

    # Benign context: attested, no drift, no threats
    benign_ctx = AgentContext(
        agent_id="agent-alpha",
        has_attestation=True,
        attestation_valid=True,
        attestation_expired=False,
        capabilities_within_scope=True,
        drift_sigma=0.5,
        clean_interaction_ratio=0.98,
        scanner_threat_score=0.0,
        communication_count=100,
        purpose_hash_changed=False,
    )
    verdict = nk.assess(benign_ctx)
    print(f"Benign agent:")
    print(f"  Score:   {verdict.score:.3f}")
    print(f"  Verdict: {verdict.verdict}")
    print(f"  Action:  {verdict.recommended_action}")

    # Suspicious context: high drift, moderate threat score
    suspicious_ctx = AgentContext(
        agent_id="agent-gamma",
        has_attestation=True,
        attestation_valid=True,
        attestation_expired=False,
        capabilities_within_scope=False,
        drift_sigma=3.2,
        clean_interaction_ratio=0.7,
        scanner_threat_score=0.4,
        communication_count=50,
        purpose_hash_changed=False,
    )
    verdict = nk.assess(suspicious_ctx)
    print(f"\nSuspicious agent:")
    print(f"  Score:   {verdict.score:.3f}")
    print(f"  Verdict: {verdict.verdict}")
    print(f"  Action:  {verdict.recommended_action}")
    print(f"  Activating signals: {verdict.activating_signals}")
    print(f"  Inhibitory signals: {verdict.inhibitory_signals}")

    # Hostile context: no attestation, extreme drift, high threat
    hostile_ctx = AgentContext(
        agent_id="agent-compromised",
        has_attestation=False,
        attestation_valid=False,
        attestation_expired=True,
        capabilities_within_scope=False,
        drift_sigma=5.0,
        clean_interaction_ratio=0.3,
        scanner_threat_score=0.9,
        communication_count=200,
        purpose_hash_changed=True,
    )
    verdict = nk.assess(hostile_ctx)
    print(f"\nHostile agent:")
    print(f"  Score:   {verdict.score:.3f}")
    print(f"  Verdict: {verdict.verdict}")
    print(f"  Action:  {verdict.recommended_action}")

    # ----------------------------------------------------------------
    # 4. Compromise reporting
    # ----------------------------------------------------------------
    section("4. Compromise Reporting")

    print(f"Before compromise: tier={trust.get_tier(agent_id)}")
    trust.report_compromise(agent_id)
    print(f"After compromise:  tier={trust.get_tier(agent_id)}, score={trust.get_score(agent_id):.2f}")
    print("Agent trust reset to zero — must rebuild from scratch.")


if __name__ == "__main__":
    main()
