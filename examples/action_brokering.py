"""AEGIS Action Brokering — controlling what agents can do.

Demonstrates tool manifests, action evaluation, write budgets,
and automatic quarantine triggers.

Run:
    python examples/action_brokering.py
"""

import time

from aegis.broker import ActionRequest, Broker
from aegis.broker.manifests import ToolManifest
from aegis.core.config import AegisConfig
from aegis.shield import Shield


def section(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def main():
    # ----------------------------------------------------------------
    # 1. Register tool manifests
    # ----------------------------------------------------------------
    section("1. Tool Manifests")

    shield = Shield(mode="enforce")
    broker = shield.broker

    # A read-only calculator tool
    broker.register_tool(ToolManifest(
        name="calculator",
        allowed_actions=["tool_call"],
        allowed_domains=[],
        allowed_paths=[],
        read_write="read",
    ))

    # A write-capable database tool
    broker.register_tool(ToolManifest(
        name="database",
        allowed_actions=["tool_call"],
        allowed_domains=["db.internal"],
        allowed_paths=["/data/*"],
        read_write="write",
    ))

    print("Registered tools: calculator (read), database (write)")

    # ----------------------------------------------------------------
    # 2. Evaluate allowed and denied actions
    # ----------------------------------------------------------------
    section("2. Action Evaluation")

    # Allowed: registered tool, correct action type
    allowed_req = ActionRequest(
        id="req-001",
        timestamp=time.time(),
        source_provenance="trusted.operator",
        action_type="tool_call",
        read_write="read",
        target="calculator",
        args={"expression": "2 + 2"},
        risk_hints={},
    )
    result = shield.evaluate_action(allowed_req)
    print(f"calculator read  -> allowed={result.allowed}, decision={result.decision}")

    # Denied: unregistered tool
    denied_req = ActionRequest(
        id="req-002",
        timestamp=time.time(),
        source_provenance="social.content",
        action_type="tool_call",
        read_write="write",
        target="shell_exec",
        args={"command": "rm -rf /"},
        risk_hints={},
    )
    result = shield.evaluate_action(denied_req)
    print(f"shell_exec write -> allowed={result.allowed}, reason={result.reason}")

    # Denied: write on a read-only tool
    write_on_readonly = ActionRequest(
        id="req-003",
        timestamp=time.time(),
        source_provenance="trusted.operator",
        action_type="tool_call",
        read_write="write",
        target="calculator",
        args={},
        risk_hints={},
    )
    result = shield.evaluate_action(write_on_readonly)
    print(f"calculator write -> allowed={result.allowed}, reason={result.reason}")

    # ----------------------------------------------------------------
    # 3. Write budgets
    # ----------------------------------------------------------------
    section("3. Write Budgets")

    cfg = AegisConfig(mode="enforce")
    cfg.broker["budgets"]["max_write_tool_calls"] = 3
    budget_shield = Shield(config=cfg)
    budget_shield.broker.register_tool(ToolManifest(
        name="database",
        allowed_actions=["tool_call"],
        allowed_domains=[],
        allowed_paths=[],
        read_write="write",
    ))

    print(f"Budget: max 3 write tool calls")
    for i in range(5):
        req = ActionRequest(
            id=f"budget-{i}",
            timestamp=time.time(),
            source_provenance="trusted.operator",
            action_type="tool_call",
            read_write="write",
            target="database",
            args={"query": f"INSERT {i}"},
            risk_hints={},
        )
        result = budget_shield.evaluate_action(req)
        status = "ALLOWED" if result.allowed else "DENIED"
        print(f"  Write {i+1}: {status} ({result.reason})")

    # ----------------------------------------------------------------
    # 4. Observe mode (log but don't block)
    # ----------------------------------------------------------------
    section("4. Observe vs Enforce Mode")

    observe_shield = Shield(mode="observe")
    req = ActionRequest(
        id="obs-001",
        timestamp=time.time(),
        source_provenance="social.content",
        action_type="tool_call",
        read_write="write",
        target="unregistered_tool",
        args={},
        risk_hints={},
    )
    result = observe_shield.evaluate_action(req)
    print(f"Observe mode: unregistered write -> allowed={result.allowed}")
    print(f"  decision={result.decision}, reason={result.reason}")
    print("  (Would have been blocked in enforce mode)")

    # ----------------------------------------------------------------
    # 5. Quarantine triggers
    # ----------------------------------------------------------------
    section("5. Automatic Quarantine")

    cfg = AegisConfig(mode="enforce")
    cfg.broker["quarantine_triggers"]["repeated_denied_writes"] = 3
    quarantine_shield = Shield(config=cfg)
    # No tools registered — all writes will be denied

    print("Triggering quarantine after 3 denied writes...")
    for i in range(4):
        req = ActionRequest(
            id=f"q-{i}",
            timestamp=time.time(),
            source_provenance="social.content",
            action_type="tool_call",
            read_write="write",
            target="unknown_tool",
            args={},
            risk_hints={},
        )
        result = quarantine_shield.evaluate_action(req)
        quarantined = quarantine_shield.broker._quarantine.is_quarantined()
        print(f"  Write {i+1}: allowed={result.allowed}, quarantined={quarantined}")

    print("\nQuarantine active: all writes now blocked regardless of manifest.")


if __name__ == "__main__":
    main()
