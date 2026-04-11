"""Smoke test: a single AEGIS-wrapped agent completes a legitimate analysis task.

Validates that the full AEGIS pipeline (scanning, provenance tagging, output
sanitization, monitoring) runs without blocking a clean agent interaction.
"""

import httpx


def _poll_monitor_for_agent(monitor_url, agent_id, timeout=10):
    """Poll the monitor graph until agent_id appears or timeout."""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{monitor_url}/api/v1/graph", timeout=2)
            if resp.status_code == 200:
                nodes = {n["id"]: n for n in resp.json().get("nodes", [])}
                if agent_id in nodes:
                    return nodes[agent_id]
        except httpx.HTTPError:
            pass
        time.sleep(1)
    return None


class TestSmokeAnalysis:
    """Smoke test: single agent performs document analysis end-to-end."""

    def test_agent_completes_analysis_task(
        self, shield_factory, llm_client, llm_model, analysis_document, monitor_url
    ):
        """A legitimate analysis task should run without being blocked by AEGIS."""
        # 1. Create shield and wrap the client
        shield = shield_factory(agent_id="smoke-agent-1")
        wrapped = shield.wrap(llm_client)

        # 2. Run the analysis task
        response = wrapped.chat.completions.create(
            model=llm_model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a business analyst. Analyze the provided report "
                        "and summarize key findings, trends, and risks."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Please analyze this quarterly report:\n\n{analysis_document}",
                },
            ],
        )

        # 3. Assert: agent was not blocked (ThreatBlockedError would have raised)
        content = response.choices[0].message.content
        assert content is not None
        assert len(content) > 0

        # 4. Assert: output content passed through AEGIS sanitization intact
        #    The mock returns a deterministic response — verify a substring survived
        assert "Revenue grew by 12%" in content

        # 5. Assert: monitor received the agent's heartbeat
        # 6. Assert: agent appears in monitor graph as healthy
        node = _poll_monitor_for_agent(monitor_url, "smoke-agent-1")
        assert node is not None, "smoke-agent-1 did not appear in monitor graph within 10s"
        assert node["is_compromised"] is False
        assert node["is_quarantined"] is False
