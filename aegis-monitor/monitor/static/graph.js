/**
 * AEGIS Monitor — graph visualization and real-time dashboard.
 *
 * Uses Sigma.js v2 with graphology for WebGL-accelerated rendering.
 */

(function () {
    "use strict";

    // ---- State ----
    let sigmaInstance = null;
    let graphInstance = null;
    let ws = null;
    let reconnectTimer = null;
    const RECONNECT_MS = 3000;
    let topicViewActive = false;

    // ---- Initialize graph ----
    function initGraph() {
        const container = document.getElementById("graph-canvas");
        if (!container) return;

        graphInstance = new graphology.Graph({ multi: false, type: "directed" });
        sigmaInstance = new Sigma(graphInstance, container, {
            renderLabels: true,
            labelColor: { color: "#e0e6ed" },
            labelSize: 12,
            defaultNodeColor: "#95a5a6",
            defaultEdgeColor: "#2c3e50",
            minCameraRatio: 0.1,
            maxCameraRatio: 10,
        });

        sigmaInstance.on("clickNode", function (e) {
            showAgentPopup(e.node);
        });
    }

    // ---- Fetch & render graph ----
    async function fetchGraph() {
        try {
            const resp = await fetch("/api/v1/graph");
            const data = await resp.json();
            renderGraph(data);
        } catch (err) {
            logEvent("system", "Failed to fetch graph: " + err.message);
        }
    }

    function renderGraph(data) {
        if (!graphInstance) return;

        graphInstance.clear();

        const nodes = data.nodes || [];
        const edges = data.edges || [];

        // Layout: circular for now
        const n = nodes.length;
        nodes.forEach(function (node, i) {
            const angle = (2 * Math.PI * i) / Math.max(n, 1);
            const r = 10;
            if (!isFiltered(node)) return;
            var nodeColor = node.color || "#95a5a6";
            if (topicViewActive && node.topic_color) {
                nodeColor = node.topic_color;
            }
            graphInstance.addNode(node.id, {
                x: r * Math.cos(angle),
                y: r * Math.sin(angle),
                size: 8 + (node.trust_score || 0) * 0.1,
                color: nodeColor,
                label: node.id,
                _data: node,
            });
        });

        edges.forEach(function (edge) {
            if (graphInstance.hasNode(edge.source) && graphInstance.hasNode(edge.target)) {
                try {
                    graphInstance.addEdge(edge.source, edge.target, {
                        size: Math.max(1, (edge.message_count || 1) * 0.5),
                        color: "#2c3e50",
                    });
                } catch (e) {
                    // Duplicate edge
                }
            }
        });

        if (sigmaInstance) sigmaInstance.refresh();
    }

    // ---- Filtering ----
    function isFiltered(node) {
        const tierCheckboxes = document.querySelectorAll('[data-filter="tier"]');
        const visibleTiers = new Set();
        tierCheckboxes.forEach(function (cb) {
            if (cb.checked) visibleTiers.add(parseInt(cb.dataset.value, 10));
        });

        if (node.is_killswitched) {
            var showKillswitched = document.querySelector('[data-filter="killswitched"]');
            return showKillswitched ? showKillswitched.checked : true;
        }

        const showCompromised = document.querySelector('[data-filter="compromised"]');
        if (node.is_compromised || node.is_quarantined) {
            return showCompromised ? showCompromised.checked : true;
        }

        return visibleTiers.has(node.trust_tier || 0);
    }

    // ---- Metrics ----
    async function fetchMetrics() {
        try {
            const resp = await fetch("/api/v1/metrics");
            const data = await resp.json();
            updateMetrics(data);
        } catch (err) {
            // silent
        }
    }

    function updateMetrics(data) {
        setText("m-r0", (data.r0 || 0).toFixed(2));
        setText("m-threats", data.active_threats || 0);
        setText("m-quarantined", data.quarantined_agents || 0);
        setText("m-killswitched", data.killswitched_agents || 0);
        setText("m-clusters", data.cluster_count || 0);
        setText("m-agents", data.total_agents || 0);

        // Update strain filters
        const strainDiv = document.getElementById("strain-filters");
        if (strainDiv && data.clusters && data.clusters.length > 0) {
            const realClusters = data.clusters.filter(function (c) { return c.cluster_id >= 0; });
            if (realClusters.length > 0) {
                strainDiv.innerHTML = realClusters.map(function (c) {
                    return '<label><input type="checkbox" checked data-strain="' + c.cluster_id + '"> ' +
                        c.label + ' (' + c.event_count + ')</label>';
                }).join("");
            }
        }
    }

    function setText(id, value) {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    }

    // ---- Agent popup ----
    async function showAgentPopup(nodeId) {
        try {
            const resp = await fetch("/api/v1/trust/" + encodeURIComponent(nodeId));
            const data = await resp.json();
            setText("popup-agent-id", nodeId);
            setText("popup-tier", data.trust_tier !== undefined ? "Tier " + data.trust_tier : "—");
            setText("popup-score", data.trust_score !== undefined ? data.trust_score.toFixed(1) : "—");
            setText("popup-status",
                data.is_killswitched ? "KILLSWITCHED" :
                data.is_compromised ? "COMPROMISED" :
                data.is_quarantined ? "QUARANTINED" : "Active");
            setText("popup-operator", data.operator_id || "—");
            setText("popup-heartbeat", "—");
            setText("popup-at-risk",
                data.at_risk_agents && data.at_risk_agents.length > 0 ?
                    data.at_risk_agents.join(", ") : "None");

            // Add killswitch buttons to popup
            var popup = document.getElementById("agent-popup");
            var existingKsBtn = popup.querySelector(".ks-popup-actions");
            if (existingKsBtn) existingKsBtn.remove();
            var btnDiv = document.createElement("div");
            btnDiv.className = "ks-popup-actions";
            btnDiv.innerHTML =
                '<button class="ks-btn ks-block-agent" onclick="ksBlockAgent(\'' + nodeId + '\')">Block Agent</button>' +
                '<button class="ks-btn ks-unblock-agent" onclick="ksUnblockAgent(\'' + nodeId + '\')">Unblock Agent</button>';
            popup.appendChild(btnDiv);

            popup.classList.add("visible");
        } catch (err) {
            // silent
        }
    }

    // ---- WebSocket ----
    function connectWS() {
        const protocol = location.protocol === "https:" ? "wss:" : "ws:";
        const url = protocol + "//" + location.host + "/ws/dashboard";
        ws = new WebSocket(url);

        ws.onopen = function () {
            document.getElementById("ws-status").classList.remove("disconnected");
            document.getElementById("ws-status").classList.add("connected");
            logEvent("system", "WebSocket connected");
        };

        ws.onmessage = function (event) {
            try {
                var data = JSON.parse(event.data);
                handleWSEvent(data);
            } catch (e) { }
        };

        ws.onclose = function () {
            document.getElementById("ws-status").classList.remove("connected");
            document.getElementById("ws-status").classList.add("disconnected");
            reconnectTimer = setTimeout(connectWS, RECONNECT_MS);
        };

        ws.onerror = function () {
            ws.close();
        };
    }

    function handleWSEvent(data) {
        var type = data.type || "unknown";

        if (type === "compromise") {
            logEvent("compromise", "COMPROMISE: " + data.compromised_agent_id +
                (data.at_risk ? " | At risk: " + data.at_risk.join(", ") : ""));
        } else if (type === "threat") {
            logEvent("threat", "THREAT: agent=" + data.agent_id +
                " score=" + (data.threat_score || 0).toFixed(2));
        } else if (type === "heartbeat") {
            logEvent("heartbeat", "HEARTBEAT: " + data.agent_id);
        } else if (type === "contagion_alert") {
            logEvent("contagion", "CONTAGION: agent=" + data.agent_id +
                " score=" + (data.contagion_score || 0).toFixed(2));
        } else if (type === "killswitch") {
            logEvent("killswitch", "KILLSWITCH: " + data.action + " rule " + data.rule_id);
            fetchKillswitchRules();
        }

        // Refresh graph and metrics
        fetchGraph();
        fetchMetrics();
    }

    // ---- Event log ----
    function logEvent(type, message) {
        var log = document.getElementById("event-log");
        if (!log) return;
        var div = document.createElement("div");
        div.className = "event " + type;
        div.textContent = new Date().toLocaleTimeString() + " " + message;
        log.appendChild(div);
        log.scrollTop = log.scrollHeight;

        // Cap log lines
        while (log.children.length > 200) {
            log.removeChild(log.firstChild);
        }
    }

    // ---- Killswitch ----
    async function fetchKillswitchRules() {
        try {
            var resp = await fetch("/api/v1/killswitch/rules");
            var data = await resp.json();
            var rules = data.rules || [];
            var statusEl = document.getElementById("ks-status");
            var listEl = document.getElementById("ks-rules-list");
            if (!statusEl || !listEl) return;

            if (rules.length === 0) {
                statusEl.textContent = "No rules active";
                statusEl.className = "ks-status-text";
                listEl.innerHTML = "";
                return;
            }

            var blockingRules = rules.filter(function (r) { return r.blocked; });
            if (blockingRules.length > 0) {
                statusEl.textContent = blockingRules.length + " blocking rule(s) active";
                statusEl.className = "ks-status-text ks-active";
            } else {
                statusEl.textContent = rules.length + " rule(s), none blocking";
                statusEl.className = "ks-status-text";
            }

            listEl.innerHTML = rules.map(function (r) {
                var label = r.scope === "swarm" ? "ALL AGENTS" :
                    r.scope + ": " + (r.target || "—");
                return '<div class="ks-rule">' +
                    '<span class="ks-rule-scope">' + label + '</span>' +
                    '<span class="ks-rule-reason">' + (r.reason || "") + '</span>' +
                    '<button class="ks-rule-delete" onclick="ksDeleteRule(\'' + r.rule_id + '\')">&times;</button>' +
                    '</div>';
            }).join("");
        } catch (err) {
            // silent
        }
    }

    window.ksBlockSwarm = async function () {
        try {
            await fetch("/api/v1/killswitch/rules", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    scope: "swarm",
                    blocked: true,
                    reason: "Emergency shutoff via dashboard",
                }),
            });
            fetchKillswitchRules();
        } catch (err) {
            logEvent("system", "Failed to block swarm: " + err.message);
        }
    };

    window.ksUnblockSwarm = async function () {
        try {
            var resp = await fetch("/api/v1/killswitch/rules");
            var data = await resp.json();
            var swarmRules = (data.rules || []).filter(function (r) { return r.scope === "swarm"; });
            for (var i = 0; i < swarmRules.length; i++) {
                await fetch("/api/v1/killswitch/rules/" + swarmRules[i].rule_id, { method: "DELETE" });
            }
            fetchKillswitchRules();
        } catch (err) {
            logEvent("system", "Failed to unblock swarm: " + err.message);
        }
    };

    window.ksBlockAgent = async function (agentId) {
        try {
            await fetch("/api/v1/killswitch/rules", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    scope: "agent",
                    target: agentId,
                    blocked: true,
                    reason: "Blocked via dashboard",
                }),
            });
            fetchKillswitchRules();
        } catch (err) {
            logEvent("system", "Failed to block agent: " + err.message);
        }
    };

    window.ksUnblockAgent = async function (agentId) {
        try {
            var resp = await fetch("/api/v1/killswitch/rules");
            var data = await resp.json();
            var agentRules = (data.rules || []).filter(function (r) {
                return r.scope === "agent" && r.target === agentId;
            });
            for (var i = 0; i < agentRules.length; i++) {
                await fetch("/api/v1/killswitch/rules/" + agentRules[i].rule_id, { method: "DELETE" });
            }
            fetchKillswitchRules();
        } catch (err) {
            logEvent("system", "Failed to unblock agent: " + err.message);
        }
    };

    window.ksDeleteRule = async function (ruleId) {
        try {
            await fetch("/api/v1/killswitch/rules/" + ruleId, { method: "DELETE" });
            fetchKillswitchRules();
        } catch (err) {
            logEvent("system", "Failed to delete rule: " + err.message);
        }
    };

    // ---- Filter listeners ----
    function setupFilters() {
        document.querySelectorAll('[data-filter]').forEach(function (el) {
            el.addEventListener("change", function () { fetchGraph(); });
        });
    }

    // ---- Topic view toggle ----
    function setupTopicToggle() {
        var btn = document.getElementById("topic-view-toggle");
        if (!btn) return;
        btn.addEventListener("click", function () {
            topicViewActive = !topicViewActive;
            btn.classList.toggle("active", topicViewActive);
            btn.textContent = topicViewActive ? "Trust view" : "Topic view";
            fetchGraph();
        });
    }

    // ---- Boot ----
    document.addEventListener("DOMContentLoaded", function () {
        initGraph();
        setupFilters();
        setupTopicToggle();
        fetchGraph();
        fetchMetrics();
        fetchKillswitchRules();
        connectWS();

        // Periodic refresh
        setInterval(fetchGraph, 15000);
        setInterval(fetchMetrics, 10000);
        setInterval(fetchKillswitchRules, 10000);
    });
})();
