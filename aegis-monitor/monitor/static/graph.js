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
            graphInstance.addNode(node.id, {
                x: r * Math.cos(angle),
                y: r * Math.sin(angle),
                size: 8 + (node.trust_score || 0) * 0.1,
                color: node.color || "#95a5a6",
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
                data.is_compromised ? "COMPROMISED" :
                data.is_quarantined ? "QUARANTINED" : "Active");
            setText("popup-operator", data.operator_id || "—");
            setText("popup-heartbeat", "—");
            setText("popup-at-risk",
                data.at_risk_agents && data.at_risk_agents.length > 0 ?
                    data.at_risk_agents.join(", ") : "None");

            document.getElementById("agent-popup").classList.add("visible");
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

    // ---- Filter listeners ----
    function setupFilters() {
        document.querySelectorAll('[data-filter]').forEach(function (el) {
            el.addEventListener("change", function () { fetchGraph(); });
        });
    }

    // ---- Boot ----
    document.addEventListener("DOMContentLoaded", function () {
        initGraph();
        setupFilters();
        fetchGraph();
        fetchMetrics();
        connectWS();

        // Periodic refresh
        setInterval(fetchGraph, 15000);
        setInterval(fetchMetrics, 10000);
    });
})();
