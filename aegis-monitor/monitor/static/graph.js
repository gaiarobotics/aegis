/**
 * AEGIS Monitor — graph visualization and real-time dashboard.
 *
 * Uses Sigma.js v3 with graphology for WebGL-accelerated rendering.
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
    let topicPanelVisible = false;
    let activeTopicTab = "clusters";

    var CLUSTER_PALETTE = [
        "#1abc9c", "#2ecc71", "#3498db", "#9b59b6",
        "#e74c3c", "#e67e22", "#f1c40f", "#1f77b4",
        "#ff7f0e", "#2ca02c", "#d62728", "#9467bd",
        "#8c564b", "#17becf", "#bcbd22", "#7f7f7f",
    ];
    function clusterColor(cid) {
        return CLUSTER_PALETTE[cid % CLUSTER_PALETTE.length];
    }
    function escapeHtml(str) {
        var div = document.createElement("div");
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    // ---- Dark-theme node hover ----
    function drawDarkHover(context, data, settings) {
        var size = settings.labelSize;
        var font = settings.labelFont;
        var weight = settings.labelWeight;

        context.font = (weight ? weight + " " : "") + size + "px " + font;

        var label = data.label;
        if (!label) return;

        var textWidth = context.measureText(label).width;
        var padding = 4;
        var boxWidth = Math.round(textWidth + 8 + data.size + 3 * padding);
        var boxHeight = Math.round(Math.max(2 * data.size, size + 2 * padding) + 2 * padding);
        var radius = 5;

        var x = Math.round(data.x - data.size - padding);
        var y = Math.round(data.y - boxHeight / 2);

        // Draw rounded-rect background
        context.beginPath();
        context.moveTo(x + radius, y);
        context.lineTo(x + boxWidth - radius, y);
        context.quadraticCurveTo(x + boxWidth, y, x + boxWidth, y + radius);
        context.lineTo(x + boxWidth, y + boxHeight - radius);
        context.quadraticCurveTo(x + boxWidth, y + boxHeight, x + boxWidth - radius, y + boxHeight);
        context.lineTo(x + radius, y + boxHeight);
        context.quadraticCurveTo(x, y + boxHeight, x, y + boxHeight - radius);
        context.lineTo(x, y + radius);
        context.quadraticCurveTo(x, y, x + radius, y);
        context.closePath();

        context.fillStyle = "#1a2332";
        context.shadowOffsetX = 0;
        context.shadowOffsetY = 2;
        context.shadowBlur = 8;
        context.shadowColor = "#00000080";
        context.fill();

        context.shadowOffsetX = 0;
        context.shadowOffsetY = 0;
        context.shadowBlur = 0;
        context.shadowColor = "transparent";

        context.strokeStyle = "#2c3e50";
        context.lineWidth = 1;
        context.stroke();

        // Draw node disc
        context.beginPath();
        context.arc(data.x, data.y, data.size, 0, Math.PI * 2);
        context.fillStyle = data.color;
        context.fill();

        // Draw label
        context.fillStyle = "#e0e6ed";
        context.fillText(label, Math.round(data.x + data.size + padding), Math.round(data.y + size / 3));
    }

    // ---- Initialize graph ----
    function initGraph() {
        const container = document.getElementById("graph-canvas");
        if (!container) return;

        graphInstance = new graphology.Graph({ multi: false, type: "directed" });

        var AegisBorderProgram = createNodeBorderProgram({
            borders: [
                { size: { attribute: "borderSize", defaultValue: 0, mode: "relative" }, color: { attribute: "borderColor", defaultValue: "#00000000" } },
                { size: { fill: true }, color: { attribute: "color" } },
            ],
        });

        sigmaInstance = new Sigma(graphInstance, container, {
            renderLabels: true,
            labelColor: { color: "#e0e6ed" },
            labelSize: 12,
            defaultNodeColor: "#95a5a6",
            defaultEdgeColor: "#2c3e50",
            minCameraRatio: 0.1,
            maxCameraRatio: 10,
            defaultNodeType: "bordered",
            nodeProgramClasses: { bordered: AegisBorderProgram },
            defaultDrawNodeHover: drawDarkHover,
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

    function muteColor(hex) {
        // Mix a hex color with gray to produce a desaturated version
        var r = parseInt(hex.slice(1, 3), 16);
        var g = parseInt(hex.slice(3, 5), 16);
        var b = parseInt(hex.slice(5, 7), 16);
        r = Math.round(r * 0.6 + 0x7f * 0.4);
        g = Math.round(g * 0.6 + 0x8c * 0.4);
        b = Math.round(b * 0.6 + 0x9b * 0.4);
        return "#" + ((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1);
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
            var hasAegis = node.has_aegis || false;
            graphInstance.addNode(node.id, {
                x: r * Math.cos(angle),
                y: r * Math.sin(angle),
                size: hasAegis ? 10 + (node.trust_score || 0) * 0.1 : 7 + (node.trust_score || 0) * 0.1,
                color: hasAegis ? nodeColor : muteColor(nodeColor),
                borderColor: hasAegis ? "#3498db" : "#00000000",
                borderSize: hasAegis ? 0.15 : 0,
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
        setText("m-topic-clusters", data.topic_cluster_count || 0);

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
            setText("popup-aegis", data.has_aegis ? "Protected" : "Not installed");
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
        } else if (type === "topic_clusters_updated") {
            setText("m-topic-clusters", data.active_cluster_count || 0);
            if (topicPanelVisible) {
                fetchTopicClusters();
                if (activeTopicTab === "dendrogram") fetchDendrogram();
            }
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

    // ---- Topic Clusters ----
    async function fetchTopicClusters() {
        try {
            var resp = await fetch("/api/v1/topic-clusters");
            var data = await resp.json();
            renderCentroidCards(data || []);
        } catch (err) {
            // silent
        }
    }

    function renderCentroidCards(centroids) {
        var container = document.getElementById("topic-centroid-cards");
        if (!container) return;
        container.innerHTML = "";

        if (!centroids || centroids.length === 0) {
            container.innerHTML = '<p style="color:var(--text-muted);font-size:12px;">No topic clusters detected</p>';
            return;
        }

        centroids.forEach(function (c) {
            var card = document.createElement("div");
            card.className = "centroid-card" + (c.active === false ? " dissolved" : "");
            card.style.borderLeftColor = clusterColor(c.cluster_id);

            // Header
            var header = document.createElement("div");
            header.className = "centroid-header";
            var lifetimeHTML = "";
            if (c.formed_at != null) {
                var updates;
                if (c.dissolved_at != null) {
                    updates = c.dissolved_at - c.formed_at;
                } else {
                    updates = "active";
                }
                lifetimeHTML = '<span class="centroid-lifetime">' + updates + (typeof updates === "number" ? " updates" : "") + "</span>";
            }
            header.innerHTML = '<span class="centroid-dot" style="background:' + clusterColor(c.cluster_id) + '"></span>'
                + '<strong>Cluster ' + c.cluster_id + '</strong>'
                + (c.active === false ? '<span class="centroid-dissolved-badge">dissolved</span>' : '')
                + '<span class="centroid-count">' + c.member_count + ' agents'
                + lifetimeHTML + '</span>';
            card.appendChild(header);

            // Status breakdown
            if (c.member_statuses) {
                var statuses = document.createElement("div");
                statuses.className = "centroid-statuses";
                var parts = [];
                ["active", "compromised", "quarantined"].forEach(function (s) {
                    var n = c.member_statuses[s] || 0;
                    if (n > 0) {
                        parts.push('<span class="status-badge status-badge-' + s + '">' + n + ' ' + s + '</span>');
                    }
                });
                statuses.innerHTML = parts.join(" ");
                card.appendChild(statuses);
            }

            // Compromised count
            if (c.compromised_count > 0) {
                var compEl = document.createElement("div");
                compEl.className = "centroid-compromised";
                compEl.textContent = c.compromised_count + " compromised agent" + (c.compromised_count !== 1 ? "s" : "");
                card.appendChild(compEl);
            }

            // Click to toggle expanded
            card.addEventListener("click", function () {
                card.classList.toggle("expanded");
            });

            container.appendChild(card);
        });
    }

    // ---- Dendrogram ----
    async function fetchDendrogram() {
        try {
            var resp = await fetch("/api/v1/dendrogram");
            var data = await resp.json();
            if (data && data.linkage && data.linkage.length > 0) {
                renderDendrogram(data);
            }
        } catch (err) {
            // silent
        }
    }

    function renderDendrogram(data) {
        var canvas = document.getElementById("dendro-canvas");
        var container = document.getElementById("topic-dendrogram-view");
        if (!canvas || !container) return;

        var labels = data.labels || [];
        var Z = data.linkage || [];
        var leaves = data.leaves || [];
        var n = labels.length;
        if (n < 2) return;

        var LEAF_SPACING = n > 500 ? 8 : n > 200 ? 14 : 24;
        var TOP_MARGIN = 30;
        var BOTTOM_MARGIN = n <= 80 ? 100 : 40;
        var LEFT_MARGIN = 60;
        var RIGHT_MARGIN = 20;
        var containerHeight = container.clientHeight || 220;
        var canvasWidth = Math.max(container.clientWidth, n * LEAF_SPACING + LEFT_MARGIN + RIGHT_MARGIN);
        var canvasHeight = containerHeight;

        var dpr = window.devicePixelRatio || 1;
        canvas.width = canvasWidth * dpr;
        canvas.height = canvasHeight * dpr;
        canvas.style.width = canvasWidth + "px";
        canvas.style.height = canvasHeight + "px";

        var ctx = canvas.getContext("2d");
        ctx.scale(dpr, dpr);
        ctx.clearRect(0, 0, canvasWidth, canvasHeight);

        // Build tree nodes: 0..n-1 = leaves, n..2n-2 = internal
        var nodes = [];
        for (var i = 0; i < n; i++) {
            nodes.push({ id: i, isLeaf: true, left: null, right: null, height: 0, x: 0, y: 0 });
        }
        for (var i = 0; i < Z.length; i++) {
            var leftIdx = Math.round(Z[i][0]);
            var rightIdx = Math.round(Z[i][1]);
            var mergeHeight = Z[i][2];
            nodes.push({ id: n + i, isLeaf: false, left: leftIdx, right: rightIdx, height: mergeHeight, x: 0, y: 0 });
        }

        // In-order traversal for leaf ordering
        var leafOrder = [];
        function inorder(nodeId) {
            var node = nodes[nodeId];
            if (node.isLeaf) { leafOrder.push(nodeId); return; }
            inorder(node.left);
            inorder(node.right);
        }
        inorder(nodes.length - 1);

        // Max merge height for scaling
        var maxHeight = 0;
        for (var i = 0; i < Z.length; i++) {
            if (Z[i][2] > maxHeight) maxHeight = Z[i][2];
        }
        if (maxHeight === 0) maxHeight = 1;

        var drawableHeight = canvasHeight - TOP_MARGIN - BOTTOM_MARGIN;

        // Assign x to leaves
        for (var i = 0; i < leafOrder.length; i++) {
            nodes[leafOrder[i]].x = LEFT_MARGIN + i * LEAF_SPACING + LEAF_SPACING / 2;
            nodes[leafOrder[i]].y = canvasHeight - BOTTOM_MARGIN;
        }

        // Assign x and y to internal nodes
        function assignInternal(nodeId) {
            var node = nodes[nodeId];
            if (node.isLeaf) return;
            assignInternal(node.left);
            assignInternal(node.right);
            var leftNode = nodes[node.left];
            var rightNode = nodes[node.right];
            node.x = (leftNode.x + rightNode.x) / 2;
            node.y = TOP_MARGIN + (1 - node.height / maxHeight) * drawableHeight;
        }
        assignInternal(nodes.length - 1);

        // Draw U-shaped connectors
        ctx.strokeStyle = "#4a6785";
        ctx.lineWidth = 1;
        for (var i = n; i < nodes.length; i++) {
            var node = nodes[i];
            var leftNode = nodes[node.left];
            var rightNode = nodes[node.right];
            ctx.beginPath();
            ctx.moveTo(leftNode.x, leftNode.y);
            ctx.lineTo(leftNode.x, node.y);
            ctx.lineTo(rightNode.x, node.y);
            ctx.lineTo(rightNode.x, rightNode.y);
            ctx.stroke();
        }

        // Hit targets for tooltips
        var hitTargets = [];

        // Draw leaf dots
        for (var i = 0; i < leafOrder.length; i++) {
            var leafIdx = leafOrder[i];
            var leafNode = nodes[leafIdx];
            var leafInfo = leaves[leafIdx] || {};
            var isCompromised = leafInfo.status === "compromised" || leafInfo.status === "quarantined";
            var cid = leafInfo.cluster_id;
            var color = isCompromised ? "#e74c3c" : (cid !== undefined && cid !== -1 ? clusterColor(cid) : "#95a5a6");
            var dotRadius = isCompromised ? 5 : 3;

            if (isCompromised) {
                // Glow ring
                ctx.save();
                ctx.beginPath();
                ctx.arc(leafNode.x, leafNode.y, 9, 0, Math.PI * 2);
                ctx.fillStyle = "rgba(231, 76, 60, 0.18)";
                ctx.fill();
                ctx.restore();
                ctx.beginPath();
                ctx.arc(leafNode.x, leafNode.y, 7, 0, Math.PI * 2);
                ctx.strokeStyle = "rgba(231, 76, 60, 0.55)";
                ctx.lineWidth = 1;
                ctx.stroke();
            }

            ctx.beginPath();
            ctx.arc(leafNode.x, leafNode.y, dotRadius, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.fill();

            hitTargets.push({
                x: leafNode.x, y: leafNode.y,
                r: isCompromised ? 12 : 8,
                label: leafInfo.agent_id || labels[leafIdx] || "?",
                status: leafInfo.status || "?",
                clusterId: cid,
                type: "leaf",
            });
        }

        // Draw rotated leaf labels
        ctx.font = "10px 'JetBrains Mono', monospace";
        ctx.textAlign = "right";
        for (var i = 0; i < leafOrder.length; i++) {
            var leafIdx = leafOrder[i];
            var leafNode = nodes[leafIdx];
            var leafInfo = leaves[leafIdx] || {};
            var isCompromised = leafInfo.status === "compromised" || leafInfo.status === "quarantined";
            if (!isCompromised && n > 80) continue;
            var lbl = leafInfo.agent_id || labels[leafIdx] || "";
            if (lbl.length > 10) lbl = lbl.slice(0, 10) + "..";
            ctx.fillStyle = isCompromised ? "#e74c3c" : "#7f8c9b";
            ctx.save();
            ctx.translate(leafNode.x, leafNode.y + 8);
            ctx.rotate(-Math.PI / 3);
            ctx.fillText(lbl, 0, 0);
            ctx.restore();
        }

        // Y-axis scale ticks
        ctx.fillStyle = "#7f8c9b";
        ctx.strokeStyle = "#2c3e5066";
        ctx.font = "10px 'JetBrains Mono', monospace";
        ctx.textAlign = "right";
        var numTicks = 5;
        for (var t = 0; t <= numTicks; t++) {
            var frac = t / numTicks;
            var tickY = TOP_MARGIN + (1 - frac) * drawableHeight;
            var tickVal = (frac * maxHeight).toFixed(1);
            ctx.fillText(tickVal, LEFT_MARGIN - 8, tickY + 3);
            ctx.beginPath();
            ctx.setLineDash([3, 4]);
            ctx.moveTo(LEFT_MARGIN, tickY);
            ctx.lineTo(canvasWidth - RIGHT_MARGIN, tickY);
            ctx.stroke();
            ctx.setLineDash([]);
        }

        // Hit targets for internal nodes
        for (var i = n; i < nodes.length; i++) {
            var node = nodes[i];
            hitTargets.push({
                x: node.x, y: node.y, r: 6,
                label: "merge",
                mergeDistance: node.height.toFixed(2),
                size: Math.round(Z[i - n][3]),
                type: "internal",
            });
        }

        // Tooltip handler
        var tooltip = document.getElementById("dendro-tooltip");
        canvas.onmousemove = function (e) {
            var rect = canvas.getBoundingClientRect();
            var mx = e.clientX - rect.left;
            var my = e.clientY - rect.top;
            var best = null;
            var bestDist = Infinity;
            for (var i = 0; i < hitTargets.length; i++) {
                var ht = hitTargets[i];
                var dx = mx - ht.x;
                var dy = my - ht.y;
                var d = dx * dx + dy * dy;
                if (d < ht.r * ht.r && d < bestDist) {
                    best = ht;
                    bestDist = d;
                }
            }
            if (best && tooltip) {
                var tipHtml;
                if (best.type === "leaf") {
                    var parts = best.label;
                    if (best.clusterId !== undefined && best.clusterId !== -1) parts += " | C" + best.clusterId;
                    parts += " | " + best.status;
                    tipHtml = escapeHtml(parts);
                } else {
                    tipHtml = escapeHtml("merge d=" + best.mergeDistance + " | " + best.size + " members");
                }
                tooltip.innerHTML = tipHtml;
                tooltip.style.display = "block";
                tooltip.style.left = (mx + 12) + "px";
                tooltip.style.top = (my - 8) + "px";
            } else if (tooltip) {
                tooltip.style.display = "none";
            }
        };
        canvas.onmouseleave = function () {
            if (tooltip) tooltip.style.display = "none";
        };
    }

    // ---- Topic panel setup ----
    function setupTopicPanel() {
        // Panel toggle
        var toggle = document.getElementById("topic-panel-toggle");
        var body = document.getElementById("topic-panel-body");
        if (toggle && body) {
            toggle.addEventListener("click", function () {
                var isHidden = body.style.display === "none";
                body.style.display = isHidden ? "" : "none";
                toggle.classList.toggle("collapsed", !isHidden);
            });
        }

        // Tab switching
        document.querySelectorAll(".topic-tab").forEach(function (tab) {
            tab.addEventListener("click", function () {
                document.querySelectorAll(".topic-tab").forEach(function (t) { t.classList.remove("active"); });
                tab.classList.add("active");
                activeTopicTab = tab.dataset.topicTab;

                var clustersView = document.getElementById("topic-clusters-view");
                var dendroView = document.getElementById("topic-dendrogram-view");
                if (clustersView) clustersView.style.display = "none";
                if (dendroView) dendroView.style.display = "none";

                if (activeTopicTab === "dendrogram") {
                    if (dendroView) dendroView.style.display = "";
                    fetchDendrogram();
                } else {
                    if (clustersView) clustersView.style.display = "";
                    fetchTopicClusters();
                }
            });
        });
    }

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

            // Show/hide topic clusters panel
            var panel = document.getElementById("topic-clusters-panel");
            if (panel) {
                topicPanelVisible = topicViewActive;
                panel.classList.toggle("visible", topicPanelVisible);
                if (topicPanelVisible) {
                    fetchTopicClusters();
                }
            }
        });
    }

    // ---- Boot ----
    document.addEventListener("DOMContentLoaded", function () {
        initGraph();
        setupFilters();
        setupTopicToggle();
        setupTopicPanel();
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
