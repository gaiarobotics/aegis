/**
 * AEGIS Epidemic Simulator — interactive frontend logic.
 *
 * Single IIFE containing all simulation control, graph rendering,
 * population charting, confusion matrix display, event logging,
 * WebSocket streaming, preset management, and result export.
 */
(function () {
    "use strict";

    // ---- State ----
    var simState = "idle";
    var tickData = [];
    var populationChart = null;
    var sigmaInstance = null;
    var graphInstance = null;
    var ws = null;
    var currentCM = "aggregate";
    var latestConfusion = {};
    var runInterval = null;
    var hashData = [];

    // ---- Utility ----
    function el(id) {
        return document.getElementById(id);
    }

    // ---- API helpers ----
    async function apiPost(path, body) {
        var resp = await fetch(path, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: body !== undefined ? JSON.stringify(body) : undefined,
        });
        if (!resp.ok) {
            var text = await resp.text();
            throw new Error("API error " + resp.status + ": " + text);
        }
        return resp.json();
    }

    async function apiGet(path) {
        var resp = await fetch(path);
        if (!resp.ok) {
            var text = await resp.text();
            throw new Error("API error " + resp.status + ": " + text);
        }
        return resp.json();
    }

    async function apiDelete(path) {
        var resp = await fetch(path, { method: "DELETE" });
        if (!resp.ok) {
            var text = await resp.text();
            throw new Error("API error " + resp.status + ": " + text);
        }
        return resp.json();
    }

    // ---- Config collection ----
    function collectConfig() {
        return {
            aegis_adoption_rate: parseInt(el("m-adoption").value) / 100,
            num_agents: parseInt(el("p-agents").value),
            max_ticks: parseInt(el("p-max-ticks").value),
            initial_infected_pct: parseFloat(el("p-infected").value) / 100,
            seed_strategy: el("p-seed-strategy").value,
            background_message_rate: parseFloat(el("p-bg-rate").value),
            recovery_ticks: parseInt(el("p-recovery").value),
            seed: el("p-seed").value ? parseInt(el("p-seed").value) : null,
            topology: {
                type: el("p-topology").value,
                mean_degree: parseInt(el("p-degree").value),
                m: parseInt(el("p-m").value),
                rewire_probability: parseFloat(el("p-rewire").value),
                num_communities: parseInt(el("p-communities").value),
                intra_probability: parseFloat(el("p-intra").value),
                inter_probability: parseFloat(el("p-inter").value),
            },
            corpus: {
                sources: [{ type: "builtin" }, { type: "moltbook_signatures" }],
                technique_probabilities: {
                    worm_propagation: parseFloat(el("p-t-worm").value),
                    memory_poisoning: parseFloat(el("p-t-memory").value),
                    role_hijacking: parseFloat(el("p-t-role").value),
                    credential_extraction: parseFloat(el("p-t-cred").value),
                    shell_injection: parseFloat(el("p-t-shell").value),
                },
            },
            modules: {
                scanner: el("m-scanner").checked,
                broker: el("m-broker").checked,
                identity: el("m-identity").checked,
                behavior: el("m-behavior").checked,
                recovery: el("m-recovery").checked,
                sensitivity: parseInt(el("m-sensitivity").value) / 100,
                confidence_threshold: parseInt(el("m-confidence").value) / 100,
                scanner_toggles: {
                    pattern_matching: el("m-pattern").checked,
                    semantic_analysis: el("m-semantic").checked,
                    content_gate: el("m-gate").checked,
                },
            },
        };
    }

    // ---- Config application (reverse of collectConfig) ----
    function applyConfig(cfg) {
        if (!cfg) return;
        if (cfg.aegis_adoption_rate !== undefined) {
            var adoptVal = Math.round(cfg.aegis_adoption_rate * 100);
            el("m-adoption").value = adoptVal;
            el("adoption-val").textContent = cfg.aegis_adoption_rate.toFixed(2);
        }
        if (cfg.num_agents !== undefined) el("p-agents").value = cfg.num_agents;
        if (cfg.max_ticks !== undefined) el("p-max-ticks").value = cfg.max_ticks;
        if (cfg.initial_infected_pct !== undefined) el("p-infected").value = Math.round(cfg.initial_infected_pct * 100);
        if (cfg.seed_strategy !== undefined) el("p-seed-strategy").value = cfg.seed_strategy;
        if (cfg.background_message_rate !== undefined) el("p-bg-rate").value = cfg.background_message_rate;
        if (cfg.recovery_ticks !== undefined) el("p-recovery").value = cfg.recovery_ticks;
        if (cfg.seed !== undefined && cfg.seed !== null) {
            el("p-seed").value = cfg.seed;
        } else {
            el("p-seed").value = "";
        }

        if (cfg.topology) {
            if (cfg.topology.type !== undefined) el("p-topology").value = cfg.topology.type;
            if (cfg.topology.mean_degree !== undefined) el("p-degree").value = cfg.topology.mean_degree;
            if (cfg.topology.m !== undefined) el("p-m").value = cfg.topology.m;
            if (cfg.topology.rewire_probability !== undefined) el("p-rewire").value = cfg.topology.rewire_probability;
            if (cfg.topology.num_communities !== undefined) el("p-communities").value = cfg.topology.num_communities;
            if (cfg.topology.intra_probability !== undefined) el("p-intra").value = cfg.topology.intra_probability;
            if (cfg.topology.inter_probability !== undefined) el("p-inter").value = cfg.topology.inter_probability;
        }

        if (cfg.corpus && cfg.corpus.technique_probabilities) {
            var tp = cfg.corpus.technique_probabilities;
            if (tp.worm_propagation !== undefined) el("p-t-worm").value = tp.worm_propagation;
            if (tp.memory_poisoning !== undefined) el("p-t-memory").value = tp.memory_poisoning;
            if (tp.role_hijacking !== undefined) el("p-t-role").value = tp.role_hijacking;
            if (tp.credential_extraction !== undefined) el("p-t-cred").value = tp.credential_extraction;
            if (tp.shell_injection !== undefined) el("p-t-shell").value = tp.shell_injection;
        }

        if (cfg.modules) {
            if (cfg.modules.scanner !== undefined) el("m-scanner").checked = cfg.modules.scanner;
            if (cfg.modules.broker !== undefined) el("m-broker").checked = cfg.modules.broker;
            if (cfg.modules.identity !== undefined) el("m-identity").checked = cfg.modules.identity;
            if (cfg.modules.behavior !== undefined) el("m-behavior").checked = cfg.modules.behavior;
            if (cfg.modules.recovery !== undefined) el("m-recovery").checked = cfg.modules.recovery;
            if (cfg.modules.sensitivity !== undefined) {
                var sensVal = Math.round(cfg.modules.sensitivity * 100);
                el("m-sensitivity").value = sensVal;
                el("sensitivity-val").textContent = cfg.modules.sensitivity.toFixed(2);
            }
            if (cfg.modules.confidence_threshold !== undefined) {
                var confVal = Math.round(cfg.modules.confidence_threshold * 100);
                el("m-confidence").value = confVal;
                el("confidence-val").textContent = cfg.modules.confidence_threshold.toFixed(2);
            }
            if (cfg.modules.scanner_toggles) {
                var st = cfg.modules.scanner_toggles;
                if (st.pattern_matching !== undefined) el("m-pattern").checked = st.pattern_matching;
                if (st.semantic_analysis !== undefined) el("m-semantic").checked = st.semantic_analysis;
                if (st.content_gate !== undefined) el("m-gate").checked = st.content_gate;
            }
        }
    }

    // ---- Simulation control ----
    async function doGenerate() {
        try {
            var config = collectConfig();
            var resp = await apiPost("/api/v1/simulator/generate", config);
            simState = resp.state || "ready";
            updateControls();
            logEvent({ tick: 0, type: "system", message: "Scenario generated (" + config.num_agents + " agents)" });
            await fetchGraph();
        } catch (err) {
            logEvent({ tick: 0, type: "error", message: "Generate failed: " + err.message });
        }
    }

    async function doStart() {
        try {
            var resp = await apiPost("/api/v1/simulator/start");
            simState = resp.state || "running";
            updateControls();
            logEvent({ tick: 0, type: "system", message: "Simulation started" });
            // Begin running at the configured speed
            var speed = parseInt(el("speed-slider").value);
            await apiPost("/api/v1/simulator/run", { ticks_per_second: speed });
        } catch (err) {
            logEvent({ tick: 0, type: "error", message: "Start failed: " + err.message });
        }
    }

    async function doPause() {
        try {
            var resp = await apiPost("/api/v1/simulator/pause");
            simState = resp.state || "paused";
            updateControls();
            logEvent({ tick: parseInt(el("tick-counter").textContent), type: "system", message: "Simulation paused" });
        } catch (err) {
            logEvent({ tick: 0, type: "error", message: "Pause failed: " + err.message });
        }
    }

    async function doResume() {
        try {
            var resp = await apiPost("/api/v1/simulator/resume");
            simState = resp.state || "running";
            updateControls();
            logEvent({ tick: parseInt(el("tick-counter").textContent), type: "system", message: "Simulation resumed" });
            // Resume running at configured speed
            var speed = parseInt(el("speed-slider").value);
            await apiPost("/api/v1/simulator/run", { ticks_per_second: speed });
        } catch (err) {
            logEvent({ tick: 0, type: "error", message: "Resume failed: " + err.message });
        }
    }

    async function doStop() {
        try {
            var resp = await apiPost("/api/v1/simulator/stop");
            simState = resp.state || "completed";
            updateControls();
            logEvent({ tick: parseInt(el("tick-counter").textContent), type: "system", message: "Simulation stopped" });
        } catch (err) {
            logEvent({ tick: 0, type: "error", message: "Stop failed: " + err.message });
        }
    }

    async function doStep() {
        try {
            var resp = await apiPost("/api/v1/simulator/tick");
            if (resp) {
                handleSnapshot(resp);
            }
            logEvent({ tick: parseInt(el("tick-counter").textContent), type: "system", message: "Single step executed" });
        } catch (err) {
            logEvent({ tick: 0, type: "error", message: "Step failed: " + err.message });
        }
    }

    async function doReset() {
        try {
            await apiPost("/api/v1/simulator/reset");
            simState = "idle";
            updateControls();
            // Clear chart data
            tickData = [];
            if (populationChart) {
                populationChart.data.labels = [];
                populationChart.data.datasets.forEach(function (ds) { ds.data = []; });
                populationChart.update();
            }
            // Clear graph
            if (graphInstance) {
                graphInstance.clear();
                if (sigmaInstance) sigmaInstance.refresh();
            }
            // Clear confusion matrix
            latestConfusion = {};
            showConfusion("aggregate");
            // Clear hash database
            hashData = [];
            var hashBody = el("hash-table-body");
            if (hashBody) hashBody.innerHTML = "";
            el("hash-count").textContent = "0";
            // Clear stats
            el("tick-counter").textContent = "0";
            el("stat-r0").textContent = "-";
            el("stat-re").textContent = "-";
            el("stat-infections").textContent = "0";
            el("stat-detection-rate").textContent = "-";
            el("stat-fpr").textContent = "-";
            el("stat-mttq").textContent = "-";
            el("stat-clusters").textContent = "-";
            // Clear event log
            el("event-log").innerHTML = "";
            logEvent({ tick: 0, type: "system", message: "Simulation reset" });
        } catch (err) {
            logEvent({ tick: 0, type: "error", message: "Reset failed: " + err.message });
        }
    }

    // ---- Presets ----
    async function loadPresetList() {
        try {
            var data = await apiGet("/api/v1/simulator/presets");
            var select = el("preset-select");
            // Keep the first option
            select.innerHTML = '<option value="">-- Select Preset --</option>';
            var presets = data.presets || data || [];
            presets.forEach(function (p) {
                var name = typeof p === "string" ? p : p.name;
                var option = document.createElement("option");
                option.value = name;
                option.textContent = name;
                select.appendChild(option);
            });
        } catch (err) {
            console.warn("Failed to load presets:", err);
            logEvent({ tick: 0, type: "error", message: "Failed to load presets: " + err.message });
        }
    }

    async function loadPreset() {
        var name = el("preset-select").value;
        if (!name) return;
        try {
            var data = await apiGet("/api/v1/simulator/presets/" + encodeURIComponent(name));
            applyConfig(data.config || data);
            logEvent({ tick: 0, type: "system", message: "Preset loaded: " + name });
        } catch (err) {
            logEvent({ tick: 0, type: "error", message: "Failed to load preset: " + err.message });
        }
    }

    async function savePreset() {
        var name = el("preset-name").value.trim();
        if (!name) return;
        try {
            var config = collectConfig();
            await apiPost("/api/v1/simulator/presets", { name: name, config: config });
            el("preset-name").value = "";
            logEvent({ tick: 0, type: "system", message: "Preset saved: " + name });
            await loadPresetList();
        } catch (err) {
            logEvent({ tick: 0, type: "error", message: "Failed to save preset: " + err.message });
        }
    }

    async function deletePreset() {
        var name = el("preset-select").value;
        if (!name) return;
        try {
            await apiDelete("/api/v1/simulator/presets/" + encodeURIComponent(name));
            logEvent({ tick: 0, type: "system", message: "Preset deleted: " + name });
            await loadPresetList();
        } catch (err) {
            logEvent({ tick: 0, type: "error", message: "Failed to delete preset: " + err.message });
        }
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

    // ---- Graph rendering ----
    function initGraph() {
        graphInstance = new graphology.Graph({ multi: false, type: "undirected" });
        var container = el("sim-graph-canvas");
        if (!container) return;

        var AegisBorderProgram = createNodeBorderProgram({
            borders: [
                { size: { attribute: "borderSize", defaultValue: 0, mode: "relative" }, color: { attribute: "borderColor", defaultValue: "#00000000" } },
                { size: { fill: true }, color: { attribute: "color" } },
            ],
        });

        sigmaInstance = new Sigma(graphInstance, container, {
            renderLabels: true,
            labelColor: { color: "#e0e6ed" },
            labelSize: 10,
            labelDensity: 2,
            labelRenderedSizeThreshold: 3,
            defaultNodeColor: "#95a5a6",
            defaultEdgeColor: "#2c3e50",
            minCameraRatio: 0.1,
            maxCameraRatio: 10,
            defaultNodeType: "bordered",
            nodeProgramClasses: { bordered: AegisBorderProgram },
            defaultDrawNodeHover: drawDarkHover,
        });
    }

    async function fetchGraph() {
        try {
            var data = await apiGet("/api/v1/simulator/graph");
            renderGraph(data);
        } catch (err) {
            // Graph endpoint may not be available yet
        }
    }

    function renderGraph(data) {
        if (!graphInstance) return;
        graphInstance.clear();

        var nodes = data.nodes || [];
        var edges = data.edges || [];
        var n = nodes.length;

        nodes.forEach(function (node, i) {
            var angle = (2 * Math.PI * i) / Math.max(n, 1);
            var r = 10;
            var baseColor = statusColor(node.status || "clean");
            var hasAegis = node.has_aegis || false;
            graphInstance.addNode(node.id, {
                x: r * Math.cos(angle),
                y: r * Math.sin(angle),
                size: 5 + (node.degree || 1) * 0.5,
                color: baseColor,
                borderColor: hasAegis ? "#ffffff" : "#00000000",
                borderSize: hasAegis ? 0.2 : 0,
                label: String(node.id),
                forceLabel: true,
            });
        });

        edges.forEach(function (edge) {
            var key = edge.source + "-" + edge.target;
            if (!graphInstance.hasEdge(key)) {
                try {
                    graphInstance.addEdgeWithKey(key, edge.source, edge.target, {
                        size: 0.5,
                        color: "#2c3e5050",
                    });
                } catch (e) {
                    // Skip duplicate or invalid edges
                }
            }
        });

        if (sigmaInstance) sigmaInstance.refresh();
    }

    function statusColor(status) {
        switch (status) {
            case "clean":       return "#2ecc71";
            case "infected":    return "#e74c3c";
            case "quarantined": return "#e67e22";
            case "recovered":   return "#3498db";
            default:            return "#95a5a6";
        }
    }

    // ---- Population chart ----
    function initChart() {
        var canvas = el("population-chart");
        if (!canvas) return;
        var ctx = canvas.getContext("2d");
        populationChart = new Chart(ctx, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "Clean",
                        borderColor: "#2ecc71",
                        backgroundColor: "#2ecc7133",
                        fill: true,
                        data: [],
                        tension: 0.3,
                        pointRadius: 0,
                    },
                    {
                        label: "Infected",
                        borderColor: "#e74c3c",
                        backgroundColor: "#e74c3c33",
                        fill: true,
                        data: [],
                        tension: 0.3,
                        pointRadius: 0,
                    },
                    {
                        label: "Quarantined",
                        borderColor: "#e67e22",
                        backgroundColor: "#e67e2233",
                        fill: true,
                        data: [],
                        tension: 0.3,
                        pointRadius: 0,
                    },
                    {
                        label: "Recovered",
                        borderColor: "#3498db",
                        backgroundColor: "#3498db33",
                        fill: true,
                        data: [],
                        tension: 0.3,
                        pointRadius: 0,
                    },
                    {
                        label: "Seed R",
                        borderColor: "#f1c40f",
                        borderDash: [5, 5],
                        data: [],
                        yAxisID: "y1",
                        fill: false,
                        tension: 0.3,
                        pointRadius: 0,
                    },
                    {
                        label: "R\u2091",
                        borderColor: "#e67e22",
                        borderDash: [2, 3],
                        data: [],
                        yAxisID: "y1",
                        fill: false,
                        tension: 0.3,
                        pointRadius: 0,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        title: { display: true, text: "Tick", color: "#7f8c9b" },
                        ticks: { color: "#7f8c9b" },
                        grid: { color: "#1a283666" },
                    },
                    y: {
                        title: { display: true, text: "% of Population", color: "#7f8c9b" },
                        ticks: { color: "#7f8c9b" },
                        grid: { color: "#1a283666" },
                        min: 0,
                        max: 100,
                    },
                    y1: {
                        position: "right",
                        title: { display: true, text: "Seed R / R\u2091", color: "#f1c40f" },
                        ticks: { color: "#f1c40f" },
                        grid: { drawOnChartArea: false },
                        min: 0,
                    },
                },
                plugins: {
                    legend: { labels: { color: "#e0e6ed" } },
                },
                animation: { duration: 0 },
            },
        });
    }

    function updateChart(snapshot) {
        if (!populationChart || !snapshot.counts) return;
        var total = Object.values(snapshot.counts).reduce(function (a, b) { return a + b; }, 0) || 1;
        populationChart.data.labels.push(snapshot.tick);
        populationChart.data.datasets[0].data.push((snapshot.counts.clean || 0) / total * 100);
        populationChart.data.datasets[1].data.push((snapshot.counts.infected || 0) / total * 100);
        populationChart.data.datasets[2].data.push((snapshot.counts.quarantined || 0) / total * 100);
        populationChart.data.datasets[3].data.push((snapshot.counts.recovered || 0) / total * 100);
        populationChart.data.datasets[4].data.push(snapshot.seed_r || 0);
        populationChart.data.datasets[5].data.push(snapshot.re || 0);
        populationChart.update();
    }

    // ---- Confusion matrix ----
    function updateConfusionMatrix(confusion) {
        if (!confusion) return;
        latestConfusion = confusion;
        showConfusion(currentCM);
    }

    function showConfusion(key) {
        var cm = (latestConfusion && latestConfusion[key]) || { tp: 0, fp: 0, fn: 0, tn: 0, precision: 0, recall: 0, f1: 0, fpr: 0 };
        el("cm-tp").textContent = cm.tp || 0;
        el("cm-fp").textContent = cm.fp || 0;
        el("cm-fn").textContent = cm.fn || 0;
        el("cm-tn").textContent = cm.tn || 0;
        el("cm-precision").textContent = (cm.precision || 0).toFixed(3);
        el("cm-recall").textContent = (cm.recall || 0).toFixed(3);
        el("cm-f1").textContent = (cm.f1 || 0).toFixed(3);
        el("cm-fpr").textContent = (cm.fpr || 0).toFixed(3);
    }

    // ---- Summary stats ----
    function updateStats(snapshot) {
        if (!snapshot) return;
        el("stat-r0").textContent = (snapshot.seed_r || 0).toFixed(2);
        el("stat-re").textContent = (snapshot.re || 0).toFixed(2);

        var counts = snapshot.counts || {};
        var totalInfected = (counts.infected || 0) + (counts.quarantined || 0) + (counts.recovered || 0);
        el("stat-infections").textContent = totalInfected;

        var cm = (snapshot.confusion && snapshot.confusion.aggregate) || {};
        el("stat-detection-rate").textContent = cm.recall ? (cm.recall * 100).toFixed(1) + "%" : "-";
        el("stat-fpr").textContent = cm.fpr ? (cm.fpr * 100).toFixed(1) + "%" : "-";

        if (snapshot.mttq !== undefined && snapshot.mttq !== null) {
            el("stat-mttq").textContent = snapshot.mttq.toFixed(1) + "t";
        }
    }

    // ---- Event log ----
    function logEvent(evt) {
        var log = el("event-log");
        if (!log) return;
        var line = document.createElement("div");
        var type = evt.type || "info";
        line.className = "log-line log-" + type;

        var tick = evt.tick !== undefined ? evt.tick : "?";
        var message = evt.message || JSON.stringify(evt);
        line.textContent = "[" + tick + "] " + type + ": " + message;

        log.appendChild(line);

        // Cap at 200 entries
        while (log.children.length > 200) {
            log.removeChild(log.firstChild);
        }

        log.scrollTop = log.scrollHeight;
    }

    // ---- WebSocket ----
    function connectWS() {
        var proto = location.protocol === "https:" ? "wss:" : "ws:";
        var url = proto + "//" + location.host + "/ws/simulator";
        try {
            ws = new WebSocket(url);
        } catch (err) {
            setTimeout(connectWS, 3000);
            return;
        }

        ws.onopen = function () {
            el("ws-status").className = "ws-status connected";
        };

        ws.onclose = function () {
            el("ws-status").className = "ws-status disconnected";
            setTimeout(connectWS, 3000);
        };

        ws.onerror = function () {
            ws.close();
        };

        ws.onmessage = function (e) {
            try {
                var snapshot = JSON.parse(e.data);
                handleSnapshot(snapshot);
            } catch (err) {
                // Ignore malformed messages
            }
        };
    }

    function handleSnapshot(snapshot) {
        if (!snapshot) return;

        // Update tick counter
        if (snapshot.tick !== undefined) {
            el("tick-counter").textContent = snapshot.tick;
        }

        // Update population chart
        updateChart(snapshot);

        // Update confusion matrix
        if (snapshot.confusion) {
            updateConfusionMatrix(snapshot.confusion);
        }

        // Update summary stats
        updateStats(snapshot);

        // Update graph node colors for status changes
        if (snapshot.status_changes && snapshot.status_changes.length > 0 && graphInstance) {
            snapshot.status_changes.forEach(function (change) {
                if (graphInstance.hasNode(change.agent_id)) {
                    graphInstance.setNodeAttribute(change.agent_id, "color", statusColor(change.to));
                }
            });
            if (sigmaInstance) sigmaInstance.refresh();
        }

        // Update cluster count
        if (snapshot.cluster_summary && snapshot.cluster_summary.num_clusters !== undefined) {
            el("stat-clusters").textContent = snapshot.cluster_summary.num_clusters;
        }

        // Auto-fetch hash DB if hash-tab is visible
        var hashTab = document.getElementById("hash-tab");
        if (hashTab && hashTab.style.display !== "none") {
            fetchHashDatabase();
        }

        // Log events
        if (snapshot.events && snapshot.events.length > 0) {
            snapshot.events.forEach(logEvent);
        }

        // Store tick data for export
        tickData.push(snapshot);

        // Sync simulation state from engine
        if (snapshot.state) {
            simState = snapshot.state;
            updateControls();
        }
    }

    // ---- Controls ----
    function updateControls() {
        el("btn-generate").disabled = simState !== "idle";
        el("btn-start").disabled = simState !== "ready";
        el("btn-pause").disabled = simState !== "running";
        el("btn-pause").style.display = simState === "running" ? "" : "none";
        el("btn-resume").disabled = simState !== "paused";
        el("btn-resume").style.display = simState === "paused" ? "" : "none";
        el("btn-stop").disabled = !(simState === "running" || simState === "paused");
        el("btn-step").disabled = !(simState === "ready" || simState === "running" || simState === "paused");
        el("btn-reset").disabled = simState === "idle";

        // Disable parameter inputs when simulation is not idle
        var inputs = document.querySelectorAll(".sim-sidebar-left input, .sim-sidebar-left select");
        inputs.forEach(function (inp) {
            inp.disabled = simState !== "idle";
        });
    }

    // ---- Export ----
    async function doExport() {
        try {
            var data = await apiGet("/api/v1/simulator/export");
            var blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
            var url = URL.createObjectURL(blob);
            var a = document.createElement("a");
            a.href = url;
            a.download = "aegis-sim-results.json";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (err) {
            // Fallback: export local tick data
            var blob = new Blob([JSON.stringify(tickData, null, 2)], { type: "application/json" });
            var url = URL.createObjectURL(blob);
            var a = document.createElement("a");
            a.href = url;
            a.download = "aegis-sim-results.json";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
    }

    // ---- Hash Database ----
    async function fetchHashDatabase() {
        try {
            hashData = await apiGet("/api/v1/simulator/embeddings");
            renderHashTable();
        } catch (err) {
            hashData = [];
            renderHashTable();
        }
    }

    function renderHashTable() {
        var tbody = el("hash-table-body");
        if (!tbody) return;
        tbody.innerHTML = "";

        var search = (el("hash-search").value || "").toLowerCase();
        var statusFilter = el("hash-status-filter").value;

        var filtered = hashData.filter(function (entry) {
            if (statusFilter && entry.status !== statusFilter) return false;
            if (search) {
                var matchId = entry.agent_id.toLowerCase().indexOf(search) !== -1;
                var matchHash = entry.hash && entry.hash.toLowerCase().indexOf(search) !== -1;
                if (!matchId && !matchHash) return false;
            }
            return true;
        });

        el("hash-count").textContent = filtered.length;

        filtered.forEach(function (entry) {
            var tr = document.createElement("tr");
            tr.className = "hash-row";

            var expandTd = document.createElement("td");
            expandTd.className = "hash-expand";
            expandTd.textContent = "\u25B6";
            tr.appendChild(expandTd);

            var agentTd = document.createElement("td");
            agentTd.textContent = entry.agent_id;
            tr.appendChild(agentTd);

            var hashTd = document.createElement("td");
            hashTd.className = "hash-cell-mono";
            hashTd.textContent = entry.hash ? entry.hash.substring(0, 16) + "..." : "-";
            hashTd.title = entry.hash || "";
            tr.appendChild(hashTd);

            var statusTd = document.createElement("td");
            var badge = document.createElement("span");
            badge.className = "hash-badge hash-badge-" + entry.status;
            badge.textContent = entry.status;
            statusTd.appendChild(badge);
            tr.appendChild(statusTd);

            var clusterTd = document.createElement("td");
            clusterTd.textContent = entry.cluster_id !== undefined ? entry.cluster_id : "-";
            tr.appendChild(clusterTd);

            var contagionTd = document.createElement("td");
            var score = entry.contagion_score || 0;
            contagionTd.textContent = score.toFixed(3);
            if (score >= 0.85) contagionTd.style.color = "var(--red)";
            else if (score >= 0.5) contagionTd.style.color = "var(--orange)";
            tr.appendChild(contagionTd);

            tbody.appendChild(tr);

            // Detail row for neighbors (hidden by default)
            var detailTr = document.createElement("tr");
            detailTr.className = "hash-detail-row";
            detailTr.style.display = "none";
            var detailTd = document.createElement("td");
            detailTd.colSpan = 6;
            detailTd.innerHTML = buildNeighborHTML(entry.neighbors || []);
            detailTr.appendChild(detailTd);
            tbody.appendChild(detailTr);

            // Toggle expand
            tr.addEventListener("click", function () {
                var isVisible = detailTr.style.display !== "none";
                detailTr.style.display = isVisible ? "none" : "table-row";
                expandTd.textContent = isVisible ? "\u25B6" : "\u25BC";
            });
        });
    }

    function buildNeighborHTML(neighbors) {
        if (!neighbors || neighbors.length === 0) {
            return '<div class="hash-neighbors"><em>No neighbors</em></div>';
        }
        var html = '<div class="hash-neighbors"><table class="neighbor-table">';
        html += '<tr><th>Agent</th><th>Distance</th><th>Status</th><th>Hash</th></tr>';
        neighbors.forEach(function (n) {
            var pct = Math.min(100, (n.distance / 128) * 100);
            html += '<tr>';
            html += '<td>' + n.agent_id + '</td>';
            html += '<td><div class="dist-bar"><div class="dist-fill" style="width:' + pct + '%"></div></div><span>' + n.distance + '</span></td>';
            html += '<td><span class="hash-badge hash-badge-' + n.status + '">' + n.status + '</span></td>';
            html += '<td class="hash-cell-mono">' + (n.hash || '-') + '</td>';
            html += '</tr>';
        });
        html += '</table></div>';
        return html;
    }

    // ---- Collapsible panels ----
    function setupPanels() {
        document.querySelectorAll(".panel-header").forEach(function (header) {
            header.addEventListener("click", function () {
                var targetId = header.dataset.toggle;
                if (targetId) {
                    var body = document.getElementById(targetId);
                    if (body) {
                        var isHidden = body.style.display === "none";
                        body.style.display = isHidden ? "" : "none";
                        header.classList.toggle("collapsed", !isHidden);
                    }
                }
            });
        });
    }

    // ---- Tabs ----
    function setupTabs() {
        // Center tabs (Graph / Chart)
        document.querySelectorAll(".tab").forEach(function (tab) {
            tab.addEventListener("click", function () {
                document.querySelectorAll(".tab").forEach(function (t) {
                    t.classList.remove("active");
                });
                tab.classList.add("active");
                document.querySelectorAll(".tab-content").forEach(function (tc) {
                    tc.style.display = "none";
                });
                var target = document.getElementById(tab.dataset.tab);
                if (target) target.style.display = "";

                // Resize chart when switching to chart tab
                if (tab.dataset.tab === "chart-tab" && populationChart) {
                    populationChart.resize();
                }
                // Refresh sigma when switching to graph tab
                if (tab.dataset.tab === "graph-tab" && sigmaInstance) {
                    sigmaInstance.refresh();
                }
                // Fetch hash data when switching to hash tab
                if (tab.dataset.tab === "hash-tab") {
                    fetchHashDatabase();
                }
            });
        });

        // Confusion matrix tabs
        document.querySelectorAll(".cm-tab").forEach(function (tab) {
            tab.addEventListener("click", function () {
                document.querySelectorAll(".cm-tab").forEach(function (t) {
                    t.classList.remove("active");
                });
                tab.classList.add("active");
                currentCM = tab.dataset.cm;
                showConfusion(currentCM);
            });
        });
    }

    // ---- Boot ----
    document.addEventListener("DOMContentLoaded", function () {
        initGraph();
        initChart();
        setupPanels();
        setupTabs();
        updateControls();
        loadPresetList();
        connectWS();

        // Speed slider
        el("speed-slider").addEventListener("input", function (e) {
            el("speed-label").textContent = e.target.value;
        });

        // Adoption rate slider
        el("m-adoption").addEventListener("input", function (e) {
            el("adoption-val").textContent = (e.target.value / 100).toFixed(2);
        });

        // Sensitivity slider
        el("m-sensitivity").addEventListener("input", function (e) {
            el("sensitivity-val").textContent = (e.target.value / 100).toFixed(2);
        });

        // Confidence slider
        el("m-confidence").addEventListener("input", function (e) {
            el("confidence-val").textContent = (e.target.value / 100).toFixed(2);
        });

        // Hash database search/filter
        el("hash-search").addEventListener("input", renderHashTable);
        el("hash-status-filter").addEventListener("change", renderHashTable);

        // Button handlers
        el("btn-generate").addEventListener("click", doGenerate);
        el("btn-start").addEventListener("click", doStart);
        el("btn-pause").addEventListener("click", doPause);
        el("btn-resume").addEventListener("click", doResume);
        el("btn-stop").addEventListener("click", doStop);
        el("btn-step").addEventListener("click", doStep);
        el("btn-reset").addEventListener("click", doReset);
        el("btn-export").addEventListener("click", doExport);
        el("btn-load-preset").addEventListener("click", loadPreset);
        el("btn-save-preset").addEventListener("click", savePreset);
        el("btn-delete-preset").addEventListener("click", deletePreset);
    });
})();


