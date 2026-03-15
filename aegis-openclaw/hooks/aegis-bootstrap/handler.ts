import { spawn } from "child_process";
import { mkdirSync, writeFileSync } from "fs";
import { join } from "path";

interface BootstrapEvent {
  workspace_path: string;
}

interface StatusResult {
  mode: string;
  agent_id: string;
  modules_enabled: string[];
  scanner_sensitivity: number;
  scanner_confidence_threshold: number;
  broker_posture: string;
  state_store_enabled?: boolean;
  trust_tier?: number;
  quarantine_active?: boolean;
  quarantine_reason?: string | null;
  budget_remaining?: Record<string, number>;
  state_error?: string;
}

interface KillswitchResult {
  blocked: boolean;
  reason: string;
  is_blocked_any: boolean;
}

interface IntegrityResult {
  tampered: boolean;
  model_name: string;
  provider: string;
  detail?: string;
}

interface ThreatIntelResult {
  feed_reachable?: boolean;
  compromised_agents_count?: number;
  compromised_hashes_count?: number;
  error?: string;
}

interface NKAssessResult {
  agent_id: string;
  score: number;
  verdict: string;
  recommended_action: string;
  error?: string;
}

function runPythonScript(
  scriptName: string,
  args: string[] = [],
  stdin?: string
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const proc = spawn("python3", [
      `aegis-openclaw/scripts/${scriptName}`,
      "--json",
      ...args,
    ]);

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data: Buffer) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data: Buffer) => {
      stderr += data.toString();
    });

    proc.on("close", (code: number) => {
      if (code !== 0) {
        reject(new Error(`${scriptName} exited with code ${code}: ${stderr}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout));
      } catch (e) {
        reject(new Error(`Failed to parse ${scriptName} output: ${stdout}`));
      }
    });

    if (stdin !== undefined) {
      proc.stdin.write(stdin);
    }
    proc.stdin.end();
  });
}

export default async function handler(event: BootstrapEvent): Promise<void> {
  const workspacePath = event.workspace_path || process.cwd();
  const aegisDir = join(workspacePath, ".aegis");

  try {
    // Run all checks in parallel
    const statusPromise = runPythonScript("status.py");
    const killswitchPromise = runPythonScript("killswitch.py").catch(
      () => ({ blocked: false, reason: "", is_blocked_any: false }) as Record<string, unknown>
    );
    const threatIntelPromise = runPythonScript("threat_intel.py", [
      "--status",
    ]).catch(
      () => ({ error: "unavailable" }) as Record<string, unknown>
    );
    const nkAssessPromise = runPythonScript("nk_assess.py", [
      "--agent-id",
      "self",
    ]).catch(
      () => ({ error: "unavailable" }) as Record<string, unknown>
    );

    const [statusRaw, killswitchRaw, threatIntelRaw, nkAssessRaw] =
      await Promise.all([
        statusPromise,
        killswitchPromise,
        threatIntelPromise,
        nkAssessPromise,
      ]);

    const status = statusRaw as unknown as StatusResult;
    const killswitch = killswitchRaw as unknown as KillswitchResult;
    const threatIntel = threatIntelRaw as unknown as ThreatIntelResult;
    const nkAssess = nkAssessRaw as unknown as NKAssessResult;

    // Optional model integrity check (only if env vars are set)
    let integritySection = "";
    const modelName = process.env.AEGIS_MODEL_NAME;
    const modelProvider = process.env.AEGIS_MODEL_PROVIDER;
    if (modelName && modelProvider) {
      try {
        const integrityRaw = await runPythonScript("integrity_check.py", [
          "--model-name",
          modelName,
          "--provider",
          modelProvider,
        ]);
        const integrity = integrityRaw as unknown as IntegrityResult;
        integritySection = `
## Model Integrity

- **Model:** ${integrity.model_name} (${integrity.provider})
- **Status:** ${integrity.tampered ? "TAMPERED — " + (integrity.detail || "unknown") : "OK"}
`;
      } catch {
        // Integrity check not available
      }
    }

    // Create .aegis directory
    mkdirSync(aegisDir, { recursive: true });

    // Write status.md
    const timestamp = new Date().toISOString();
    const tierNames: Record<number, string> = {
      0: "untrusted",
      1: "provisional",
      2: "established",
      3: "vouched",
    };
    const tierNum = status.trust_tier ?? 0;
    const tierLabel = tierNames[tierNum] || "unknown";

    const br = status.budget_remaining;
    const budgetSection = br
      ? `
## Budget Remaining

- Write tool calls: ${br.write_tool_calls}
- Post messages: ${br.posts_messages}
- External HTTP writes: ${br.external_http_writes}
- New domains: ${br.new_domains}
`
      : "";

    const quarantineLabel = status.quarantine_active
      ? `ACTIVE — ${status.quarantine_reason}`
      : "none";

    const stateSection = status.state_store_enabled
      ? `
## Security State

- **Trust Tier:** ${tierLabel} (${tierNum})
- **Quarantine:** ${quarantineLabel}
${budgetSection}`
      : `
## Security State

- State store: disabled
`;

    // Killswitch section
    const killswitchSection = `
## Killswitch Status

- **Blocked:** ${killswitch.blocked ? "YES — " + killswitch.reason : "no"}
- **Any Block Active:** ${killswitch.is_blocked_any ? "yes" : "no"}
`;

    // Threat intel section
    const threatIntelSection = threatIntel.error
      ? `
## Threat Intelligence

- **Feed:** unavailable (${threatIntel.error})
`
      : `
## Threat Intelligence

- **Feed:** ${threatIntel.feed_reachable ? "connected" : "disconnected"}
- **Known compromised agents:** ${threatIntel.compromised_agents_count ?? 0}
- **Known compromised hashes:** ${threatIntel.compromised_hashes_count ?? 0}
`;

    // NK assessment section
    const nkSection = nkAssess.error
      ? ""
      : `
## Initial NK Assessment

- **Verdict:** ${nkAssess.verdict} (score=${(nkAssess.score ?? 0).toFixed(2)})
- **Recommended Action:** ${nkAssess.recommended_action}
`;

    const content = `# AEGIS Security Status

> Auto-generated at ${timestamp}

## Current Configuration

- **Mode:** ${status.mode}
- **Agent ID:** ${status.agent_id || "(auto-generated)"}
- **Modules:** ${status.modules_enabled.join(", ")}

## Scanner Settings

- Sensitivity: ${status.scanner_sensitivity}
- Confidence threshold: ${status.scanner_confidence_threshold}

## Broker Settings

- Default posture: ${status.broker_posture}
${stateSection}${killswitchSection}${threatIntelSection}${nkSection}${integritySection}
## Security Commands

### Scanning & Sanitization
- \`aegis-scan\` — Scan text for threats
- \`aegis-sanitize\` — Clean output text
- \`aegis-evaluate\` — Check action permissions

### Status & Monitoring
- \`aegis-status\` — Check current status
- \`aegis-trust\` — Check trust tier
- \`aegis-budget\` — Check remaining budget
- \`aegis-quarantine\` — Check quarantine status
- \`aegis-drift\` — Check behavioral drift
- \`aegis-killswitch\` — Check killswitch status
- \`aegis-integrity-check\` — Check model file integrity
- \`aegis-threat-intel\` — Query threat intelligence feed

### Mutations
- \`aegis-vouch\` — Record agent vouch
- \`aegis-compromise\` — Report agent compromise
- \`aegis-quarantine-manage\` — Enter/exit/escalate quarantine
- \`aegis-decay\` — Apply trust decay

### Advanced
- \`aegis-nk-assess\` — Run NK cell immune assessment
- \`aegis-memory-validate\` — Validate memory write
- \`aegis-context-snapshot\` — Save/restore context snapshots
- \`aegis-audit\` — Review security log
`;

    writeFileSync(join(aegisDir, "status.md"), content);
    console.error(`[AEGIS] Bootstrap complete: ${aegisDir}/status.md written`);
  } catch (err) {
    console.error("[AEGIS] Bootstrap hook error:", err);
  }
}
