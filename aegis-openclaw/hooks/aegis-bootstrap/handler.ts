import { spawn } from "child_process";
import { mkdirSync, writeFileSync } from "fs";
import { join } from "path";

interface BootstrapEvent {
  workspace_path: string;
}

interface StatusResult {
  mode: string;
  killswitch_active: boolean;
  agent_id: string;
  modules_enabled: string[];
  scanner_sensitivity: number;
  scanner_confidence_threshold: number;
  broker_posture: string;
}

function getStatus(): Promise<StatusResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn("python3", [
      "aegis-openclaw/scripts/status.py",
      "--json",
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
        reject(new Error(`status.py exited with code ${code}: ${stderr}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout));
      } catch (e) {
        reject(new Error(`Failed to parse status output: ${stdout}`));
      }
    });
  });
}

export default async function handler(event: BootstrapEvent): Promise<void> {
  const workspacePath = event.workspace_path || process.cwd();
  const aegisDir = join(workspacePath, ".aegis");

  try {
    const status = await getStatus();

    // Create .aegis directory
    mkdirSync(aegisDir, { recursive: true });

    // Write status.md
    const timestamp = new Date().toISOString();
    const content = `# AEGIS Security Status

> Auto-generated at ${timestamp}

## Current Configuration

- **Mode:** ${status.mode}
- **Killswitch:** ${status.killswitch_active ? "ACTIVE (all checks bypassed)" : "inactive"}
- **Agent ID:** ${status.agent_id || "(auto-generated)"}
- **Modules:** ${status.modules_enabled.join(", ")}

## Scanner Settings

- Sensitivity: ${status.scanner_sensitivity}
- Confidence threshold: ${status.scanner_confidence_threshold}

## Broker Settings

- Default posture: ${status.broker_posture}

## Security Commands

- \`aegis-scan\` — Scan text for threats
- \`aegis-sanitize\` — Clean output text
- \`aegis-evaluate\` — Check action permissions
- \`aegis-audit\` — Review security log
- \`aegis-status\` — Check current status
`;

    writeFileSync(join(aegisDir, "status.md"), content);
    console.error(`[AEGIS] Bootstrap complete: ${aegisDir}/status.md written`);
  } catch (err) {
    console.error("[AEGIS] Bootstrap hook error:", err);
  }
}
