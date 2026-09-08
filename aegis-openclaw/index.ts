import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

interface EvaluateResult {
  allowed: boolean;
  reason?: string;
  quarantine_active?: boolean;
  killswitch_blocked?: boolean;
  killswitch_reason?: string;
}

const evaluatorPath = fileURLToPath(
  new URL("./scripts/evaluate_action.py", import.meta.url),
);

function classifyReadWrite(toolName: string): "read" | "write" {
  const lower = toolName.toLowerCase();
  const readOnly = ["read", "get", "list", "search", "find", "view", "status"];
  return readOnly.some((part) => lower.includes(part)) ? "read" : "write";
}

function selectTarget(
  toolName: string,
  params: Record<string, unknown>,
  derivedPaths?: string[],
): string {
  const candidate =
    params.path ?? params.url ?? params.command ?? params.cmd ?? params.target;
  if (typeof candidate === "string" && candidate.length > 0) return candidate;
  if (derivedPaths && derivedPaths.length > 0) return derivedPaths.join("\n");
  return toolName;
}

function evaluate(
  pythonBinary: string,
  input: Record<string, unknown>,
): Promise<EvaluateResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn(pythonBinary, [evaluatorPath, "--json"], {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      proc.kill();
      reject(new Error("AEGIS evaluator timed out"));
    }, 10_000);
    proc.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    proc.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    proc.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    proc.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(`AEGIS evaluator exited ${code}: ${stderr}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout) as EvaluateResult);
      } catch {
        reject(new Error("AEGIS evaluator returned invalid JSON"));
      }
    });
    proc.stdin.end(JSON.stringify(input));
  });
}

export default definePluginEntry({
  id: "aegis-security",
  name: "AEGIS Security",
  description: "Fail-closed pre-tool policy enforcement for AEGIS",
  register(api) {
    api.on(
      "before_tool_call",
      async (event) => {
        const toolName = event.toolName || "unknown";
        const params = event.params || {};
        const readWrite = classifyReadWrite(toolName);
        const pluginConfig = event.context?.pluginConfig as
          | { pythonBinary?: string }
          | undefined;
        const pythonBinary =
          pluginConfig?.pythonBinary || process.env.AEGIS_PYTHON || "python3";
        const result = await evaluate(pythonBinary, {
          tool: toolName,
          action_type: "tool_call",
          target: selectTarget(toolName, params, event.derivedPaths),
          read_write: readWrite,
          args: params,
        });

        if (result.killswitch_blocked) {
          return {
            block: true,
            blockReason: result.killswitch_reason || "AEGIS killswitch is active",
          };
        }
        if (result.quarantine_active && readWrite === "write") {
          return { block: true, blockReason: "AEGIS quarantine blocks write tools" };
        }
        if (!result.allowed) {
          return { block: true, blockReason: result.reason || "AEGIS policy denied tool" };
        }
        return undefined;
      },
      { priority: 100, timeoutMs: 15_000 },
    );
  },
});
