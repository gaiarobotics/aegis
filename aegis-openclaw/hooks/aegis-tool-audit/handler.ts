import { spawn } from "child_process";

interface ToolCallEvent {
  tool_name: string;
  tool_args: Record<string, unknown>;
  tool_result?: string;
  read_write?: string;
}

interface EvaluateResult {
  allowed: boolean;
  decision: string;
  reason: string;
  tool: string;
  action_type: string;
  target: string;
}

function classifyReadWrite(toolName: string, args: Record<string, unknown>): string {
  const writeTools = [
    "bash",
    "write",
    "edit",
    "delete",
    "send_email",
    "send_message",
    "post",
    "put",
    "patch",
    "create",
  ];
  const lower = toolName.toLowerCase();
  for (const w of writeTools) {
    if (lower.includes(w)) return "write";
  }
  return "read";
}

function runEvaluate(input: Record<string, unknown>): Promise<EvaluateResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn("python3", [
      "aegis-openclaw/scripts/evaluate_action.py",
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
        reject(
          new Error(`evaluate_action.py exited with code ${code}: ${stderr}`)
        );
        return;
      }
      try {
        resolve(JSON.parse(stdout));
      } catch (e) {
        reject(new Error(`Failed to parse evaluate output: ${stdout}`));
      }
    });

    proc.stdin.write(JSON.stringify(input));
    proc.stdin.end();
  });
}

export default async function handler(event: ToolCallEvent): Promise<void> {
  const toolName = event.tool_name || "unknown";
  const toolArgs = event.tool_args || {};
  const readWrite = event.read_write || classifyReadWrite(toolName, toolArgs);

  // Determine target from tool args
  const target =
    (toolArgs.path as string) ||
    (toolArgs.url as string) ||
    (toolArgs.command as string) ||
    toolName;

  const input = {
    tool: toolName,
    action_type: "tool_call",
    target,
    read_write: readWrite,
  };

  try {
    const result = await runEvaluate(input);

    if (!result.allowed) {
      console.error(
        `[AEGIS] Tool call DENIED: ${toolName} -> ${target} (${result.reason})`
      );
    }
  } catch (err) {
    console.error("[AEGIS] Tool audit hook error:", err);
  }
}
