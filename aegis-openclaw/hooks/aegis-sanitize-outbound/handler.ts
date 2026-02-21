import { spawn } from "child_process";

interface HookEvent {
  messages: Array<{ role: string; content: string }>;
}

interface SanitizeResult {
  cleaned_text: string;
  modifications: string[];
  was_modified: boolean;
}

function runSanitize(text: string): Promise<SanitizeResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn("python3", [
      "aegis-openclaw/scripts/sanitize.py",
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
        reject(new Error(`sanitize.py exited with code ${code}: ${stderr}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout));
      } catch (e) {
        reject(new Error(`Failed to parse sanitize output: ${stdout}`));
      }
    });

    proc.stdin.write(text);
    proc.stdin.end();
  });
}

export default async function handler(event: HookEvent): Promise<HookEvent> {
  const lastMessage = event.messages[event.messages.length - 1];
  if (!lastMessage || lastMessage.role !== "assistant") {
    return event;
  }

  const text =
    typeof lastMessage.content === "string"
      ? lastMessage.content
      : JSON.stringify(lastMessage.content);

  try {
    const result = await runSanitize(text);

    if (result.was_modified) {
      console.error(
        `[AEGIS] Outbound message sanitized: ${result.modifications.join(", ")}`
      );
      lastMessage.content = result.cleaned_text;
    }
  } catch (err) {
    console.error("[AEGIS] Sanitize hook error:", err);
  }

  return event;
}
