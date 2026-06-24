import * as fs from "fs";
import * as os from "os";
import * as path from "path";

export interface ScanVerdict {
  blocked: boolean;
  pattern_name: string;
  score: number;
}

const MAX_SCAN_BYTES = 1024 * 1024; // 1 MiB guard
const TIMEOUT_MS = 1500;

/** Read the agent's loopback bearer token (~/.prompt-gate/api-token).
 *  A Node process has no browser Origin, so the API requires the token. */
function readToken(): string | undefined {
  try {
    return fs
      .readFileSync(path.join(os.homedir(), ".prompt-gate", "api-token"), "utf8")
      .trim();
  } catch {
    return undefined;
  }
}

/** Scan `content` through the local Prompt Gate agent's DLP pipeline.
 *  Returns null on any failure (fail-open) so the editor is never blocked
 *  by an agent outage. */
export async function scan(
  agentBase: string,
  content: string,
  sessionId: string,
): Promise<ScanVerdict | null> {
  if (content.length === 0 || content.length > MAX_SCAN_BYTES) {
    return null;
  }
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const token = readToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  try {
    const res = await fetch(`${agentBase}/api/dlp/scan`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        content,
        session_id: sessionId,
        source: { destination_kind: "ai_code", element_kind: "editor" },
      }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) {
      return null;
    }
    return (await res.json()) as ScanVerdict;
  } catch {
    return null; // agent unreachable / timeout → fail open
  }
}
