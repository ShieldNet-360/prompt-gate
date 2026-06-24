import * as vscode from "vscode";
import { randomUUID } from "crypto";
import { scan } from "./scanClient";

const MIN_DELTA_BYTES = 50; // ignore tiny edits — mirrors the browser interceptor
const DEBOUNCE_MS = 200;

// Each scan uses a fresh session id so the agent's multi-piece
// correlator judges every debounced edit independently. A persistent
// per-editor session would keep flagging benign edits for the
// correlator TTL after a real secret — confusing in a live editor.

export function activate(context: vscode.ExtensionContext): void {
  const status = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100,
  );
  status.text = "$(shield) Prompt Gate";
  status.tooltip = "Prompt Gate DLP — scanning edits for secrets before they reach an AI assistant";
  status.show();
  context.subscriptions.push(status);

  const agentBase = (): string =>
    vscode.workspace
      .getConfiguration("promptGate")
      .get<string>("agentUrl", "http://127.0.0.1:9191");

  // Debounced scan of incoming edits.
  let timer: ReturnType<typeof setTimeout> | undefined;
  const recentlyWarned = new Set<string>();

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (
        !vscode.workspace
          .getConfiguration("promptGate")
          .get<boolean>("scanOnEdit", true)
      ) {
        return;
      }
      const added = e.contentChanges.map((c) => c.text).join("");
      if (added.length < MIN_DELTA_BYTES) {
        return;
      }
      if (timer) {
        clearTimeout(timer);
      }
      timer = setTimeout(() => void check(added), DEBOUNCE_MS);
    }),
  );

  async function check(text: string): Promise<void> {
    const verdict = await scan(agentBase(), text, randomUUID());
    if (!verdict?.blocked) {
      return;
    }
    const key = verdict.pattern_name + "|" + text.slice(0, 24);
    if (recentlyWarned.has(key)) {
      return; // don't spam the same finding
    }
    recentlyWarned.add(key);
    setTimeout(() => recentlyWarned.delete(key), 10_000);

    void vscode.window.showWarningMessage(
      `Prompt Gate: ${verdict.pattern_name} detected — don't paste this into an AI assistant.`,
      "Dismiss",
    );
    status.text = "$(shield) Prompt Gate: secret detected";
    setTimeout(() => {
      status.text = "$(shield) Prompt Gate";
    }, 5_000);
  }

  // On-demand scan of the current selection (or whole file).
  context.subscriptions.push(
    vscode.commands.registerCommand("promptGate.scanSelection", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        return;
      }
      const text =
        editor.document.getText(editor.selection) || editor.document.getText();
      const verdict = await scan(agentBase(), text, randomUUID());
      if (!verdict) {
        void vscode.window.showInformationMessage(
          "Prompt Gate: agent not reachable — is the Prompt Gate app running?",
        );
        return;
      }
      void vscode.window.showInformationMessage(
        verdict.blocked
          ? `Prompt Gate: BLOCKED — ${verdict.pattern_name} (score ${verdict.score})`
          : "Prompt Gate: no secrets detected.",
      );
    }),
  );
}

export function deactivate(): void {
  /* nothing to clean up */
}
