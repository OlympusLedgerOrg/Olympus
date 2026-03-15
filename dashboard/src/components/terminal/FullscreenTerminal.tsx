"use client";

import { useState } from "react";

const COMMANDS: Record<string, string> = {
  help: "Commands: scan, hack, nodes, status, clear",
  scan: "Scanning global network nodes...",
  hack: "Injecting payload... bypassing firewall...",
  nodes: "Active nodes: 21",
  status: "System secure. No anomalies detected.",
};

export function FullscreenTerminal() {
  const [history, setHistory] = useState<string[]>([
    "Matrix OS v3.1",
    "Press ESC to exit",
    "Type 'help' for commands",
  ]);
  const [input, setInput] = useState("");

  function runCommand(command: string) {
    const normalized = command.trim().toLowerCase();
    if (!normalized) {
      return;
    }
    if (normalized === "clear") {
      setHistory([]);
      return;
    }
    const response = COMMANDS[normalized] ?? "Unknown command";
    setHistory((previous) => [...previous, `> ${normalized}`, response]);
  }

  return (
    <div className="flex h-full flex-col font-mono text-sm">
      <div className="mb-4 flex-1 space-y-1 overflow-y-auto">
        {history.map((line, index) => (
          <div key={`${line}-${index}`}>{line}</div>
        ))}
      </div>
      <input
        autoFocus
        value={input}
        onChange={(event) => setInput(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            runCommand(input);
            setInput("");
          }
        }}
        placeholder="enter command..."
        className="border px-3 py-2 outline-none"
        style={{ borderColor: "var(--color-primary)", background: "transparent" }}
      />
    </div>
  );
}
