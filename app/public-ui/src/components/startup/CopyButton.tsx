// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";

export function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }}
      style={{
        flexShrink: 0,
        background: copied ? "rgba(0,255,65,0.25)" : "rgba(0,255,65,0.08)",
        border: "1px solid rgba(0,255,65,0.5)",
        color: "#00ff41",
        fontFamily: "var(--font-terminal)",
        fontSize: "0.6rem",
        letterSpacing: "0.1em",
        padding: "0.45rem 0.85rem",
        cursor: "pointer",
      }}
    >
      {copied ? "COPIED" : "COPY"}
    </button>
  );
}
