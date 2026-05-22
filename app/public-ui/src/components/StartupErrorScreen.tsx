/// Replaces silent `process::exit(2)` with a GUI surface. The Rust side
/// stores a StartupError via Tauri-managed state at boot; this component
/// polls for it at mount and renders a red FATAL screen if present.
///
/// Backend: src-tauri/src/main.rs (StartupErrorState + get_startup_error).
import { useEffect, useState } from "react";

type StartupError = {
  code: string;
  message: string;
  doc_url?: string | null;
};

const StartupErrorScreen: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [err, setErr] = useState<StartupError | null>(null);

  useEffect(() => {
    const tauri = (window as unknown as {
      __TAURI__?: { core?: { invoke: (cmd: string) => Promise<unknown> } };
    }).__TAURI__;
    if (!tauri?.core?.invoke) return;
    void tauri.core
      .invoke("get_startup_error")
      .then(result => {
        if (result && typeof result === "object") {
          setErr(result as StartupError);
        }
      })
      .catch(() => {});
  }, []);

  if (!err) return <>{children}</>;

  return (
    <div
      role="alert"
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 9500,
        background: "#0a0a0a",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "2rem",
        fontFamily: "'DM Mono', monospace",
        color: "#ff4477",
        textAlign: "center",
      }}
    >
      <div
        style={{
          fontFamily: "'Share Tech Mono', monospace",
          letterSpacing: "0.32em",
          fontSize: "0.7rem",
          color: "#ff4477",
          marginBottom: "0.4rem",
        }}
      >
        OLYMPUS_PROTOCØL
      </div>
      <div
        style={{
          fontFamily: "'Share Tech Mono', monospace",
          fontSize: "1.2rem",
          letterSpacing: "0.16em",
          color: "#ff4477",
          marginBottom: "0.6rem",
        }}
      >
        STARTUP HALTED
      </div>
      <div
        style={{
          maxWidth: 520,
          fontSize: "0.7rem",
          color: "rgba(255,68,119,0.8)",
          lineHeight: 1.6,
          marginBottom: "1.2rem",
        }}
      >
        {err.message}
      </div>
      <div
        style={{
          fontSize: "0.55rem",
          letterSpacing: "0.1em",
          color: "rgba(255,68,119,0.5)",
        }}
      >
        code: {err.code}
      </div>
      {err.doc_url && (
        <a
          href={err.doc_url}
          target="_blank"
          rel="noopener noreferrer"
          style={{
            marginTop: "1rem",
            color: "#ff4477",
            fontSize: "0.62rem",
            letterSpacing: "0.1em",
            textDecoration: "underline",
          }}
        >
          read docs →
        </a>
      )}
    </div>
  );
};

export default StartupErrorScreen;
