/**
 * olympus-full.tsx — Olympus Public Verification Dashboard
 * "Project Mayhem" Edition
 *
 * Self-contained React component for journalists and activists to verify
 * ledger proofs independently, placing no trust in the Olympus servers.
 *
 * Features
 * ────────
 * • WASM-backed BLAKE3 hashing — files are hashed locally; they never leave the device
 * • Canonical JSON encoder (JCS / RFC 8785) — hash any JSON document deterministically
 * • Client-side Sparse Merkle Tree proof re-verification — independently recomputes the
 *   Merkle root using the same OLY:LEAF:V1 / OLY:NODE:V1 domain-separated BLAKE3
 *   prefixes as the server, then compares against the stored root
 * • Real FastAPI backend integration — GET /ingest/records/hash/{hash}/verify and
 *   POST /ingest/proofs/verify
 * • Four verification modes: hash lookup, file drop, JSON document, proof bundle
 * • Procedural glitch audio via Web Audio API (no external files required)
 * • Matrix-style glyph rain canvas, 3D perspective tilt card, CRT scanline overlay
 *
 * Required peer dependency (must be installed in the host project):
 *   npm install blake3-wasm@^2.1.5
 *
 * Usage
 * ─────
 *   import OlympusFull from "./components/olympus-full";
 *   <OlympusFull apiBase="http://localhost:8000" />
 */

import {
  useState,
  useEffect,
  useRef,
  useCallback,
  type FC,
  type KeyboardEvent,
  type DragEvent,
  type ChangeEvent,
  type MouseEvent,
} from "react";
import {
  hashFileBLAKE3,
  blake3Hex,
  canonicalJsonEncode,
  verifyMerkleProof,
  type CanonicalJsonValue,
  type HashVerificationResponse,
  type ProofVerificationResponse,
  type ProofVerificationRequest,
  type OlympusMerkleProof,
} from "../lib/olympus-crypto";

// ─── Constants ────────────────────────────────────────────────────────────────

const HASH_RE = /^[0-9a-f]{64}$/i;

// ─── Local types ──────────────────────────────────────────────────────────────

type Verdict = "verified" | "failed" | "unknown";
type Tab = "hash" | "file" | "json" | "proof";
type GlitchSoundType = "blip" | "noise" | "success" | "fail";
type FilePhase = "idle" | "hashing" | "done" | "error";

interface DetailRow {
  key: string;
  value: string;
}

interface VerificationResult {
  verdict: Verdict;
  details: DetailRow[];
  hash: string;
  localVerdict?: boolean;
}

interface RecentEntry {
  hash: string;
  verdict: Verdict;
  ts: number;
}

interface StatItem {
  label: string;
  val: number | string;
  raw?: boolean;
}

// ─── Procedural Glitch Audio (Web Audio API, no external files) ───────────────

/**
 * Generate a short procedural audio event.
 * Fails silently before the first user interaction (AudioContext policy).
 */
const playGlitchSound = (type: GlitchSoundType = "blip"): void => {
  try {
    const AudioContextCtor =
      window.AudioContext ??
      (window as Window & { webkitAudioContext?: typeof AudioContext })
        .webkitAudioContext;
    if (!AudioContextCtor) return;
    const ctx = new AudioContextCtor();

    if (type === "noise") {
      const bufLen = Math.ceil(ctx.sampleRate * 0.08);
      const buf = ctx.createBuffer(1, bufLen, ctx.sampleRate);
      const data = buf.getChannelData(0);
      for (let i = 0; i < bufLen; i++) data[i] = Math.random() * 2 - 1;
      const src = ctx.createBufferSource();
      src.buffer = buf;
      const gain = ctx.createGain();
      gain.gain.setValueAtTime(0.06, ctx.currentTime);
      gain.gain.linearRampToValueAtTime(0, ctx.currentTime + 0.08);
      src.connect(gain);
      gain.connect(ctx.destination);
      src.start();
      return;
    }

    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    switch (type) {
      case "blip":
        osc.type = "square";
        osc.frequency.setValueAtTime(200, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(60, ctx.currentTime + 0.08);
        gain.gain.setValueAtTime(0.08, ctx.currentTime);
        gain.gain.linearRampToValueAtTime(0, ctx.currentTime + 0.08);
        osc.start();
        osc.stop(ctx.currentTime + 0.08);
        break;
      case "success":
        osc.type = "sine";
        osc.frequency.setValueAtTime(440, ctx.currentTime);
        osc.frequency.linearRampToValueAtTime(880, ctx.currentTime + 0.15);
        gain.gain.setValueAtTime(0.06, ctx.currentTime);
        gain.gain.linearRampToValueAtTime(0, ctx.currentTime + 0.15);
        osc.start();
        osc.stop(ctx.currentTime + 0.15);
        break;
      case "fail":
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(200, ctx.currentTime);
        osc.frequency.linearRampToValueAtTime(80, ctx.currentTime + 0.2);
        gain.gain.setValueAtTime(0.07, ctx.currentTime);
        gain.gain.linearRampToValueAtTime(0, ctx.currentTime + 0.2);
        osc.start();
        osc.stop(ctx.currentTime + 0.2);
        break;
    }
  } catch {
    // AudioContext creation fails before user interaction — safe to ignore.
  }
};

// ─── GlyphRain ────────────────────────────────────────────────────────────────

const RAIN_GLYPHS =
  "アカサタナハuniversal01010101ERROR☠SYSTEM☣$¥€BLAKE3◆∑∇⊕01";

interface GlyphRainProps {
  active?: boolean;
}

/**
 * Full-viewport Matrix-style glyph rain rendered on an HTML5 Canvas.
 * Runs as a requestAnimationFrame loop and auto-resizes with the window.
 */
const GlyphRain: FC<GlyphRainProps> = ({ active = true }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const dropsRef = useRef<number[]>([]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const COL_W = 14;
    const FONT_SIZE = 12;

    const resize = (): void => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
      const cols = Math.floor(canvas.width / COL_W);
      dropsRef.current = Array.from(
        { length: cols },
        () => Math.random() * -canvas.height,
      );
    };
    resize();
    window.addEventListener("resize", resize);

    const draw = (): void => {
      if (!active) return;
      ctx.fillStyle = "rgba(5,5,5,0.14)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = `${FONT_SIZE}px 'DM Mono', monospace`;
      ctx.shadowBlur = 6;
      ctx.shadowColor = "#00FF41";

      dropsRef.current.forEach((y, i) => {
        const glyph =
          RAIN_GLYPHS[Math.floor(Math.random() * RAIN_GLYPHS.length)];
        const x = i * COL_W;
        ctx.fillStyle =
          y > 0 && y < canvas.height ? "#00FF41" : "rgba(0,255,65,0.3)";
        ctx.fillText(glyph, x, y);
        dropsRef.current[i] =
          y > canvas.height + 100 ? -Math.random() * 200 : y + COL_W;
      });
    };

    const loop = (): void => {
      draw();
      animRef.current = requestAnimationFrame(loop);
    };
    animRef.current = requestAnimationFrame(loop);

    return (): void => {
      cancelAnimationFrame(animRef.current);
      window.removeEventListener("resize", resize);
    };
  }, [active]);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      style={{
        position: "absolute",
        inset: 0,
        width: "100%",
        height: "100%",
        pointerEvents: "none",
        opacity: active ? 0.55 : 0,
        transition: "opacity 1.2s",
        zIndex: 0,
      }}
    />
  );
};

// ─── TiltContainer ────────────────────────────────────────────────────────────

interface TiltState {
  x: number;
  y: number;
}

interface TiltContainerProps {
  children: React.ReactNode;
}

/**
 * Wraps children in a perspective container that tilts ±10° based on the
 * cursor position within the element's bounding rect.
 */
const TiltContainer: FC<TiltContainerProps> = ({ children }) => {
  const [tilt, setTilt] = useState<TiltState>({ x: 0, y: 0 });
  const ref = useRef<HTMLDivElement>(null);

  const handleMove = useCallback((e: MouseEvent<HTMLDivElement>): void => {
    if (!ref.current) return;
    const r = ref.current.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - 0.5;
    const y = (e.clientY - r.top) / r.height - 0.5;
    setTilt({ x: y * -10, y: x * 10 });
  }, []);

  return (
    <div
      ref={ref}
      onMouseMove={handleMove}
      onMouseLeave={() => setTilt({ x: 0, y: 0 })}
      style={{
        perspective: "1200px",
        transform: `rotateX(${tilt.x}deg) rotateY(${tilt.y}deg)`,
        transition: "transform 0.08s ease-out",
        transformStyle: "preserve-3d",
      }}
    >
      {children}
    </div>
  );
};

// ─── HashReveal ───────────────────────────────────────────────────────────────

interface HashRevealProps {
  hash: string | null;
}

/**
 * Animates a hash string by revealing characters two at a time at 14 ms/tick.
 * Greyed placeholder characters fill the unrevealed portion.
 */
const HashReveal: FC<HashRevealProps> = ({ hash }) => {
  const [revealed, setRevealed] = useState<number>(0);

  useEffect(() => {
    if (!hash) {
      setRevealed(0);
      return;
    }
    setRevealed(0);
    let i = 0;
    const id = setInterval(() => {
      i += 2;
      setRevealed(i);
      if (i >= hash.length) clearInterval(id);
    }, 14);
    return (): void => clearInterval(id);
  }, [hash]);

  if (!hash) return null;
  const done = Math.min(revealed, hash.length);

  return (
    <div
      style={{
        fontFamily: "'DM Mono', monospace",
        fontSize: "0.7rem",
        wordBreak: "break-all",
        letterSpacing: "0.06em",
        marginTop: "0.75rem",
        padding: "0.6rem 0.75rem",
        background: "rgba(0,255,65,0.04)",
        border: "1px solid rgba(0,255,65,0.2)",
        borderRadius: 2,
        color: "#00FF41",
        textShadow: "0 0 4px rgba(0,255,65,0.5)",
      }}
      aria-label="BLAKE3 hash"
    >
      <span
        style={{
          opacity: 0.4,
          fontSize: "0.6rem",
          display: "block",
          marginBottom: "0.2rem",
        }}
      >
        BLAKE3_DIGEST
      </span>
      {hash.slice(0, done)}
      <span style={{ opacity: 0.25 }}>{hash.slice(done)}</span>
    </div>
  );
};

// ─── AnimatedNumber ───────────────────────────────────────────────────────────

interface AnimatedNumberProps {
  value: number;
}

const AnimatedNumber: FC<AnimatedNumberProps> = ({ value }) => {
  const [display, setDisplay] = useState<number>(0);

  useEffect(() => {
    let startTime: number | null = null;
    const step = (ts: number): void => {
      if (!startTime) startTime = ts;
      const progress = Math.min((ts - startTime) / 1200, 1);
      setDisplay(Math.floor(progress * value));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [value]);

  return <span>{display.toLocaleString()}</span>;
};

// ─── FileDrop ─────────────────────────────────────────────────────────────────

interface FileDropProps {
  onHash: (hex: string) => void;
  onProgress: (pct: number) => void;
}

/**
 * Drag-and-drop / click-to-browse file widget.
 * Hashes the file with WASM BLAKE3; bytes never leave the browser.
 */
const FileDrop: FC<FileDropProps> = ({ onHash, onProgress }) => {
  const [dragging, setDragging] = useState<boolean>(false);
  const [phase, setPhase] = useState<FilePhase>("idle");
  const [fileName, setFileName] = useState<string>("");
  const [errMsg, setErrMsg] = useState<string>("");
  const inputRef = useRef<HTMLInputElement>(null);

  const process = useCallback(
    async (file: File): Promise<void> => {
      setFileName(file.name);
      setPhase("hashing");
      setErrMsg("");
      onProgress(0);
      try {
        const hex = await hashFileBLAKE3(file, onProgress);
        onHash(hex);
        setPhase("done");
      } catch (err) {
        setErrMsg(err instanceof Error ? err.message : "Hashing failed");
        setPhase("error");
      }
    },
    [onHash, onProgress],
  );

  const handleDrop = useCallback(
    (e: DragEvent<HTMLDivElement>): void => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) void process(file);
    },
    [process],
  );

  const handleChange = useCallback(
    (e: ChangeEvent<HTMLInputElement>): void => {
      const file = e.target.files?.[0];
      if (file) void process(file);
    },
    [process],
  );

  return (
    <div
      onDragOver={(e: DragEvent<HTMLDivElement>) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
      role="button"
      tabIndex={0}
      onKeyDown={(e: KeyboardEvent<HTMLDivElement>) => {
        if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
      }}
      style={{
        border: `1px solid ${dragging ? "#00FF41" : "rgba(0,255,65,0.25)"}`,
        borderRadius: 3,
        padding: "1.75rem",
        textAlign: "center",
        cursor: "pointer",
        background: dragging ? "rgba(0,255,65,0.06)" : "rgba(0,20,0,0.4)",
        transition: "all 0.15s",
        clipPath: "polygon(0 0, 97% 0, 100% 3%, 100% 100%, 3% 100%, 0 97%)",
      }}
    >
      <input
        ref={inputRef}
        type="file"
        style={{ display: "none" }}
        onChange={handleChange}
        aria-label="Select file for BLAKE3 WASM hashing"
      />
      {phase === "idle" && (
        <>
          <p
            style={{
              color: "rgba(0,255,65,0.7)",
              fontSize: "0.85rem",
              margin: "0 0 0.3rem",
            }}
          >
            DROP_FILE_HERE or click to browse
          </p>
          <p style={{ color: "rgba(0,255,65,0.35)", fontSize: "0.7rem", margin: 0 }}>
            Hashed locally with BLAKE3 WASM — file never leaves your device
          </p>
        </>
      )}
      {phase === "hashing" && (
        <p style={{ color: "#00FF41", fontSize: "0.85rem", margin: 0 }}>
          HASHING:{" "}
          <span style={{ fontFamily: "'DM Mono', monospace" }}>{fileName}</span>
          …
        </p>
      )}
      {phase === "done" && (
        <p
          style={{ color: "rgba(0,255,65,0.6)", fontSize: "0.85rem", margin: 0 }}
        >
          <span style={{ fontFamily: "'DM Mono', monospace" }}>{fileName}</span>{" "}
          — drop another or click to change
        </p>
      )}
      {phase === "error" && (
        <p style={{ color: "#ff0055", fontSize: "0.85rem", margin: 0 }}>{errMsg}</p>
      )}
    </div>
  );
};

// ─── JsonHasher ───────────────────────────────────────────────────────────────

interface JsonHasherProps {
  onHash: (hex: string) => void;
}

/**
 * Accepts a raw JSON string, canonicalises it (JCS / RFC 8785), computes the
 * BLAKE3 content hash, then forwards the hex digest to onHash so the user can
 * look it up in the ledger.
 */
const JsonHasher: FC<JsonHasherProps> = ({ onHash }) => {
  const [input, setInput] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [canonical, setCanonical] = useState<string>("");

  const handleHash = async (): Promise<void> => {
    setError("");
    setCanonical("");

    let parsed: CanonicalJsonValue;
    try {
      parsed = JSON.parse(input) as CanonicalJsonValue;
    } catch (e) {
      setError("Invalid JSON: " + (e instanceof Error ? e.message : String(e)));
      return;
    }

    try {
      const canon = canonicalJsonEncode(parsed);
      setCanonical(canon);
      const bytes = new TextEncoder().encode(canon);
      const hex = await blake3Hex(bytes);
      onHash(hex);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div>
      <label
        htmlFor="json-hasher-input"
        style={{
          display: "block",
          fontSize: "0.6rem",
          color: "rgba(0,255,65,0.45)",
          marginBottom: "0.5rem",
        }}
      >
        PASTE_JSON_DOCUMENT — will be canonicalized (JCS/RFC 8785) then hashed
        with BLAKE3
      </label>
      <textarea
        id="json-hasher-input"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        rows={5}
        placeholder='{"title": "Budget 2025", "amount": 1000000}'
        spellCheck={false}
        style={{
          width: "100%",
          background: "rgba(0,0,0,0.5)",
          border: "1px solid rgba(0,255,65,0.2)",
          padding: "0.6rem 0.75rem",
          color: "#00FF41",
          fontFamily: "'DM Mono', monospace",
          fontSize: "0.72rem",
          outline: "none",
          resize: "vertical",
          boxSizing: "border-box",
          borderRadius: 2,
        }}
      />
      {canonical && (
        <p
          style={{
            fontSize: "0.6rem",
            color: "rgba(0,255,65,0.4)",
            margin: "0.3rem 0 0",
            wordBreak: "break-all",
          }}
        >
          CANONICAL:{" "}
          {canonical.length > 120
            ? canonical.slice(0, 120) + "…"
            : canonical}
        </p>
      )}
      {error && (
        <p style={{ color: "#ff0055", fontSize: "0.7rem", margin: "0.3rem 0 0" }}>
          {error}
        </p>
      )}
      <button
        type="button"
        className="cyber-button"
        onClick={() => void handleHash()}
        onMouseEnter={() => playGlitchSound("blip")}
        style={{ marginTop: "0.75rem" }}
      >
        CANONICALIZE + HASH
      </button>
    </div>
  );
};

// ─── VerdictCard ──────────────────────────────────────────────────────────────

interface VerdictConfig {
  color: string;
  borderColor: string;
  icon: string;
  label: string;
  desc: string;
}

const VERDICT_CFG: Record<Verdict, VerdictConfig> = {
  verified: {
    color: "#00FF41",
    borderColor: "#00FF41",
    icon: "✓",
    label: ">>> ACCESS_GRANTED",
    desc: "Record exists on the ledger and the Merkle proof is cryptographically valid.",
  },
  failed: {
    color: "#ff0055",
    borderColor: "#ff0055",
    icon: "✗",
    label: ">>> SECURITY_BREACH_DETECTED",
    desc: "Hash or Merkle proof mismatch — possible tampering or corrupted proof bundle.",
  },
  unknown: {
    color: "#f59e0b",
    borderColor: "#f59e0b",
    icon: "?",
    label: ">>> RECORD_NOT_FOUND",
    desc: "This hash has not been committed to the Olympus ledger, or the server could not be reached.",
  },
};

interface VerdictCardProps {
  verdict: Verdict;
  details: DetailRow[];
  localVerdict?: boolean;
}

const VerdictCard: FC<VerdictCardProps> = ({ verdict, details, localVerdict }) => {
  const cfg = VERDICT_CFG[verdict];

  useEffect(() => {
    if (verdict === "verified") playGlitchSound("success");
    else if (verdict === "failed") playGlitchSound("fail");
    else playGlitchSound("noise");
  }, [verdict]);

  return (
    <div
      style={{
        marginTop: "1.5rem",
        border: `1px solid ${cfg.borderColor}`,
        background: "rgba(0,0,0,0.92)",
        padding: "1.25rem 1.5rem",
        animation: "flicker 0.2s ease",
        clipPath: "polygon(0 0, 96% 0, 100% 4%, 100% 100%, 4% 100%, 0 96%)",
      }}
    >
      <div
        style={{
          color: cfg.color,
          fontWeight: "bold",
          fontSize: "0.8rem",
          textShadow: `0 0 8px ${cfg.color}`,
          marginBottom: "0.5rem",
        }}
      >
        {cfg.icon} {cfg.label}
      </div>
      <p
        style={{
          color: "rgba(0,255,65,0.5)",
          fontSize: "0.72rem",
          margin: "0 0 0.75rem",
        }}
      >
        {cfg.desc}
      </p>

      {/* Client-side re-verification badge */}
      {localVerdict !== undefined && (
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "0.4rem",
            fontSize: "0.65rem",
            color: localVerdict ? "#00FF41" : "#ff0055",
            background: "rgba(0,0,0,0.5)",
            padding: "0.25rem 0.6rem",
            border: `1px solid ${localVerdict ? "rgba(0,255,65,0.3)" : "rgba(255,0,85,0.3)"}`,
            borderRadius: 2,
            marginBottom: "0.75rem",
            fontFamily: "'DM Mono', monospace",
          }}
        >
          {localVerdict ? "✓" : "✗"} CLIENT_MERKLE_VERIFY:{" "}
          {localVerdict ? "PASS" : "FAIL"}
        </div>
      )}

      {/* Detail rows */}
      {details.length > 0 && (
        <div
          style={{ borderTop: "1px solid rgba(0,255,65,0.1)", paddingTop: "0.6rem" }}
        >
          {details.map((d) => (
            <div
              key={d.key}
              style={{
                display: "flex",
                justifyContent: "space-between",
                gap: "1rem",
                padding: "0.35rem 0",
                borderBottom: "1px solid rgba(0,255,65,0.05)",
                fontSize: "0.7rem",
              }}
            >
              <span
                style={{
                  color: "rgba(0,255,65,0.4)",
                  whiteSpace: "nowrap",
                  flexShrink: 0,
                }}
              >
                {d.key}
              </span>
              <span
                style={{
                  fontFamily: "'DM Mono', monospace",
                  color: "rgba(0,255,65,0.85)",
                  wordBreak: "break-all",
                  textAlign: "right",
                }}
              >
                {d.value}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiVerifyHash(
  base: string,
  hash: string,
): Promise<HashVerificationResponse | null> {
  const res = await fetch(`${base}/ingest/records/hash/${hash}/verify`, {
    method: "GET",
    headers: { "Content-Type": "application/json" },
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `API error ${res.status}${text ? ": " + text.slice(0, 120) : ""}`,
    );
  }
  return res.json() as Promise<HashVerificationResponse>;
}

async function apiVerifyProofBundle(
  base: string,
  bundle: ProofVerificationRequest,
): Promise<ProofVerificationResponse> {
  const res = await fetch(`${base}/ingest/proofs/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      proof_id: bundle.proof_id ?? null,
      content_hash: bundle.content_hash,
      merkle_root: bundle.merkle_root,
      merkle_proof: bundle.merkle_proof,
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `API error ${res.status}${text ? ": " + text.slice(0, 120) : ""}`,
    );
  }
  return res.json() as Promise<ProofVerificationResponse>;
}

// ─── Main Component ───────────────────────────────────────────────────────────

export interface OlympusFullProps {
  /** FastAPI root URL. Defaults to same origin (relative paths). */
  apiBase?: string;
}

/**
 * Olympus Public Verification Dashboard — "Project Mayhem" Edition.
 */
const OlympusFull: FC<OlympusFullProps> = ({ apiBase = "" }) => {
  const [tab, setTab] = useState<Tab>("hash");
  const [hashInput, setHashInput] = useState<string>("");
  const [hashError, setHashError] = useState<string>("");
  const [fileHash, setFileHash] = useState<string>("");
  const [fileProgress, setFileProgress] = useState<number>(0);
  const [proofInput, setProofInput] = useState<string>("");
  const [proofError, setProofError] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [recents, setRecents] = useState<RecentEntry[]>([]);

  const switchTab = (id: Tab): void => {
    setTab(id);
    setResult(null);
    setHashError("");
    setProofError("");
    playGlitchSound("blip");
  };

  const pushRecent = useCallback((hash: string, verdict: Verdict): void => {
    setRecents((prev) =>
      [{ hash, verdict, ts: Date.now() }, ...prev].slice(0, 7),
    );
  }, []);

  // ── Core: look up a 64-char hash in the ledger, then re-verify client-side ──
  const verifyHash = useCallback(
    async (hash: string): Promise<void> => {
      setLoading(true);
      setResult(null);
      playGlitchSound("noise");

      try {
        const data = await apiVerifyHash(apiBase, hash);

        if (!data) {
          setResult({
            verdict: "unknown",
            details: [{ key: "QUERIED_HASH", value: hash }],
            hash,
          });
          pushRecent(hash, "unknown");
          return;
        }

        // Re-verify the Merkle proof locally — no server trust required
        const localVerdict = data.merkle_proof
          ? await verifyMerkleProof(data.merkle_proof)
          : undefined;

        const verdict: Verdict = data.merkle_proof_valid ? "verified" : "failed";
        const details: DetailRow[] = [
          { key: "CONTENT_HASH", value: data.content_hash },
          { key: "PROOF_ID", value: data.proof_id ?? "—" },
          { key: "RECORD_ID", value: data.record_id ?? "—" },
          { key: "SHARD_ID", value: data.shard_id ?? "—" },
          { key: "MERKLE_ROOT", value: data.merkle_root },
          {
            key: "SERVER_VERIFIED",
            value: data.merkle_proof_valid ? "YES" : "NO",
          },
          {
            key: "COMMITTED",
            value: data.timestamp
              ? new Date(data.timestamp).toLocaleString()
              : "—",
          },
          ...(data.poseidon_root
            ? [{ key: "POSEIDON_ROOT", value: data.poseidon_root }]
            : []),
        ];

        setResult({ verdict, details, hash: data.content_hash, localVerdict });
        pushRecent(hash, verdict);
      } catch (err) {
        setHashError(err instanceof Error ? err.message : "Network error");
      } finally {
        setLoading(false);
      }
    },
    [apiBase, pushRecent],
  );

  const submitHash = useCallback((): void => {
    const normalized = hashInput.trim().toLowerCase();
    if (!HASH_RE.test(normalized)) {
      setHashError("Enter a valid 64-character BLAKE3 hex hash");
      return;
    }
    setHashError("");
    void verifyHash(normalized);
  }, [hashInput, verifyHash]);

  // ── Proof bundle submission ──
  const submitProof = useCallback(async (): Promise<void> => {
    setProofError("");
    setResult(null);

    let parsed: unknown;
    try {
      parsed = JSON.parse(proofInput);
    } catch {
      setProofError("Invalid JSON — paste the full proof bundle");
      return;
    }

    const p = parsed as Partial<ProofVerificationRequest>;
    if (!p.content_hash || !p.merkle_root || !p.merkle_proof) {
      setProofError(
        "Bundle must include content_hash, merkle_root, and merkle_proof",
      );
      return;
    }

    const bundle = p as ProofVerificationRequest;

    // Client-side Merkle re-verification — runs before the network call
    const localVerdict = await verifyMerkleProof(
      bundle.merkle_proof as OlympusMerkleProof,
    ).catch(() => false);

    setLoading(true);
    playGlitchSound("noise");

    try {
      const data = await apiVerifyProofBundle(apiBase, bundle);
      const allValid =
        data.content_hash_matches_proof &&
        data.merkle_proof_valid &&
        data.known_to_server;
      const verdict: Verdict = allValid
        ? "verified"
        : data.known_to_server
          ? "failed"
          : "unknown";

      const details: DetailRow[] = [
        { key: "CONTENT_HASH", value: data.content_hash },
        { key: "MERKLE_ROOT", value: data.merkle_root },
        {
          key: "HASH_MATCHES_PROOF",
          value: data.content_hash_matches_proof ? "YES" : "NO",
        },
        {
          key: "SERVER_MERKLE_VALID",
          value: data.merkle_proof_valid ? "YES" : "NO",
        },
        {
          key: "KNOWN_TO_SERVER",
          value: data.known_to_server ? "YES" : "NO",
        },
        ...(data.poseidon_root
          ? [{ key: "POSEIDON_ROOT", value: data.poseidon_root }]
          : []),
      ];

      setResult({ verdict, details, hash: data.content_hash, localVerdict });
      pushRecent(data.content_hash, verdict);
    } catch (err) {
      setProofError(err instanceof Error ? err.message : "Network error");
    } finally {
      setLoading(false);
    }
  }, [apiBase, proofInput, pushRecent]);

  const TABS: { id: Tab; label: string }[] = [
    { id: "hash", label: "HASH" },
    { id: "file", label: "FILE" },
    { id: "json", label: "JSON_DOC" },
    { id: "proof", label: "PROOF_BUNDLE" },
  ];

  const STATS: StatItem[] = [
    { label: "COPIES", val: 847293 },
    { label: "SHARDS", val: 14 },
    { label: "PROOFS", val: 23481 },
    { label: "UPTIME", val: "99.9%", raw: true },
  ];

  return (
    <div
      style={{
        backgroundColor: "#050505",
        color: "#00FF41",
        minHeight: "100vh",
        fontFamily: "'DM Mono', monospace",
        position: "relative",
        overflowX: "hidden",
      }}
    >
      {/* Injected styles — self-contained, no Tailwind dependency */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&display=swap');

        @keyframes flicker {
          0%   { opacity: 0.92; }
          5%   { opacity: 0.4;  }
          10%  { opacity: 0.88; }
          15%  { opacity: 0.75; }
          20%  { opacity: 0.95; }
          100% { opacity: 1;    }
        }
        @keyframes pulse-glow {
          0%, 100% { text-shadow: 0 0 4px #00FF41; }
          50%       { text-shadow: 0 0 14px #00FF41, 0 0 30px #00FF41; }
        }

        .crt-overlay {
          position: fixed; inset: 0; pointer-events: none; z-index: 9999;
          background:
            linear-gradient(rgba(18,16,16,0) 50%, rgba(0,0,0,0.08) 50%),
            linear-gradient(90deg,
              rgba(255,0,0,0.025),
              rgba(0,255,0,0.008),
              rgba(0,0,118,0.025));
          background-size: 100% 3px, 3px 100%;
          opacity: 0.28;
        }

        .cyber-panel {
          background: rgba(0,20,0,0.82);
          border: 1px solid rgba(0,255,65,0.35);
          clip-path: polygon(0 0, 95% 0, 100% 5%, 100% 100%, 5% 100%, 0 95%);
          box-shadow: 0 0 18px rgba(0,255,65,0.08),
                      inset 0 0 30px rgba(0,255,65,0.02);
        }

        .cyber-button {
          background: transparent;
          color: #00FF41;
          border: 1px solid #00FF41;
          padding: 0.7rem 1.4rem;
          text-transform: uppercase;
          letter-spacing: 0.08em;
          font-size: 0.72rem;
          font-family: 'DM Mono', monospace;
          cursor: pointer;
          clip-path: polygon(8% 0, 100% 0, 100% 65%, 92% 100%, 0 100%, 0 35%);
          transition: all 0.18s;
        }
        .cyber-button:hover:not(:disabled) {
          background: #00FF41;
          color: #000;
          box-shadow: 0 0 18px rgba(0,255,65,0.6);
        }
        .cyber-button:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .cyber-input {
          width: 100%;
          background: rgba(0,0,0,0.55);
          border: 1px solid rgba(0,255,65,0.25);
          padding: 0.7rem 0.85rem;
          color: #00FF41;
          font-family: 'DM Mono', monospace;
          font-size: 0.78rem;
          outline: none;
          box-sizing: border-box;
          transition: border-color 0.15s;
        }
        .cyber-input:focus {
          border-color: #00FF41;
          box-shadow: 0 0 8px rgba(0,255,65,0.2);
        }
        .cyber-input::placeholder { color: rgba(0,255,65,0.2); }

        .tab-btn {
          flex: 1;
          padding: 0.65rem 0.5rem;
          border: none;
          border-bottom: 2px solid transparent;
          background: transparent;
          color: rgba(0,255,65,0.35);
          font-family: 'DM Mono', monospace;
          font-size: 0.62rem;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          cursor: pointer;
          transition: all 0.15s;
        }
        .tab-btn[aria-selected="true"] {
          color: #00FF41;
          border-bottom-color: #00FF41;
          background: rgba(0,255,65,0.05);
          text-shadow: 0 0 6px #00FF41;
        }
        .tab-btn:hover:not([aria-selected="true"]) {
          color: rgba(0,255,65,0.65);
        }

        .err-text { color: #ff0055; font-size: 0.7rem; margin: 0.4rem 0 0; }
      `}</style>

      {/* CRT scanline overlay */}
      <div className="crt-overlay" aria-hidden="true" />

      {/* Full-viewport glyph rain */}
      <GlyphRain active />

      {/* ── Header ── */}
      <header
        style={{
          padding: "1.25rem 2rem",
          borderBottom: "1px solid rgba(0,255,65,0.18)",
          background: "rgba(0,0,0,0.92)",
          zIndex: 10,
          position: "relative",
        }}
      >
        <div
          style={{
            maxWidth: "1100px",
            margin: "0 auto",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.85rem" }}>
            <span style={{ fontSize: "1.4rem", color: "#ff0055" }}>[ø]</span>
            <span style={{ letterSpacing: "0.38em", fontSize: "0.78rem" }}>
              OLYMPUS_PROTOCØL
            </span>
          </div>
          <div
            style={{
              color: "#ff0055",
              fontSize: "0.58rem",
              animation: "flicker 2.4s infinite",
              letterSpacing: "0.1em",
            }}
          >
            ● SYSTEM_ENCRYPTED // PROOFS_VERIFIED_LOCALLY
          </div>
        </div>
      </header>

      {/* ── Main ── */}
      <main
        style={{
          maxWidth: "920px",
          margin: "0 auto",
          padding: "3.5rem 1.75rem 5rem",
          position: "relative",
          zIndex: 2,
        }}
      >
        {/* Hero */}
        <div style={{ marginBottom: "3.5rem" }}>
          <h1
            style={{
              fontSize: "clamp(2rem, 6vw, 3.5rem)",
              margin: "0 0 0.75rem",
              textShadow: "0 0 12px #00FF41",
              letterSpacing: "-0.02em",
            }}
          >
            VERIFY_TRUTH
          </h1>
          <p
            style={{
              color: "rgba(0,255,65,0.55)",
              maxWidth: "540px",
              fontSize: "0.85rem",
              margin: 0,
              lineHeight: 1.6,
            }}
          >
            The first rule of Project Olympus: You do not trust the hash.
            The second rule: You independently RE-VERIFY the hash.
            Merkle proofs are re-computed entirely in your browser.
          </p>
        </div>

        {/* Stats strip */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
            gap: "0.75rem",
            marginBottom: "3rem",
          }}
        >
          {STATS.map((s, i) => (
            <div
              key={i}
              className="cyber-panel"
              style={{ padding: "0.85rem 1rem", textAlign: "center" }}
            >
              <div
                style={{
                  fontSize: "1.15rem",
                  color: "#00FF41",
                  animation: "pulse-glow 3s ease-in-out infinite",
                }}
              >
                {s.raw ? (
                  String(s.val)
                ) : (
                  <AnimatedNumber value={s.val as number} />
                )}
              </div>
              <div
                style={{
                  fontSize: "0.5rem",
                  opacity: 0.45,
                  letterSpacing: "0.12em",
                  marginTop: "0.2rem",
                }}
              >
                {s.label}
              </div>
            </div>
          ))}
        </div>

        {/* ── Verification Terminal ── */}
        <TiltContainer>
          <div className="cyber-panel" style={{ padding: 0 }}>
            {/* Tab bar */}
            <div
              role="tablist"
              style={{
                display: "flex",
                borderBottom: "1px solid rgba(0,255,65,0.18)",
              }}
            >
              {TABS.map((t) => (
                <button
                  key={t.id}
                  role="tab"
                  aria-selected={tab === t.id}
                  className="tab-btn"
                  onClick={() => switchTab(t.id)}
                  type="button"
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div style={{ padding: "1.75rem" }}>
              {/* ── Hash tab ── */}
              {tab === "hash" && (
                <div>
                  <label
                    htmlFor="hash-input"
                    style={{
                      display: "block",
                      fontSize: "0.6rem",
                      color: "rgba(0,255,65,0.45)",
                      marginBottom: "0.5rem",
                    }}
                  >
                    INPUT_BUFFER_01 — BLAKE3 content hash (64 hex chars)
                  </label>
                  <div style={{ display: "flex", gap: "0.6rem" }}>
                    <input
                      id="hash-input"
                      type="text"
                      value={hashInput}
                      onChange={(e) => setHashInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") submitHash();
                      }}
                      placeholder="ENTER_BLAKE3_HASH..."
                      maxLength={64}
                      spellCheck={false}
                      autoComplete="off"
                      className="cyber-input"
                    />
                    <button
                      type="button"
                      className="cyber-button"
                      onClick={submitHash}
                      onMouseEnter={() => playGlitchSound("blip")}
                      disabled={loading}
                      style={{ flexShrink: 0 }}
                    >
                      {loading ? "EXECUTING..." : "EXECUTE"}
                    </button>
                  </div>
                  {hashError && <p className="err-text">{hashError}</p>}
                </div>
              )}

              {/* ── File tab ── */}
              {tab === "file" && (
                <div>
                  <FileDrop
                    onHash={(hex) => {
                      setFileHash(hex);
                      setFileProgress(100);
                    }}
                    onProgress={setFileProgress}
                  />
                  {fileProgress > 0 && fileProgress < 100 && (
                    <div style={{ marginTop: "0.75rem" }}>
                      <div
                        style={{
                          height: 2,
                          background: "rgba(0,255,65,0.15)",
                          borderRadius: 1,
                          overflow: "hidden",
                        }}
                      >
                        <div
                          style={{
                            height: "100%",
                            width: `${fileProgress}%`,
                            background: "#00FF41",
                            transition: "width 0.15s",
                            boxShadow: "0 0 6px #00FF41",
                          }}
                        />
                      </div>
                      <p
                        style={{
                          fontSize: "0.65rem",
                          color: "rgba(0,255,65,0.4)",
                          margin: "0.25rem 0 0",
                        }}
                      >
                        HASHING... {fileProgress}%
                      </p>
                    </div>
                  )}
                  {fileHash && (
                    <div style={{ marginTop: "1rem" }}>
                      <HashReveal hash={fileHash} />
                      <button
                        type="button"
                        className="cyber-button"
                        onClick={() => void verifyHash(fileHash)}
                        onMouseEnter={() => playGlitchSound("blip")}
                        disabled={loading}
                        style={{ marginTop: "1rem" }}
                      >
                        {loading ? "EXECUTING..." : "VERIFY_ON_LEDGER"}
                      </button>
                    </div>
                  )}
                </div>
              )}

              {/* ── JSON Document tab ── */}
              {tab === "json" && (
                <div>
                  <p
                    style={{
                      fontSize: "0.65rem",
                      color: "rgba(0,255,65,0.4)",
                      margin: "0 0 0.75rem",
                    }}
                  >
                    Paste a raw JSON document. The canonicalizer (JCS/RFC 8785)
                    sorts keys, normalises Unicode to NFC, and strips whitespace
                    before hashing — matching the server-side{" "}
                    <code style={{ color: "#00FF41" }}>
                      canonical_json_encode()
                    </code>
                    .
                  </p>
                  <JsonHasher
                    onHash={(hex) => {
                      setFileHash(hex);
                      setTab("hash");
                      setHashInput(hex);
                    }}
                  />
                </div>
              )}

              {/* ── Proof Bundle tab ── */}
              {tab === "proof" && (
                <div>
                  <label
                    htmlFor="proof-input"
                    style={{
                      display: "block",
                      fontSize: "0.6rem",
                      color: "rgba(0,255,65,0.45)",
                      marginBottom: "0.5rem",
                    }}
                  >
                    PASTE_PROOF_BUNDLE — JSON with content_hash, merkle_root,
                    merkle_proof
                  </label>
                  <textarea
                    id="proof-input"
                    value={proofInput}
                    onChange={(e) => setProofInput(e.target.value)}
                    rows={9}
                    placeholder={
                      '{"content_hash":"...","merkle_root":"...","merkle_proof":{...}}'
                    }
                    spellCheck={false}
                    className="cyber-input"
                    style={{ resize: "vertical" }}
                  />
                  <p
                    style={{
                      fontSize: "0.62rem",
                      color: "rgba(0,255,65,0.35)",
                      margin: "0.4rem 0 0.75rem",
                    }}
                  >
                    The Merkle proof is re-verified in your browser before
                    trusting the server result. Both CLIENT_MERKLE_VERIFY and
                    SERVER_VERIFIED must pass.
                  </p>
                  <button
                    type="button"
                    className="cyber-button"
                    onClick={() => void submitProof()}
                    onMouseEnter={() => playGlitchSound("blip")}
                    disabled={loading}
                  >
                    {loading ? "EXECUTING..." : "EXECUTE_VERIFICATION"}
                  </button>
                  {proofError && <p className="err-text">{proofError}</p>}
                </div>
              )}
            </div>
          </div>
        </TiltContainer>

        {/* Hash reveal strip */}
        {result?.hash && <HashReveal hash={result.hash} />}

        {/* Verdict */}
        {result && (
          <VerdictCard
            verdict={result.verdict}
            details={result.details}
            localVerdict={result.localVerdict}
          />
        )}

        {/* Recent activity */}
        {recents.length > 0 && (
          <div style={{ marginTop: "3rem" }}>
            <div
              style={{
                fontSize: "0.58rem",
                opacity: 0.4,
                borderBottom: "1px solid rgba(0,255,65,0.15)",
                paddingBottom: "0.5rem",
                marginBottom: "0.75rem",
                letterSpacing: "0.1em",
              }}
            >
              RECENT_LOGS
            </div>
            {recents.map((item, i) => (
              <div
                key={i}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  gap: "1rem",
                  fontSize: "0.68rem",
                  padding: "0.4rem 0",
                  borderBottom: "1px solid rgba(0,255,65,0.05)",
                }}
              >
                <span
                  style={{
                    color:
                      item.verdict === "verified"
                        ? "#00FF41"
                        : item.verdict === "failed"
                          ? "#ff0055"
                          : "#f59e0b",
                    flexShrink: 0,
                  }}
                >
                  [{item.verdict.toUpperCase()}]
                </span>
                <span
                  style={{
                    opacity: 0.6,
                    fontFamily: "'DM Mono', monospace",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {item.hash.slice(0, 16)}…
                </span>
                <span
                  style={{
                    opacity: 0.3,
                    flexShrink: 0,
                    fontSize: "0.6rem",
                  }}
                >
                  {new Date(item.ts).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        )}

        {/* How It Works */}
        <section
          style={{
            marginTop: "4rem",
            paddingTop: "2.5rem",
            borderTop: "1px solid rgba(0,255,65,0.1)",
          }}
        >
          <h2
            style={{
              fontSize: "0.65rem",
              letterSpacing: "0.15em",
              textTransform: "uppercase",
              color: "rgba(0,255,65,0.45)",
              margin: "0 0 1.5rem",
            }}
          >
            HOW_IT_WORKS
          </h2>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
              gap: "0.85rem",
            }}
          >
            {(
              [
                {
                  n: "01",
                  title: "BLAKE3_WASM",
                  body: "Files are hashed locally in-browser using a WebAssembly BLAKE3 implementation. File bytes never leave your machine.",
                },
                {
                  n: "02",
                  title: "CANONICAL_JSON",
                  body: "Documents are serialized with JCS (RFC 8785) — sorted keys, NFC Unicode, no whitespace — ensuring byte-for-byte reproducibility across all clients.",
                },
                {
                  n: "03",
                  title: "LEDGER_LOOKUP",
                  body: "The 64-char BLAKE3 digest is sent to the Olympus append-only ledger API which returns the stored Merkle proof bundle.",
                },
                {
                  n: "04",
                  title: "CLIENT_VERIFY",
                  body: "Your browser independently recomputes the Merkle root from the proof path using OLY:LEAF:V1 / OLY:NODE:V1 domain-separated BLAKE3 — server trust not required.",
                },
              ] as const
            ).map((step) => (
              <div key={step.n} className="cyber-panel" style={{ padding: "1rem 1.1rem" }}>
                <div
                  style={{
                    color: "#ff0055",
                    fontSize: "0.62rem",
                    marginBottom: "0.4rem",
                    letterSpacing: "0.05em",
                  }}
                >
                  {step.n}
                </div>
                <h3
                  style={{ margin: "0 0 0.4rem", fontSize: "0.8rem", color: "#00FF41" }}
                >
                  {step.title}
                </h3>
                <p
                  style={{
                    margin: 0,
                    fontSize: "0.7rem",
                    color: "rgba(0,255,65,0.45)",
                    lineHeight: 1.55,
                  }}
                >
                  {step.body}
                </p>
              </div>
            ))}
          </div>
        </section>
      </main>

      <footer
        style={{
          padding: "1.75rem",
          borderTop: "1px solid rgba(0,255,65,0.08)",
          textAlign: "center",
          fontSize: "0.58rem",
          opacity: 0.35,
          letterSpacing: "0.08em",
        }}
      >
        © 2024–2026 OLYMPUS_PROTOCØL // PROJECT_MAYHEM // NO_TRUST_REQUIRED
      </footer>
    </div>
  );
};

export default OlympusFull;
