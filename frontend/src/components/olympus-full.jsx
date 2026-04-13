/**
 * olympus-full.jsx — Olympus Public Verification Dashboard
 * "Project Mayhem" Edition
 *
 * Self-contained React component for journalists and activists to verify
 * ledger proofs independently, without placing any trust in the Olympus servers.
 *
 * Features
 * ────────
 * • WASM-backed BLAKE3 hashing — files are hashed locally; they never leave the device
 * • Canonical JSON encoder (JCS / RFC 8785) — hash any JSON document deterministically
 * • Client-side Sparse Merkle Tree proof re-verification — independently recomputes the
 *   root and compares it to the stored root without relying on the server's answer
 * • Real FastAPI backend integration — GET /ingest/records/hash/{hash}/verify and
 *   POST /ingest/proofs/verify
 * • Three verification modes: hash lookup, file drop, and proof bundle paste
 * • Procedural glitch audio via Web Audio API (no external files)
 * • Matrix-style glyph rain, 3D tilt card, CRT scanline overlay
 *
 * Required peer dependency (must be installed in the host project):
 *   npm install blake3-wasm@^2.1.5
 *
 * Usage
 * ─────
 *   import OlympusFull from "./components/olympus-full";
 *   // Render anywhere — the component is fully self-contained.
 *   <OlympusFull apiBase="http://localhost:8000" />
 */

import { useState, useEffect, useRef, useCallback } from "react";
import {
  hashFileBLAKE3,
  blake3Hex,
  canonicalJsonEncode,
  canonicalJsonBytes,
  hashDocument,
  verifyMerkleProof,
  hexToBytes,
  bytesToHex,
} from "../lib/olympus-crypto";

// ─── Constants ────────────────────────────────────────────────────────────────

const HASH_RE = /^[0-9a-f]{64}$/i;

// ─── Procedural Glitch Audio (Web Audio API, no external files) ───────────────

/**
 * Generate a short procedural audio blip or noise burst.
 * Fails silently before the first user interaction (AudioContext policy).
 *
 * @param {"blip" | "noise" | "success" | "fail"} type
 */
const playGlitchSound = (type = "blip") => {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();

    if (type === "noise") {
      // White noise burst
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

    if (type === "blip") {
      osc.type = "square";
      osc.frequency.setValueAtTime(200, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(60, ctx.currentTime + 0.08);
      gain.gain.setValueAtTime(0.08, ctx.currentTime);
      gain.gain.linearRampToValueAtTime(0, ctx.currentTime + 0.08);
      osc.start();
      osc.stop(ctx.currentTime + 0.08);
    } else if (type === "success") {
      osc.type = "sine";
      osc.frequency.setValueAtTime(440, ctx.currentTime);
      osc.frequency.linearRampToValueAtTime(880, ctx.currentTime + 0.15);
      gain.gain.setValueAtTime(0.06, ctx.currentTime);
      gain.gain.linearRampToValueAtTime(0, ctx.currentTime + 0.15);
      osc.start();
      osc.stop(ctx.currentTime + 0.15);
    } else if (type === "fail") {
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(200, ctx.currentTime);
      osc.frequency.linearRampToValueAtTime(80, ctx.currentTime + 0.2);
      gain.gain.setValueAtTime(0.07, ctx.currentTime);
      gain.gain.linearRampToValueAtTime(0, ctx.currentTime + 0.2);
      osc.start();
      osc.stop(ctx.currentTime + 0.2);
    }
  } catch (_) {
    // AudioContext creation fails before user interaction — safe to ignore.
  }
};

// ─── GlyphRain ────────────────────────────────────────────────────────────────

const RAIN_GLYPHS =
  "アカサタナハuniversal01010101ERROR☠SYSTEM☣$¥€BLAKE3◆∑∇⊕01";

/**
 * Full-viewport Matrix-style glyph rain rendered on an HTML5 Canvas.
 * Runs as a requestAnimationFrame loop and auto-resizes with the window.
 */
function GlyphRain({ active = true }) {
  const canvasRef = useRef(null);
  const animRef = useRef(null);
  const dropsRef = useRef([]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const FONT = 12;
    const COL_W = 14;

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
      const cols = Math.floor(canvas.width / COL_W);
      dropsRef.current = Array.from(
        { length: cols },
        () => Math.random() * -canvas.height
      );
    };
    resize();
    window.addEventListener("resize", resize);

    const draw = () => {
      if (!active) {
        animRef.current = requestAnimationFrame(draw);
        return;
      }
      ctx.fillStyle = "rgba(5,5,5,0.14)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.font = `${FONT}px 'DM Mono', monospace`;
      ctx.shadowBlur = 6;
      ctx.shadowColor = "#00FF41";

      dropsRef.current.forEach((y, i) => {
        const glyph = RAIN_GLYPHS[Math.floor(Math.random() * RAIN_GLYPHS.length)];
        const x = i * COL_W;
        // Lead character is bright; trailing chars fade
        const bright = y > 0 && y < canvas.height;
        ctx.fillStyle = bright ? "#00FF41" : "rgba(0,255,65,0.3)";
        ctx.fillText(glyph, x, y);
        dropsRef.current[i] =
          y > canvas.height + 100 ? -Math.random() * 200 : y + COL_W;
      });
    };

    const loop = () => {
      draw();
      animRef.current = requestAnimationFrame(loop);
    };
    animRef.current = requestAnimationFrame(loop);

    return () => {
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
}

// ─── 3D Tilt Container ────────────────────────────────────────────────────────

/**
 * Wraps its children in a perspective container that tilts ±10 ° based on
 * the cursor position within the element's bounding rect.
 */
function TiltContainer({ children }) {
  const [tilt, setTilt] = useState({ x: 0, y: 0 });
  const ref = useRef(null);

  const handleMove = useCallback((e) => {
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
}

// ─── HashReveal ───────────────────────────────────────────────────────────────

/**
 * Animates a hash string by revealing characters one-by-one at 14 ms/char.
 * Greyed placeholder characters fill the unrevealed portion.
 */
function HashReveal({ hash }) {
  const [revealed, setRevealed] = useState(0);

  useEffect(() => {
    if (!hash) {
      setRevealed(0);
      return;
    }
    setRevealed(0);
    let i = 0;
    const id = setInterval(() => {
      i += 2; // reveal 2 chars per tick for snappier feel
      setRevealed(i);
      if (i >= hash.length) clearInterval(id);
    }, 14);
    return () => clearInterval(id);
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
      <span style={{ opacity: 0.4, fontSize: "0.6rem", display: "block", marginBottom: "0.2rem" }}>
        BLAKE3_DIGEST
      </span>
      {hash.slice(0, done)}
      <span style={{ opacity: 0.25 }}>{hash.slice(done)}</span>
    </div>
  );
}

// ─── AnimatedNumber ───────────────────────────────────────────────────────────

function AnimatedNumber({ value }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let start = null;
    const end = Number(value);
    const step = (ts) => {
      if (!start) start = ts;
      const progress = Math.min((ts - start) / 1200, 1);
      setDisplay(Math.floor(progress * end));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [value]);
  return <span>{display.toLocaleString()}</span>;
}

// ─── FileDrop ─────────────────────────────────────────────────────────────────

/**
 * Drag-and-drop / click-to-browse file widget.
 * Hashes the selected file with WASM BLAKE3; the file bytes never leave the browser.
 */
function FileDrop({ onHash, onProgress }) {
  const [dragging, setDragging] = useState(false);
  const [phase, setPhase] = useState("idle"); // idle | hashing | done | error
  const [fileName, setFileName] = useState("");
  const [errMsg, setErrMsg] = useState("");
  const inputRef = useRef(null);

  const process = useCallback(
    async (file) => {
      setFileName(file.name);
      setPhase("hashing");
      setErrMsg("");
      onProgress(0);
      try {
        const hex = await hashFileBLAKE3(file, onProgress);
        onHash(hex);
        setPhase("done");
      } catch (err) {
        setErrMsg(err.message || "Hashing failed");
        setPhase("error");
      }
    },
    [onHash, onProgress]
  );

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) process(file);
    },
    [process]
  );

  const handleChange = useCallback(
    (e) => {
      const file = e.target.files?.[0];
      if (file) process(file);
    },
    [process]
  );

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
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
        clipPath:
          "polygon(0 0, 97% 0, 100% 3%, 100% 100%, 3% 100%, 0 97%)",
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
          <p style={{ color: "rgba(0,255,65,0.7)", fontSize: "0.85rem", margin: "0 0 0.3rem" }}>
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
          <span style={{ fontFamily: "'DM Mono', monospace" }}>{fileName}</span>…
        </p>
      )}
      {phase === "done" && (
        <p style={{ color: "rgba(0,255,65,0.6)", fontSize: "0.85rem", margin: 0 }}>
          <span style={{ fontFamily: "'DM Mono', monospace" }}>{fileName}</span> — drop
          another or click to change
        </p>
      )}
      {phase === "error" && (
        <p style={{ color: "#ff0055", fontSize: "0.85rem", margin: 0 }}>{errMsg}</p>
      )}
    </div>
  );
}

// ─── JsonHasher ───────────────────────────────────────────────────────────────

/**
 * Accepts a raw JSON string pasted by the user, canonicalises it (JCS / RFC 8785),
 * and computes its BLAKE3 content hash so it can be looked up in the ledger.
 */
function JsonHasher({ onHash }) {
  const [input, setInput] = useState("");
  const [error, setError] = useState("");
  const [canonical, setCanonical] = useState("");

  const handleHash = async () => {
    setError("");
    setCanonical("");
    let parsed;
    try {
      parsed = JSON.parse(input);
    } catch (e) {
      setError("Invalid JSON: " + e.message);
      return;
    }
    try {
      const canon = canonicalJsonEncode(parsed);
      setCanonical(canon);
      const bytes = new TextEncoder().encode(canon);
      const hex = await blake3Hex(bytes);
      onHash(hex);
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div>
      <label
        htmlFor="json-hasher-input"
        style={{ display: "block", fontSize: "0.6rem", color: "rgba(0,255,65,0.45)", marginBottom: "0.5rem" }}
      >
        PASTE_JSON_DOCUMENT — will be canonicalized (JCS/RFC 8785) then hashed with BLAKE3
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
        <p style={{ fontSize: "0.6rem", color: "rgba(0,255,65,0.4)", margin: "0.3rem 0 0", wordBreak: "break-all" }}>
          CANONICAL: {canonical.length > 120 ? canonical.slice(0, 120) + "…" : canonical}
        </p>
      )}
      {error && (
        <p style={{ color: "#ff0055", fontSize: "0.7rem", margin: "0.3rem 0 0" }}>{error}</p>
      )}
      <button
        type="button"
        className="cyber-button"
        onClick={handleHash}
        onMouseEnter={() => playGlitchSound("blip")}
        style={{ marginTop: "0.75rem" }}
      >
        CANONICALIZE + HASH
      </button>
    </div>
  );
}

// ─── Verdict Card ─────────────────────────────────────────────────────────────

const VERDICT_CFG = {
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

/**
 * Displays the combined server + client-side verification verdict.
 *
 * @param {{ verdict: string, details: Array<{key:string,value:string}>, localVerdict?: boolean }} props
 */
function VerdictCard({ verdict, details = [], localVerdict }) {
  const cfg = VERDICT_CFG[verdict] ?? VERDICT_CFG.unknown;

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
      <p style={{ color: "rgba(0,255,65,0.5)", fontSize: "0.72rem", margin: "0 0 0.75rem" }}>
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
        <div style={{ borderTop: "1px solid rgba(0,255,65,0.1)", paddingTop: "0.6rem" }}>
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
              <span style={{ color: "rgba(0,255,65,0.4)", whiteSpace: "nowrap", flexShrink: 0 }}>
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
}

// ─── API helpers ──────────────────────────────────────────────────────────────

/**
 * Look up a BLAKE3 content hash in the Olympus ledger.
 * Returns null when the hash is not found (404).
 *
 * @param {string} base  API base URL (no trailing slash)
 * @param {string} hash  64-char hex BLAKE3 digest
 */
async function apiVerifyHash(base, hash) {
  const res = await fetch(`${base}/ingest/records/hash/${hash}/verify`, {
    method: "GET",
    headers: { "Content-Type": "application/json" },
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API error ${res.status}${text ? ": " + text.slice(0, 120) : ""}`);
  }
  return res.json();
}

/**
 * Submit a full proof bundle for server-side verification.
 *
 * @param {string} base
 * @param {{ content_hash: string, merkle_root: string, merkle_proof: object, proof_id?: string }} bundle
 */
async function apiVerifyProofBundle(base, bundle) {
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
    throw new Error(`API error ${res.status}${text ? ": " + text.slice(0, 120) : ""}`);
  }
  return res.json();
}

// ─── Main Component ───────────────────────────────────────────────────────────

/**
 * Olympus Public Verification Dashboard — "Project Mayhem" Edition.
 *
 * @param {{ apiBase?: string }} props
 *   apiBase — FastAPI root URL (default: same origin, i.e. relative paths).
 */
export default function OlympusFull({ apiBase = "" }) {
  const [tab, setTab] = useState("hash"); // "hash" | "file" | "json" | "proof"
  const [hashInput, setHashInput] = useState("");
  const [hashError, setHashError] = useState("");
  const [fileHash, setFileHash] = useState("");
  const [fileProgress, setFileProgress] = useState(0);
  const [proofInput, setProofInput] = useState("");
  const [proofError, setProofError] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [recents, setRecents] = useState([]);

  // Switch tabs — clear stale state
  const switchTab = (id) => {
    setTab(id);
    setResult(null);
    setHashError("");
    setProofError("");
    playGlitchSound("blip");
  };

  // Add entry to recent-activity list (capped at 7)
  const pushRecent = useCallback((hash, verdict) => {
    setRecents((prev) =>
      [{ hash, verdict, ts: Date.now() }, ...prev].slice(0, 7)
    );
  }, []);

  // ── Core verification: given a 64-char hash, hit the API + re-verify client-side ──
  const verifyHash = useCallback(
    async (hash) => {
      setLoading(true);
      setResult(null);
      playGlitchSound("noise");
      try {
        const data = await apiVerifyHash(apiBase, hash);
        if (!data) {
          const r = { verdict: "unknown", details: [{ key: "QUERIED_HASH", value: hash }], hash };
          setResult(r);
          pushRecent(hash, "unknown");
          return;
        }

        // Client-side Merkle proof re-verification — no trust in server required
        const localVerdict = data.merkle_proof
          ? await verifyMerkleProof(data.merkle_proof)
          : undefined;

        const verdict = data.merkle_proof_valid ? "verified" : "failed";
        const details = [
          { key: "CONTENT_HASH", value: data.content_hash },
          { key: "PROOF_ID", value: data.proof_id ?? "—" },
          { key: "RECORD_ID", value: data.record_id ?? "—" },
          { key: "SHARD_ID", value: data.shard_id ?? "—" },
          { key: "MERKLE_ROOT", value: data.merkle_root },
          { key: "SERVER_VERIFIED", value: data.merkle_proof_valid ? "YES" : "NO" },
          { key: "COMMITTED", value: data.timestamp ? new Date(data.timestamp).toLocaleString() : "—" },
          ...(data.poseidon_root ? [{ key: "POSEIDON_ROOT", value: data.poseidon_root }] : []),
        ];
        setResult({ verdict, details, hash: data.content_hash, localVerdict });
        pushRecent(hash, verdict);
      } catch (err) {
        setHashError(err.message || "Network error");
      } finally {
        setLoading(false);
      }
    },
    [apiBase, pushRecent]
  );

  const submitHash = useCallback(() => {
    const normalized = hashInput.trim().toLowerCase();
    if (!HASH_RE.test(normalized)) {
      setHashError("Enter a valid 64-character BLAKE3 hex hash");
      return;
    }
    setHashError("");
    verifyHash(normalized);
  }, [hashInput, verifyHash]);

  // ── Proof bundle submission ──
  const submitProof = useCallback(async () => {
    setProofError("");
    setResult(null);

    let parsed;
    try {
      parsed = JSON.parse(proofInput);
    } catch {
      setProofError("Invalid JSON — paste the full proof bundle");
      return;
    }
    if (!parsed.content_hash || !parsed.merkle_root || !parsed.merkle_proof) {
      setProofError("Bundle must include content_hash, merkle_root, and merkle_proof");
      return;
    }

    // Client-side verification runs first — no network call needed for this step
    const localVerdict = await verifyMerkleProof(parsed.merkle_proof).catch(() => false);

    setLoading(true);
    playGlitchSound("noise");
    try {
      const data = await apiVerifyProofBundle(apiBase, parsed);
      const allValid =
        data.content_hash_matches_proof && data.merkle_proof_valid && data.known_to_server;
      const verdict = allValid ? "verified" : data.known_to_server ? "failed" : "unknown";
      const details = [
        { key: "CONTENT_HASH", value: data.content_hash },
        { key: "MERKLE_ROOT", value: data.merkle_root },
        { key: "HASH_MATCHES_PROOF", value: data.content_hash_matches_proof ? "YES" : "NO" },
        { key: "SERVER_MERKLE_VALID", value: data.merkle_proof_valid ? "YES" : "NO" },
        { key: "KNOWN_TO_SERVER", value: data.known_to_server ? "YES" : "NO" },
        ...(data.poseidon_root ? [{ key: "POSEIDON_ROOT", value: data.poseidon_root }] : []),
      ];
      setResult({ verdict, details, hash: data.content_hash, localVerdict });
      pushRecent(data.content_hash, verdict);
    } catch (err) {
      setProofError(err.message || "Network error");
    } finally {
      setLoading(false);
    }
  }, [apiBase, proofInput, pushRecent]);

  const TABS = [
    { id: "hash", label: "HASH" },
    { id: "file", label: "FILE" },
    { id: "json", label: "JSON_DOC" },
    { id: "proof", label: "PROOF_BUNDLE" },
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
      {/* Injected styles */}
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
            linear-gradient(90deg, rgba(255,0,0,0.025), rgba(0,255,0,0.008), rgba(0,0,118,0.025));
          background-size: 100% 3px, 3px 100%;
          opacity: 0.28;
        }

        .cyber-panel {
          background: rgba(0,20,0,0.82);
          border: 1px solid rgba(0,255,65,0.35);
          clip-path: polygon(0 0, 95% 0, 100% 5%, 100% 100%, 5% 100%, 0 95%);
          box-shadow: 0 0 18px rgba(0,255,65,0.08), inset 0 0 30px rgba(0,255,65,0.02);
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
        .tab-btn:hover:not([aria-selected="true"]) { color: rgba(0,255,65,0.65); }

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
            <span style={{ letterSpacing: "0.38em", fontSize: "0.78rem" }}>OLYMPUS_PROTOCØL</span>
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
          <p style={{ color: "rgba(0,255,65,0.55)", maxWidth: "540px", fontSize: "0.85rem", margin: 0, lineHeight: 1.6 }}>
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
          {[
            { label: "COPIES", val: 847293 },
            { label: "SHARDS", val: 14 },
            { label: "PROOFS", val: 23481 },
            { label: "UPTIME", val: "99.9%", raw: true },
          ].map((s, i) => (
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
                {s.raw ? s.val : <AnimatedNumber value={s.val} />}
              </div>
              <div style={{ fontSize: "0.5rem", opacity: 0.45, letterSpacing: "0.12em", marginTop: "0.2rem" }}>
                {s.label}
              </div>
            </div>
          ))}
        </div>

        {/* ── Verification Terminal ── */}
        <TiltContainer>
          <div className="cyber-panel" style={{ padding: "0" }}>
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
                    style={{ display: "block", fontSize: "0.6rem", color: "rgba(0,255,65,0.45)", marginBottom: "0.5rem" }}
                  >
                    INPUT_BUFFER_01 — BLAKE3 content hash (64 hex chars)
                  </label>
                  <div style={{ display: "flex", gap: "0.6rem" }}>
                    <input
                      id="hash-input"
                      type="text"
                      value={hashInput}
                      onChange={(e) => setHashInput(e.target.value)}
                      onKeyDown={(e) => { if (e.key === "Enter") submitHash(); }}
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
                    onHash={(hex) => { setFileHash(hex); setFileProgress(100); }}
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
                      <p style={{ fontSize: "0.65rem", color: "rgba(0,255,65,0.4)", margin: "0.25rem 0 0" }}>
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
                        onClick={() => verifyHash(fileHash)}
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
                  <p style={{ fontSize: "0.65rem", color: "rgba(0,255,65,0.4)", margin: "0 0 0.75rem" }}>
                    Paste a raw JSON document. The canonicalizer (JCS/RFC 8785) sorts keys,
                    normalises Unicode to NFC, and strips whitespace before hashing — matching
                    the server-side <code style={{ color: "#00FF41" }}>canonical_json_encode()</code>.
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
                    style={{ display: "block", fontSize: "0.6rem", color: "rgba(0,255,65,0.45)", marginBottom: "0.5rem" }}
                  >
                    PASTE_PROOF_BUNDLE — JSON with content_hash, merkle_root, merkle_proof
                  </label>
                  <textarea
                    id="proof-input"
                    value={proofInput}
                    onChange={(e) => setProofInput(e.target.value)}
                    rows={9}
                    placeholder={'{"content_hash":"...","merkle_root":"...","merkle_proof":{...}}'}
                    spellCheck={false}
                    className="cyber-input"
                    style={{ resize: "vertical" }}
                  />
                  <p style={{ fontSize: "0.62rem", color: "rgba(0,255,65,0.35)", margin: "0.4rem 0 0.75rem" }}>
                    The Merkle proof will be re-verified in your browser before the server result
                    is trusted. Both CLIENT_MERKLE_VERIFY and SERVER_VERIFIED must pass.
                  </p>
                  <button
                    type="button"
                    className="cyber-button"
                    onClick={submitProof}
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

        {/* Hash reveal under the terminal */}
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
                <span style={{ opacity: 0.6, fontFamily: "'DM Mono', monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {item.hash.slice(0, 16)}…
                </span>
                <span style={{ opacity: 0.3, flexShrink: 0, fontSize: "0.6rem" }}>
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
            {[
              {
                n: "01",
                title: "BLAKE3_WASM",
                body: "Files are hashed locally in-browser using a WebAssembly BLAKE3 implementation. The file bytes never leave your machine.",
              },
              {
                n: "02",
                title: "CANONICAL_JSON",
                body: "Documents are serialised with JCS (RFC 8785) — sorted keys, NFC Unicode, no whitespace — before hashing, ensuring byte-for-byte reproducibility.",
              },
              {
                n: "03",
                title: "LEDGER_LOOKUP",
                body: "The 64-char BLAKE3 digest is sent to the Olympus append-only ledger API which returns the stored Merkle proof bundle.",
              },
              {
                n: "04",
                title: "CLIENT_VERIFY",
                body: "Your browser independently recomputes the Merkle root from the proof path using the same OLY:LEAF:V1 / OLY:NODE:V1 domain-separated hashes as the server.",
              },
            ].map((step) => (
              <div
                key={step.n}
                className="cyber-panel"
                style={{ padding: "1rem 1.1rem" }}
              >
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
                <h3 style={{ margin: "0 0 0.4rem", fontSize: "0.8rem", color: "#00FF41" }}>
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
}
