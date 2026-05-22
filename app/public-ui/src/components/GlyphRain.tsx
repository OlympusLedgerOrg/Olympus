import { useEffect, useRef, type FC } from "react";

// Katakana block + Olympus-flavoured symbols — matches the film palette
const RAIN_GLYPHS =
  "ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ" +
  "01アカサタナハ∑∇⊕BLAKE3$¥€☣";

// How many rows tall each column's glowing trail is
const TRAIL_LEN = 20;
// ms between column advances — higher = slower fall
const FRAME_MS  = 60;

interface GlyphRainProps {
  active?: boolean;
}

type Column = {
  head: number;      // row index of the leading (bright) character
  speed: number;     // rows advanced per tick (1 = every tick, 2 = every 2nd tick)
  tick: number;      // internal tick counter
  glyphs: string[];  // one random glyph per row, re-randomised at the head
  len: number;       // trail length for this column
};

/// Skip the animation entirely when:
/// - the user has `prefers-reduced-motion: reduce` set (accessibility),
/// - the env build was given `VITE_OLYMPUS_NO_RAIN=1` (kill-switch
///   useful for low-end / WSL hosts where the canvas paint loop visibly
///   competes with cursor updates).
const shouldDisableRain = (): boolean => {
  if (typeof window === "undefined") return true;
  if ((import.meta.env.VITE_OLYMPUS_NO_RAIN ?? "") === "1") return true;
  const mq = window.matchMedia?.("(prefers-reduced-motion: reduce)");
  return Boolean(mq?.matches);
};

const GlyphRain: FC<GlyphRainProps> = ({ active = true }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef   = useRef<number>(0);
  const lastRef   = useRef<number>(0);
  const colsRef   = useRef<Column[]>([]);

  useEffect(() => {
    if (shouldDisableRain()) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const COL_W    = 16;
    const FONT_PX  = 14;
    let rows = 0;

    const randGlyph = () =>
      RAIN_GLYPHS[Math.floor(Math.random() * RAIN_GLYPHS.length)];

    const makeCol = (numRows: number): Column => ({
      head:  Math.floor(Math.random() * numRows),
      speed: 1 + Math.floor(Math.random() * 2),   // 1 or 2 ticks per step
      tick:  0,
      glyphs: Array.from({ length: numRows }, randGlyph),
      len:   TRAIL_LEN + Math.floor(Math.random() * 8),
    });

    const resize = (): void => {
      canvas.width  = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
      rows = Math.ceil(canvas.height / COL_W);
      const cols = Math.floor(canvas.width / COL_W);
      colsRef.current = Array.from({ length: cols }, () => makeCol(rows));
    };
    resize();
    window.addEventListener("resize", resize);

    const draw = (now: number): void => {
      if (!active) return;

      const elapsed = now - lastRef.current;
      if (elapsed < FRAME_MS) {
        animRef.current = requestAnimationFrame(draw);
        return;
      }
      lastRef.current = now - (elapsed % FRAME_MS);

      // Fade the canvas — this controls how long trails persist
      ctx.fillStyle = "rgba(2,5,2,0.12)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.font = `${FONT_PX}px 'Share Tech Mono', monospace`;

      colsRef.current.forEach((col, ci) => {
        const x = ci * COL_W;

        // Draw the trail behind the head
        for (let t = 0; t < col.len; t++) {
          const row = col.head - t;
          if (row < 0 || row >= rows) continue;

          const y = row * COL_W;

          if (t === 0) {
            // Leading character: near-white flash
            ctx.shadowBlur  = 12;
            ctx.shadowColor = "#ccffcc";
            ctx.fillStyle   = "rgba(220,255,225,0.98)";
          } else {
            // Trail fades green → dark over TRAIL_LEN rows
            const ratio = 1 - t / col.len;
            const alpha = Math.pow(ratio, 1.2) * 0.92;
            ctx.shadowBlur  = ratio > 0.5 ? 8 : 0;
            ctx.shadowColor = "#00FF41";
            ctx.fillStyle   = `rgba(0,${Math.round(160 + 95 * ratio)},${Math.round(55 * ratio)},${alpha})`;
          }

          ctx.fillText(col.glyphs[row], x, y + COL_W);
        }

        // Advance head at this column's speed
        col.tick++;
        if (col.tick >= col.speed) {
          col.tick = 0;
          col.head++;
          // Re-randomise the glyph at the new head position
          if (col.head < rows) col.glyphs[col.head] = randGlyph();
          // Reset when trail has fully scrolled off
          if (col.head - col.len > rows) {
            col.head  = -col.len;
            col.speed = 1 + Math.floor(Math.random() * 2);
            col.len   = TRAIL_LEN + Math.floor(Math.random() * 8);
            col.glyphs = Array.from({ length: rows }, randGlyph);
          }
        }
      });

      animRef.current = requestAnimationFrame(draw);
    };

    animRef.current = requestAnimationFrame(draw);

    return (): void => {
      cancelAnimationFrame(animRef.current);
      window.removeEventListener("resize", resize);
    };
  }, [active]);

  // When disabled via reduced-motion / env kill-switch we render nothing
  // at all — no canvas allocation, no rAF loop, no paint contention.
  if (shouldDisableRain()) {
    return null;
  }

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      style={{
        position: "fixed",
        inset: 0,
        width: "100%",
        height: "100%",
        pointerEvents: "none",
        opacity: active ? 0.22 : 0,
        transition: "opacity 1.4s",
        zIndex: 0,
        maskImage:
          "linear-gradient(to bottom, transparent 0%, black 14%, black 86%, transparent 100%)",
        WebkitMaskImage:
          "linear-gradient(to bottom, transparent 0%, black 14%, black 86%, transparent 100%)",
      }}
    />
  );
};

export default GlyphRain;
