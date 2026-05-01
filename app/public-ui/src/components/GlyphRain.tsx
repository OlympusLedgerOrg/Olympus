import { useEffect, useRef, type FC } from "react";

const RAIN_GLYPHS =
  "アカサタナハuniversal01010101ERROR☠SYSTEM☣$¥€BLAKE3◆∑∇⊕01";

interface GlyphRainProps {
  active?: boolean;
}

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
        position: "fixed",
        inset: 0,
        width: "100%",
        height: "100%",
        pointerEvents: "none",
        opacity: active ? 0.45 : 0,
        transition: "opacity 1.2s",
        zIndex: 0,
      }}
    />
  );
};

export default GlyphRain;
