"use client";

import { useCallback, useEffect, useRef } from "react";
import { GLYPH_CHARS, GLYPH_RAIN_OPACITY } from "@/config/theme.config";

/**
 * Full-viewport canvas that renders falling green glyphs.
 * Displayed only when the fight-club theme is active.
 */
export function GlyphRain() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const dropsRef = useRef<number[]>([]);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const fontSize = 16;
    const columns = Math.floor(canvas.width / fontSize);

    /* Initialise drops array if column count changed */
    if (dropsRef.current.length !== columns) {
      dropsRef.current = new Array(columns).fill(1);
    }

    const drops = dropsRef.current;

    ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = "#00ff41";
    ctx.font = `${fontSize}px monospace`;

    for (let i = 0; i < drops.length; i++) {
      const ch = GLYPH_CHARS[Math.floor(Math.random() * GLYPH_CHARS.length)];
      ctx.fillText(ch, i * fontSize, drops[i] * fontSize);
      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i]++;
    }

    animRef.current = requestAnimationFrame(draw);
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      dropsRef.current = new Array(
        Math.floor(canvas.width / 16)
      ).fill(1);
    };

    resize();
    window.addEventListener("resize", resize);
    animRef.current = requestAnimationFrame(draw);

    return () => {
      window.removeEventListener("resize", resize);
      cancelAnimationFrame(animRef.current);
    };
  }, [draw]);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      style={{
        position: "fixed",
        inset: 0,
        zIndex: -1,
        pointerEvents: "none",
        opacity: GLYPH_RAIN_OPACITY,
      }}
    />
  );
}
