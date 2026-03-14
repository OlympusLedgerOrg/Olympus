"use client";

import { useCallback, useEffect, useRef } from "react";
import {
  GLYPH_CHARS,
  GLYPH_FONT_SIZE,
  GLYPH_RAIN_COLOR,
  GLYPH_RAIN_OPACITY,
  GLYPH_RESET_THRESHOLD,
  GLYPH_TRAIL_FADE,
} from "@/config/theme.config";

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

    const columns = Math.floor(canvas.width / GLYPH_FONT_SIZE);

    /* Initialise drops array if column count changed */
    if (dropsRef.current.length !== columns) {
      dropsRef.current = new Array(columns).fill(1);
    }

    const drops = dropsRef.current;

    ctx.fillStyle = `rgba(0, 0, 0, ${GLYPH_TRAIL_FADE})`;
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    const style = getComputedStyle(document.documentElement);
    ctx.fillStyle =
      style.getPropertyValue("--color-primary").trim() || GLYPH_RAIN_COLOR;
    ctx.font = `${GLYPH_FONT_SIZE}px monospace`;

    for (let i = 0; i < drops.length; i++) {
      const ch = GLYPH_CHARS[Math.floor(Math.random() * GLYPH_CHARS.length)];
      ctx.fillText(ch, i * GLYPH_FONT_SIZE, drops[i] * GLYPH_FONT_SIZE);
      if (
        drops[i] * GLYPH_FONT_SIZE > canvas.height &&
        Math.random() > GLYPH_RESET_THRESHOLD
      ) {
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
        Math.floor(canvas.width / GLYPH_FONT_SIZE)
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
