/**
 * Procedural glitch audio via the Web Audio API.
 *
 * All sounds are synthesised from scratch — no external audio files are
 * required. Calls fail silently before the first user interaction because
 * browsers suspend AudioContext until a user gesture has occurred.
 */

import type { GlitchSoundType } from "./types";

export { type GlitchSoundType };

// ─── Shared AudioContext singleton ────────────────────────────────────────────
// Browsers limit the number of AudioContext instances per tab.  Creating a new
// one on every sound call can exhaust that limit.  We keep a single shared
// instance and resume it (after a user gesture) as needed.

type AudioContextCtor = typeof AudioContext;
let _sharedCtx: InstanceType<AudioContextCtor> | null = null;

function getSharedAudioContext(): InstanceType<AudioContextCtor> | null {
  const Ctor: AudioContextCtor | undefined =
    window.AudioContext ??
    (window as Window & { webkitAudioContext?: AudioContextCtor })
      .webkitAudioContext;
  if (!Ctor) return null;
  if (!_sharedCtx || _sharedCtx.state === "closed") {
    _sharedCtx = new Ctor();
  }
  if (_sharedCtx.state === "suspended") {
    // Non-blocking: resume will take effect before the next render frame.
    void _sharedCtx.resume();
  }
  return _sharedCtx;
}

/**
 * Generate a short procedural audio event.
 * Fails silently before the first user interaction (AudioContext policy).
 */
export function playGlitchSound(type: GlitchSoundType = "blip"): void {
  try {
    const ctx = getSharedAudioContext();
    if (!ctx) return;

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
}
