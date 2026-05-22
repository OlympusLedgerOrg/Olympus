/// Inline SVG splash for the StartupGate "BOOT_ART" tile.
///
/// Replaces a 3 MB PNG (`public/loading.png`) that never finished
/// first-paint under WSL/llvmpipe — the file is now removed from the
/// bundle. The SVG draws crisp at any resolution, ships zero kilobytes
/// over the network, and degrades gracefully under
/// `prefers-reduced-motion: reduce` (animations collapse to a static
/// frame instead of churning a paint loop).
import { type FC } from "react";

const LoadingSplash: FC = () => (
  <svg
    viewBox="0 0 320 200"
    width="100%"
    height="100%"
    aria-hidden="true"
    preserveAspectRatio="xMidYMid slice"
    style={{ display: "block" }}
  >
    {/* Pure-black backdrop */}
    <rect width="320" height="200" fill="#000" />

    {/* Distant grid floor — pure geometry, GPU-composited */}
    <g stroke="rgba(0,255,65,0.18)" strokeWidth="0.4" fill="none">
      {Array.from({ length: 8 }).map((_, i) => (
        <line key={`h${i}`} x1="0" y1={140 + i * 8} x2="320" y2={140 + i * 8} />
      ))}
      {Array.from({ length: 13 }).map((_, i) => (
        <line
          key={`v${i}`}
          x1={160 + (i - 6) * 30}
          y1="140"
          x2={160 + (i - 6) * 80}
          y2="200"
        />
      ))}
    </g>

    {/* Skyline silhouette (cheap rectangles, no filters) */}
    <g fill="rgba(0,255,65,0.10)" stroke="rgba(0,255,65,0.25)" strokeWidth="0.5">
      <rect x="10" y="100" width="22" height="40" />
      <rect x="36" y="80" width="18" height="60" />
      <rect x="58" y="105" width="26" height="35" />
      <rect x="90" y="70" width="22" height="70" />
      <rect x="120" y="90" width="32" height="50" />
      <rect x="160" y="60" width="40" height="80" />
      <rect x="206" y="85" width="22" height="55" />
      <rect x="232" y="75" width="30" height="65" />
      <rect x="268" y="95" width="20" height="45" />
      <rect x="294" y="105" width="18" height="35" />
    </g>

    {/* Centered Olympus omega — main glyph */}
    <g style={{ transform: "translate(160px, 75px)" }}>
      <text
        x="0"
        y="0"
        textAnchor="middle"
        dominantBaseline="middle"
        fontFamily="'Share Tech Mono', 'JetBrains Mono', monospace"
        fontSize="56"
        fill="#ff0055"
        style={{ filter: "drop-shadow(0 0 6px rgba(255,0,85,0.55))" }}
      >
        [ø]
      </text>
      <text
        x="0"
        y="34"
        textAnchor="middle"
        dominantBaseline="middle"
        fontFamily="'Share Tech Mono', 'JetBrains Mono', monospace"
        fontSize="9"
        fill="#00ff41"
        letterSpacing="0.32em"
        style={{ filter: "drop-shadow(0 0 4px rgba(0,255,65,0.7))" }}
      >
        OLYMPUS
      </text>
    </g>

    {/* Indeterminate sweep line — animated; CSS gates the keyframe */}
    <line
      x1="0"
      y1="155"
      x2="320"
      y2="155"
      stroke="rgba(0,255,65,0.5)"
      strokeWidth="1"
      strokeDasharray="6 6"
    >
      <animate
        attributeName="stroke-dashoffset"
        from="0"
        to="-24"
        dur="1.4s"
        repeatCount="indefinite"
      />
    </line>

    {/* "BOOT" tag — bottom-right */}
    <text
      x="312"
      y="194"
      textAnchor="end"
      fontFamily="'DM Mono', monospace"
      fontSize="6"
      fill="rgba(0,255,65,0.45)"
      letterSpacing="0.12em"
    >
      BOOT // SECURED
    </text>

    {/* Reduced-motion: collapse the dash animation to a static frame.
        SVG SMIL doesn't honor prefers-reduced-motion automatically, so
        we layer a CSS rule via <style> inside the SVG. */}
    <style>{`
      @media (prefers-reduced-motion: reduce) {
        animate { display: none; }
      }
    `}</style>
  </svg>
);

export default LoadingSplash;
