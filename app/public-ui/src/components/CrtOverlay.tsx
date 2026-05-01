import type { FC } from "react";

const CrtOverlay: FC = () => (
  <div
    aria-hidden="true"
    style={{
      position: "fixed",
      inset: 0,
      pointerEvents: "none",
      zIndex: 9999,
      background: `
        linear-gradient(rgba(18,16,16,0) 50%, rgba(0,0,0,0.08) 50%),
        linear-gradient(90deg,
          rgba(255,0,0,0.025),
          rgba(0,255,0,0.008),
          rgba(0,0,118,0.025))
      `,
      backgroundSize: "100% 3px, 3px 100%",
      opacity: 0.28,
    }}
  />
);

export default CrtOverlay;
