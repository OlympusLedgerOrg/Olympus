import { useSkin } from "../skins/SkinContext";
import { SKIN_REGISTRY } from "../skins/registry";
import type { SkinId } from "../skins/types";

export default function SkinSelector() {
  const { skinId, setSkinId } = useSkin();

  return (
    <div
      role="group"
      aria-label="Visual skin selector"
      style={{ display: "flex", gap: "0.3rem", alignItems: "center" }}
    >
      {(Object.keys(SKIN_REGISTRY) as SkinId[]).map((id) => {
        const active = id === skinId;
        const s = SKIN_REGISTRY[id];
        return (
          <button
            key={id}
            type="button"
            title={s.description}
            onClick={() => setSkinId(id)}
            style={{
              padding: "0.22rem 0.55rem",
              border: `1px solid ${active ? "rgba(0,255,65,0.75)" : "rgba(0,255,65,0.22)"}`,
              background: active ? "rgba(0,255,65,0.12)" : "transparent",
              color: active ? "#00FF41" : "rgba(0,255,65,0.45)",
              fontFamily: "'DM Mono', monospace",
              fontSize: "0.52rem",
              letterSpacing: "0.1em",
              textTransform: "uppercase",
              cursor: "pointer",
              transition: "all 0.15s",
              whiteSpace: "nowrap",
            }}
          >
            {s.label}
          </button>
        );
      })}
    </div>
  );
}
