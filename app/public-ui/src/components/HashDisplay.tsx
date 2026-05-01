import HashReveal from "./HashReveal";
import CopyButton from "./CopyButton";

interface HashDisplayProps {
  hash: string;
  label?: string;
}

export default function HashDisplay({ hash, label }: HashDisplayProps) {
  return (
    <div style={{ position: "relative" }}>
      <HashReveal hash={hash} label={label} />
      <div
        style={{
          position: "absolute",
          top: "0.5rem",
          right: "0.5rem",
        }}
      >
        <CopyButton text={hash} />
      </div>
    </div>
  );
}
