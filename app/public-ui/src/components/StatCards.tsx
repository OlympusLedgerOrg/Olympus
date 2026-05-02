import AnimatedNumber from "./AnimatedNumber";

interface StatCard {
  label: string;
  value: string | number;
  raw?: boolean;
}

interface StatCardsProps {
  cards: StatCard[];
  onRefetch: () => void;
}

export default function StatCards({ cards, onRefetch }: StatCardsProps) {
  return (
    <div className="stats-grid">
      {cards.map((s) => (
        <button
          key={s.label}
          type="button"
          className="cyber-panel-sm stat-card"
          onClick={onRefetch}
        >
          <div style={{ fontSize: "1.1rem", color: "#00FF41" }}>
            {s.raw ? String(s.value) : <AnimatedNumber value={Number(s.value)} />}
          </div>
          <div className="stat-label">{s.label}</div>
        </button>
      ))}
    </div>
  );
}
