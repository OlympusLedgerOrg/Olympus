import { useSkin } from "../skins/SkinContext";
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
  const { skin } = useSkin();
  return (
    <div className="stats-grid">
      {cards.map((s) => (
        <button
          key={s.label}
          type="button"
          className={`${skin.classes.card} stat-card`}
          onClick={onRefetch}
        >
          <div className={skin.classes.accentText} style={{ fontSize: "1.1rem" }}>
            {s.raw ? String(s.value) : <AnimatedNumber value={Number(s.value)} />}
          </div>
          <div className="stat-label">{s.label}</div>
        </button>
      ))}
    </div>
  );
}
