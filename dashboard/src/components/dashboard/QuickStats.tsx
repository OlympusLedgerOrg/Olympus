import { motion } from "framer-motion";

export interface QuickStatItem {
  label: string;
  value: string;
  detail: string;
}

export function QuickStats({ items }: { items: QuickStatItem[] }) {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {items.map((item, index) => (
        <motion.div
          key={item.label}
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: index * 0.05, duration: 0.3 }}
          className="border p-4"
          style={{
            background: "var(--color-surface)",
            borderColor: "var(--color-border)",
            borderRadius: "var(--radius)",
          }}
        >
          <p
            className="text-xs uppercase tracking-[0.3em]"
            style={{ color: "var(--color-text-muted)" }}
          >
            {item.label}
          </p>
          <p className="mt-3 text-2xl font-semibold" style={{ color: "var(--color-primary)" }}>
            {item.value}
          </p>
          <p className="mt-2 text-sm" style={{ color: "var(--color-text-muted)" }}>
            {item.detail}
          </p>
        </motion.div>
      ))}
    </div>
  );
}
