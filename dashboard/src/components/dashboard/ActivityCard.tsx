import { motion } from "framer-motion";
import { formatCurrency, formatRelativeTime } from "@/lib/utils/formatting";

export interface ActivityItem {
  id: string;
  title: string;
  description: string;
  timestamp: string;
  category: string;
  metric?: string;
  amount?: number;
}

export function ActivityCard({
  activity,
  priority = false,
}: {
  activity: ActivityItem;
  priority?: boolean;
}) {
  return (
    <motion.article
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      whileHover={{ y: -2 }}
      className="border p-4"
      style={{
        background: priority ? "var(--color-surface)" : "var(--color-surface-muted)",
        borderColor: "var(--color-border)",
        borderRadius: "var(--radius)",
      }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2 text-xs uppercase tracking-[0.2em]">
            <span style={{ color: "var(--color-primary)" }}>{activity.category}</span>
            {activity.metric ? (
              <span style={{ color: "var(--color-text-muted)" }}>{activity.metric}</span>
            ) : null}
          </div>
          <div>
            <h3 className="text-base font-semibold" style={{ color: "var(--color-text)" }}>
              {activity.title}
            </h3>
            <p className="mt-1 text-sm" style={{ color: "var(--color-text-muted)" }}>
              {activity.description}
            </p>
          </div>
        </div>
        {typeof activity.amount === "number" ? (
          <div className="shrink-0 text-right">
            <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
              Value
            </p>
            <p className="text-sm font-semibold" style={{ color: "var(--color-accent)" }}>
              {formatCurrency(activity.amount)}
            </p>
          </div>
        ) : null}
      </div>

      <div className="mt-4 text-xs" style={{ color: "var(--color-text-muted)" }}>
        {formatRelativeTime(activity.timestamp)}
      </div>
    </motion.article>
  );
}
