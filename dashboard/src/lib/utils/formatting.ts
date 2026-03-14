export function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

export function formatCurrency(value: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: value >= 100 ? 0 : 2,
  }).format(value);
}

export function formatPercent(value: number): string {
  return `${Math.round(value)}%`;
}

/**
 * Formats relative timestamps for dashboard UI, including small future offsets
 * to tolerate clock skew during live mock updates.
 */
export function formatRelativeTime(input: string | number | Date): string {
  const date = new Date(input);
  const diffSeconds = Math.round((Date.now() - date.getTime()) / 1000);
  const absSeconds = Math.abs(diffSeconds);

  if (absSeconds < 60) {
    return diffSeconds >= 0 ? "just now" : "in a few seconds";
  }

  const units: Array<{ unit: Intl.RelativeTimeFormatUnit; seconds: number }> = [
    { unit: "day", seconds: 60 * 60 * 24 },
    { unit: "hour", seconds: 60 * 60 },
    { unit: "minute", seconds: 60 },
  ];

  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  const match = units.find(({ seconds }) => absSeconds >= seconds) ?? units[units.length - 1];
  const value = Math.round((diffSeconds * -1) / match.seconds);

  return formatter.format(value, match.unit);
}
