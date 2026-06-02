interface Props {
  label: string;
  value: number | string;
  hint?: string;
}

export function StatsCard({ label, value, hint }: Props) {
  return (
    <div
      className="stats-card"
      role="listitem"
      aria-label={`${label}: ${value}${hint ? ` (${hint})` : ''}`}
    >
      <div className="stats-card-value" aria-hidden="true">{value}</div>
      <div className="stats-card-label" aria-hidden="true">{label}</div>
      {hint && <div className="stats-card-hint" aria-hidden="true">{hint}</div>}
    </div>
  );
}
