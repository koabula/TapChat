export default function InfoCard({ title, rows }: { title: string; rows: Array<[string, string]> }) {
  return (
    <div className="info-card">
      <div className="info-card-title">{title}</div>
      <div className="info-card-rows">
        {rows.map(([label, value]) => (
          <div className="info-row" key={`${title}-${label}`}>
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}
