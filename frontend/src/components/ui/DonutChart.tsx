export function DonutChart({
  label,
  segments,
}: {
  label: string;
  segments: Array<{ name: string; value: number }>;
}) {
  const total = segments.reduce((sum, segment) => sum + segment.value, 0);
  return (
    <div className="donut-wrap">
      <div
        className="donut"
        role="img"
        aria-label={`${label}: ${segments.map(({ name, value }) => `${name} ${value}`).join(", ")}`}
      >
        <b>{total}</b>
        <span>합계</span>
      </div>
      <ul>
        {segments.map((segment) => (
          <li key={segment.name}>
            <i />
            <span>{segment.name}</span>
            <b>{segment.value}</b>
          </li>
        ))}
      </ul>
    </div>
  );
}
