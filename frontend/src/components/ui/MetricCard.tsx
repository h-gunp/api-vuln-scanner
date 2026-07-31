import { Link } from "react-router-dom";
export function MetricCard({
  to,
  label,
  value,
  detail,
  tone,
}: {
  to: string;
  label: string;
  value: string;
  detail: string;
  tone?: string;
}) {
  return (
    <Link to={to}>
      <span>{label}</span>
      <b className={tone}>{value}</b>
      <small>{detail}</small>
    </Link>
  );
}
