export function EmptyState({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="empty">
      <b>{title}</b>
      <p>{description}</p>
    </div>
  );
}
