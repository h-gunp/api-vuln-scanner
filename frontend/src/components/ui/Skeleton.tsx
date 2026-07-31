export function Skeleton({ label = "Loading content" }: { label?: string }) {
  return (
    <div className="skeleton" role="status" aria-label={label}>
      <i />
      <i />
      <i />
    </div>
  );
}
