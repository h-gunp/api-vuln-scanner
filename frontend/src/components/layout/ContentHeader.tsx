export function ContentHeader({
  kicker,
  title,
  description,
}: {
  kicker: string;
  title: string;
  description: string;
}) {
  return (
    <header className="page-head">
      <div>
        <p className="eyebrow">{kicker}</p>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <span className="status">
        <i /> Mock scan active
      </span>
    </header>
  );
}
