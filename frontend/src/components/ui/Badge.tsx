export function Badge({
  children,
  tone = "default",
}: {
  children: React.ReactNode;
  tone?: string;
}) {
  return <span className={`pill ${tone.toLowerCase()}`}>{children}</span>;
}
