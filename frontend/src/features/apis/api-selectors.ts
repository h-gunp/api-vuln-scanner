import type { NormalizedApiGraph } from "../../contracts";
type Operation = NormalizedApiGraph["operations"][number];
export function filterOperations(operations: Operation[], query: string) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return [...operations];
  return operations.filter((operation) =>
    [
      operation.method,
      operation.path_template,
      ...operation.inputs.map((item) => item.field_path),
      ...operation.outputs.map((item) => item.field_path),
    ].some((value) => value.toLowerCase().includes(normalized)),
  );
}
