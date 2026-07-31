import type { Endpoint } from "../../contracts";

export function filterOperations(operations: Endpoint[], query: string) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return [...operations];
  return operations.filter((operation) =>
    [operation.method, operation.path, operation.operationId].some((value) =>
      value.toLowerCase().includes(normalized),
    ),
  );
}
