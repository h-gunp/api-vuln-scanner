import { expect, it } from "vitest";
import { mockApiGraph } from "../../services/mock/mock-data";
import { filterOperations } from "./api-selectors";
it("filters by method, path, input and output without mutation", () => {
  const original = [...mockApiGraph.operations];
  expect(filterOperations(mockApiGraph.operations, "accounts")).toHaveLength(2);
  expect(filterOperations(mockApiGraph.operations, "BALANCE")).toHaveLength(1);
  expect(filterOperations(mockApiGraph.operations, "POST")).toHaveLength(4);
  expect(filterOperations(mockApiGraph.operations, "")).toEqual(original);
  expect(mockApiGraph.operations).toEqual(original);
});
