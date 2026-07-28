import { expect, it } from "vitest";
import type { Endpoint } from "../../contracts";
import { filterOperations } from "./api-selectors";

const endpoints: Endpoint[] = [
  { operationId: "getAccount", method: "GET", path: "/accounts/{id}" },
  { operationId: "getBalance", method: "GET", path: "/accounts/{id}/balance" },
  { operationId: "createAccount", method: "POST", path: "/accounts" },
];
it("filters confirmed endpoint fields without mutation", () => {
  const original = [...endpoints];
  expect(filterOperations(endpoints, "accounts")).toHaveLength(3);
  expect(filterOperations(endpoints, "BALANCE")).toHaveLength(1);
  expect(filterOperations(endpoints, "POST")).toHaveLength(1);
  expect(filterOperations(endpoints, "")).toEqual(original);
  expect(endpoints).toEqual(original);
});
