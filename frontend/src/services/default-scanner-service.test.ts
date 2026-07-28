import { expect, it } from "vitest";
import { HttpScannerService } from "./http-scanner-service";
import { MockScannerService } from "./mock/mock-scanner-service";
import { createDefaultScannerService } from "./default-scanner-service";

it("selects the mock service only when the local mock flag is enabled", () => {
  expect(createDefaultScannerService(true)).toBeInstanceOf(MockScannerService);
  expect(createDefaultScannerService(false)).toBeInstanceOf(HttpScannerService);
});
