import { HttpScannerService } from "./http-scanner-service";
import type { ScannerService } from "./scanner-service";
import { MockScannerService } from "./mock/mock-scanner-service";

export function createDefaultScannerService(
  useMock = import.meta.env.VITE_USE_MOCK_SERVICE === "true",
): ScannerService {
  return useMock ? new MockScannerService() : new HttpScannerService();
}
