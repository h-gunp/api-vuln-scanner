import { expect, it } from "vitest";
import { mockAiReport } from "../../services/mock/mock-data";
import {
  createMockReportPdf,
  sanitizeReportText,
} from "../../services/mock/mock-pdf";
it("creates a valid sanitized mock PDF", async () => {
  expect(sanitizeReportText("safe\u0000text")).toBe("safe text");
  const blob = await createMockReportPdf(mockAiReport);
  expect(blob.type).toBe("application/pdf");
  const prefix = new TextDecoder().decode(
    (await blob.arrayBuffer()).slice(0, 4),
  );
  expect(prefix).toBe("%PDF");
});
