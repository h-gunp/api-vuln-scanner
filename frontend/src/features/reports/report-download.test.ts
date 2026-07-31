import { expect, it, vi } from "vitest";
import type { ScannerService } from "../../services/scanner-service";
import { downloadReport } from "./report-download";

it("downloads the PDF returned by the backend with its content-disposition filename", async () => {
  const url = "blob:backend";
  const pdf = new Blob(["pdf"], { type: "application/pdf" });
  const service = { downloadReport: vi.fn().mockResolvedValue({ blob: pdf, filename: "security-report.pdf" }) } as unknown as ScannerService;
  const create = vi.spyOn(URL, "createObjectURL").mockReturnValue(url);
  const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);

  await downloadReport(service, "report-123", "scan-123");

  expect(service.downloadReport).toHaveBeenCalledWith("report-123");
  expect(create).toHaveBeenCalledWith(pdf);
  expect(click).toHaveBeenCalledOnce();
  expect(revoke).toHaveBeenCalledWith(url);
  create.mockRestore();
  revoke.mockRestore();
  click.mockRestore();
});
