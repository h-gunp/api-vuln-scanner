import type { ScannerService } from "../../services/scanner-service";

export async function downloadReport(
  service: ScannerService,
  reportId: string,
  scanId: string,
) {
  const { blob, filename } = await service.downloadReport(reportId);
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename ?? `vulnscope-${scanId}-report.pdf`;
  anchor.click();
  URL.revokeObjectURL(url);
}
