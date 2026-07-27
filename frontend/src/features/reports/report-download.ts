import type { AiReport } from "../../contracts";
import { createMockReportPdf } from "../../services/mock/mock-pdf";
export async function downloadMockReport(report: AiReport) {
  const url = URL.createObjectURL(await createMockReportPdf(report));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `vulnscope-${report.scan_id}-report.pdf`;
  anchor.click();
  URL.revokeObjectURL(url);
}
