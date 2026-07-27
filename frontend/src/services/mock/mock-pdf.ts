import type { AiReport } from "../../contracts";
export function sanitizeReportText(value: string) {
  return value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, " ");
}
export async function createMockReportPdf(report: AiReport): Promise<Blob> {
  const { jsPDF } = await import("jspdf");
  const document = new jsPDF();
  document.text("VulnScope Security Report", 16, 20);
  document.text(sanitizeReportText(report.summary), 16, 32, { maxWidth: 175 });
  return document.output("blob");
}
