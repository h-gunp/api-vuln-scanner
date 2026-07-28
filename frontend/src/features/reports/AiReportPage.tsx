import { FileSearch } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { AppShell } from "../../components/layout/AppShell";
import { ContentHeader } from "../../components/layout/ContentHeader";
import { AsyncState } from "../../components/ui/AsyncState";
import { Badge } from "../../components/ui/Badge";
import { useScannerService } from "../../services/service-context";
import { useAiReport } from "../scans/scan-queries";
import { downloadReport } from "./report-download";
export function AiReportPage() {
  const { scanId = "" } = useParams();
  const service = useScannerService();
  const query = useAiReport(scanId);
  return (
    <AppShell>
      <ContentHeader
        kicker="AI 생성 요약"
        title="AI 리포트"
        description="백엔드가 생성한 AI 리포트입니다."
      />
      <AsyncState
        isLoading={query.isLoading}
        error={query.error}
        onRetry={() => void query.refetch()}
      >
        {query.data && (
          <>
            <div className="report-actions">
              <Link
                className="secondary"
                to={`/scans/${scanId}/ai-report/preview`}
              >
                <FileSearch /> 미리보기
              </Link>
              <button
                className="primary compact"
                onClick={() => void downloadReport(service, query.data.reportId, scanId)}
              >
                PDF 다운로드
              </button>
            </div>
            <article className="report">
              <Badge tone="BOLA">{query.data.overallRisk} risk</Badge>
              <h2>핵심 요약</h2>
              <p>{query.data.summary}</p>
              {query.data.findings.map((finding) => (
                <section key={finding.findingId}>
                  <Link to={`/scans/${scanId}/findings/${finding.findingId}`}>
                    {finding.findingId} →
                  </Link>
                  <h3>{finding.rootCause}</h3>
                  <ol>
                    {finding.attackFlow.map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ol>
                  <b>영향</b>
                  <p>{finding.impact}</p>
                  <b>권장 조치</b>
                  <p>{finding.recommendation}</p>
                </section>
              ))}
            </article>
          </>
        )}
      </AsyncState>
    </AppShell>
  );
}
