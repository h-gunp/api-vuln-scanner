import { FileSearch } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { AppShell } from "../../components/layout/AppShell";
import { ContentHeader } from "../../components/layout/ContentHeader";
import { AsyncState } from "../../components/ui/AsyncState";
import { Badge } from "../../components/ui/Badge";
import { useAiReport } from "../scans/scan-queries";
import { downloadMockReport } from "./report-download";
export function AiReportPage() {
  const { scanId = "" } = useParams();
  const query = useAiReport(scanId);
  return (
    <AppShell>
      <ContentHeader
        kicker="AI-GENERATED BRIEF"
        title="Security report"
        description="검증된 Finding만을 기반으로 생성된 mock 보고서입니다."
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
                <FileSearch /> Preview
              </Link>
              <button
                className="primary compact"
                onClick={() => void downloadMockReport(query.data)}
              >
                Download PDF
              </button>
            </div>
            <article className="report">
              <Badge tone="BOLA">{query.data.overall_risk} risk</Badge>
              <h2>Executive summary</h2>
              <p>{query.data.summary}</p>
              {query.data.findings.map((finding) => (
                <section key={finding.finding_id}>
                  <Link to={`/scans/${scanId}/findings/${finding.finding_id}`}>
                    {finding.finding_id} →
                  </Link>
                  <h3>{finding.root_cause}</h3>
                  <ol>
                    {finding.attack_flow.map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ol>
                  <b>Impact</b>
                  <p>{finding.impact}</p>
                  <b>Recommendation</b>
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
