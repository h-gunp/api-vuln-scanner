import { useParams } from "react-router-dom";
import { AppShell } from "../../components/layout/AppShell";
import { ContentHeader } from "../../components/layout/ContentHeader";
import { AsyncState } from "../../components/ui/AsyncState";
import { useAiReport } from "../scans/scan-queries";
export function ReportPreviewPage() {
  const { scanId = "" } = useParams();
  const query = useAiReport(scanId);
  return (
    <AppShell>
      <ContentHeader
        kicker="PRINT PREVIEW"
        title="Security report preview"
        description="인쇄 가능한 mock 보고서 미리보기입니다."
      />
      <AsyncState
        isLoading={query.isLoading}
        error={query.error}
        onRetry={() => void query.refetch()}
      >
        {query.data && (
          <article className="report print-report">
            <h2>VulnScope Security Report</h2>
            <p>{query.data.summary}</p>
            {query.data.findings.map((finding) => (
              <section key={finding.finding_id}>
                <h3>
                  {finding.finding_id} · {finding.severity}
                </h3>
                <p>{finding.root_cause}</p>
                <ol>
                  {finding.attack_flow.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ol>
                <p>
                  <b>Impact:</b> {finding.impact}
                </p>
                <p>
                  <b>Recommendation:</b> {finding.recommendation}
                </p>
              </section>
            ))}
          </article>
        )}
      </AsyncState>
    </AppShell>
  );
}
