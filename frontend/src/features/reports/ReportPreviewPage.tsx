<<<<<<< ours
import { useParams } from "react-router-dom";
=======
import { ArrowLeft } from "lucide-react";
import { Link, useParams } from "react-router-dom";
>>>>>>> theirs
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
<<<<<<< ours
        kicker="PRINT PREVIEW"
        title="Security report preview"
        description="인쇄 가능한 mock 보고서 미리보기입니다."
      />
=======
        kicker="인쇄 미리보기"
        title="보안 리포트 미리보기"
        description="인쇄 가능한 mock 보고서 미리보기입니다."
      />
      <Link className="back" to={`/scans/${scanId}/ai-report`}>
        <ArrowLeft /> AI 리포트로 돌아가기
      </Link>
>>>>>>> theirs
      <AsyncState
        isLoading={query.isLoading}
        error={query.error}
        onRetry={() => void query.refetch()}
      >
        {query.data && (
          <article className="report print-report">
<<<<<<< ours
            <h2>VulnScope Security Report</h2>
=======
            <h2>VulnScope 보안 리포트</h2>
>>>>>>> theirs
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
<<<<<<< ours
                  <b>Impact:</b> {finding.impact}
                </p>
                <p>
                  <b>Recommendation:</b> {finding.recommendation}
=======
                  <b>영향:</b> {finding.impact}
                </p>
                <p>
                  <b>권장 조치:</b> {finding.recommendation}
>>>>>>> theirs
                </p>
              </section>
            ))}
          </article>
        )}
      </AsyncState>
    </AppShell>
  );
}
