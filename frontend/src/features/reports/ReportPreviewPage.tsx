import { ArrowLeft } from "lucide-react";
import { Link, useParams } from "react-router-dom";
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
        kicker="인쇄 미리보기"
        title="보안 리포트 미리보기"
        description="백엔드 AI 리포트의 화면 미리보기입니다."
      />
      <Link className="back" to={`/scans/${scanId}/ai-report`}>
        <ArrowLeft /> AI 리포트로 돌아가기
      </Link>
      <AsyncState
        isLoading={query.isLoading}
        error={query.error}
        onRetry={() => void query.refetch()}
      >
        {query.data && (
          <article className="report print-report">
            <h2>VulnScope 보안 리포트</h2>
            <p>{query.data.summary}</p>
            {query.data.findings.map((finding) => (
              <section key={finding.findingId}>
                <h3>
                  {finding.findingId}
                </h3>
                <p>{finding.rootCause}</p>
                <ol>
                  {finding.attackFlow.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ol>
                <p>
                  <b>영향:</b> {finding.impact}
                </p>
                <p>
                  <b>권장 조치:</b> {finding.recommendation}
                </p>
              </section>
            ))}
          </article>
        )}
      </AsyncState>
    </AppShell>
  );
}
