import { Link, useParams } from "react-router-dom";
import { AppShell } from "../../components/layout/AppShell";
import { ContentHeader } from "../../components/layout/ContentHeader";
import { AsyncState } from "../../components/ui/AsyncState";
import { useScanProgress } from "./scan-queries";
export function ScanProgressPage() {
  const { scanId = "" } = useParams();
  const query = useScanProgress(scanId);
  return (
    <AppShell>
      <ContentHeader
        kicker="SCAN PROGRESS"
        title="Verification pipeline"
        description="Mock 실행 상태이며 백엔드 응답 계약이 아닙니다."
      />
      <Link className="back" to={`/scans/${scanId}/overview`}>
        ← Back to overview
      </Link>
      <AsyncState
        isLoading={query.isLoading}
        error={query.error}
        onRetry={() => void query.refetch()}
      >
        {query.data && (
          <section className="detail-card">
            <div className="big-progress">
              <b>{query.data.progress}%</b>
              <span>Overall progress · {query.data.currentStageId}</span>
            </div>
            {query.data.stages.map((stage, index) => (
              <div className="stage" key={stage.id}>
                <i>{index + 1}</i>
                <span>
                  <b>{stage.label}</b>
                  <small>{stage.description}</small>
                </span>
                <em>{stage.status}</em>
              </div>
            ))}
          </section>
        )}
      </AsyncState>
    </AppShell>
  );
}
