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
<<<<<<< ours
        kicker="SCAN PROGRESS"
        title="Verification pipeline"
        description="Mock 실행 상태이며 백엔드 응답 계약이 아닙니다."
      />
      <Link className="back" to={`/scans/${scanId}/overview`}>
        ← Back to overview
=======
        kicker="스캔 진행률"
        title="검증 진행 상태"
        description="Mock 실행 상태이며 백엔드 응답 계약이 아닙니다."
      />
      <Link className="back" to={`/scans/${scanId}/overview`}>
        ← 개요로 돌아가기
>>>>>>> theirs
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
<<<<<<< ours
              <span>Overall progress · {query.data.currentStageId}</span>
=======
              <span>전체 진행률 · {query.data.currentStageId}</span>
>>>>>>> theirs
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
