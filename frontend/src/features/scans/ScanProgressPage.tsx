import { Link, useParams } from "react-router-dom";
import { AppShell } from "../../components/layout/AppShell";
import { ContentHeader } from "../../components/layout/ContentHeader";
import { AsyncState } from "../../components/ui/AsyncState";
import { useScanStatus } from "./scan-queries";
export function ScanProgressPage() {
  const { scanId = "" } = useParams();
  const query = useScanStatus(scanId);
  return (
    <AppShell>
      <ContentHeader
        kicker="스캔 진행률"
        title="검증 진행 상태"
        description="백엔드가 반환한 현재 스캔 상태와 진행률입니다."
      />
      <Link className="back" to={`/scans/${scanId}/overview`}>
        ← 개요로 돌아가기
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
              <span>전체 진행률 · {query.data.stage}</span>
            </div>
            <div className="stage">
              <i>1</i>
              <span>
                <b>{query.data.stage}</b>
                <small>현재 백엔드 처리 단계</small>
              </span>
              <em>{query.data.status}</em>
            </div>
            {query.data.error && (
              <p className="error">{query.data.error.code}: {query.data.error.message}</p>
            )}
          </section>
        )}
      </AsyncState>
    </AppShell>
  );
}
