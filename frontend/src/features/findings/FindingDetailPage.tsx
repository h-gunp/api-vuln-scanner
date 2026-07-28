import { useParams } from "react-router-dom";
import { AppShell } from "../../components/layout/AppShell";
import { ContentHeader } from "../../components/layout/ContentHeader";
import { AsyncState } from "../../components/ui/AsyncState";
import { Badge } from "../../components/ui/Badge";
import { EmptyState } from "../../components/ui/EmptyState";
import { useFindings } from "../scans/scan-queries";

export function FindingDetailPage() {
  const { scanId = "", findingId = "" } = useParams();
  const query = useFindings(scanId);
  const finding = query.data?.items.find((item) => item.findingId === findingId);
  return (
    <AppShell>
      <ContentHeader
        kicker="Finding 상세"
        title={finding?.title ?? "Finding을 찾을 수 없습니다"}
        description={finding?.summary ?? "요청한 Finding을 찾을 수 없습니다."}
      />
      <AsyncState isLoading={query.isLoading} error={query.error} onRetry={() => void query.refetch()}>
        {finding ? (
          <div className="two-col">
            <section className="detail-card">
              <Badge tone={finding.moduleId}>{finding.moduleId}</Badge>
              <div className="field"><b>Severity</b><span>{finding.severity}</span></div>
              <div className="field"><b>Endpoint</b><span>{finding.targetEndpoint.method} {finding.targetEndpoint.path}</span></div>
              <div className="field"><b>Operation ID</b><span>{finding.targetEndpoint.operationId}</span></div>
            </section>
            <section className="detail-card evidence">
              <h2>Evidence</h2>
              <p>Evidence 형식과 조회 API는 아직 백엔드 계약에 확정되지 않아 표시하지 않습니다.</p>
            </section>
          </div>
        ) : (
          <EmptyState title="Finding을 찾을 수 없습니다" description="현재 scan의 Finding 목록에 없는 항목입니다." />
        )}
      </AsyncState>
    </AppShell>
  );
}
