import { useParams } from "react-router-dom";
import { AppShell } from "../../components/layout/AppShell";
import { ContentHeader } from "../../components/layout/ContentHeader";
import { AsyncState } from "../../components/ui/AsyncState";
import { Badge } from "../../components/ui/Badge";
import { EmptyState } from "../../components/ui/EmptyState";
import { useScannerService } from "../../services/service-context";
import { useQuery } from "@tanstack/react-query";

export function FindingDetailPage() {
  const { findingId = "" } = useParams();
  const service = useScannerService();
  const query = useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => service.getFinding(findingId),
  });
  const finding = query.data;
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
              <p>{finding.evidence ? "Evidence가 제공되었습니다." : "Evidence는 아직 제공되지 않았습니다."}</p>
            </section>
          </div>
        ) : (
          <EmptyState title="Finding을 찾을 수 없습니다" description="현재 scan의 Finding 목록에 없는 항목입니다." />
        )}
      </AsyncState>
    </AppShell>
  );
}
