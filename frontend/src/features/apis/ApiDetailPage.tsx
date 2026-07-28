import { useParams } from "react-router-dom";
import { AppShell } from "../../components/layout/AppShell";
import { ContentHeader } from "../../components/layout/ContentHeader";
import { AsyncState } from "../../components/ui/AsyncState";
import { EmptyState } from "../../components/ui/EmptyState";
import { useEndpoints } from "../scans/scan-queries";
export function ApiDetailPage() {
  const { scanId = "", operationId = "" } = useParams();
  const query = useEndpoints(scanId);
  const operation = query.data?.items.find(
    (item) => item.operationId === decodeURIComponent(operationId),
  );
  return (
    <AppShell>
      <ContentHeader
        kicker="API 상세"
        title={operation?.path ?? "API를 찾을 수 없습니다"}
        description={
          operation
            ? `${operation.method} endpoint 계약`
            : "요청한 operation을 찾을 수 없습니다."
        }
      />
      <AsyncState
        isLoading={query.isLoading}
        error={query.error}
        onRetry={() => void query.refetch()}
      >
        {operation ? (
          <div className="two-col">
            <section className="detail-card">
              <h2>Endpoint</h2>
              <div className="field"><b>Method</b><span>{operation.method}</span></div>
              <div className="field"><b>Path</b><span>{operation.path}</span></div>
              <div className="field"><b>Operation ID</b><span>{operation.operationId}</span></div>
            </section>
            <section className="detail-card">
              <h2>입출력 계약</h2>
              <p>endpoint의 입력·출력 상세 필드는 현재 백엔드 계약에 포함되지 않았습니다.</p>
            </section>
          </div>
        ) : (
          <EmptyState
            title="API를 찾을 수 없습니다"
            description="백엔드가 반환한 endpoint에 없는 operation입니다."
          />
        )}
      </AsyncState>
    </AppShell>
  );
}
