import { useParams } from "react-router-dom";
import { AppShell } from "../../components/layout/AppShell";
import { ContentHeader } from "../../components/layout/ContentHeader";
import { AsyncState } from "../../components/ui/AsyncState";
import { EmptyState } from "../../components/ui/EmptyState";
import { useApiGraph } from "../scans/scan-queries";
export function ApiDetailPage() {
  const { scanId = "", operationId = "" } = useParams();
  const query = useApiGraph(scanId);
  const operation = query.data?.operations.find(
    (item) => item.operation_id === decodeURIComponent(operationId),
  );
  return (
    <AppShell>
      <ContentHeader
<<<<<<< ours
        kicker="API DETAIL"
        title={operation?.path_template ?? "API not found"}
        description={
          operation
            ? `${operation.method} operation contract fields`
=======
        kicker="API 상세"
        title={operation?.path_template ?? "API를 찾을 수 없습니다"}
        description={
          operation
            ? `${operation.method} operation 계약 field`
>>>>>>> theirs
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
<<<<<<< ours
              <h2>Inputs</h2>
=======
              <h2>입력</h2>
>>>>>>> theirs
              {operation.inputs.length ? (
                operation.inputs.map((input) => (
                  <div
                    className="field"
                    key={`${input.location}-${input.field_path}`}
                  >
                    <b>{input.field_path}</b>
                    <span>
                      {input.location} · {input.type}
                    </span>
                  </div>
                ))
              ) : (
<<<<<<< ours
                <p>No declared inputs</p>
              )}
            </section>
            <section className="detail-card">
              <h2>Outputs</h2>
=======
                <p>정의된 입력이 없습니다</p>
              )}
            </section>
            <section className="detail-card">
              <h2>출력</h2>
>>>>>>> theirs
              {operation.outputs.map((output) => (
                <div className="field" key={output.field_path}>
                  <b>{output.field_path}</b>
                  <span>{output.type}</span>
                </div>
              ))}
            </section>
          </div>
        ) : (
          <EmptyState
<<<<<<< ours
            title="API not found"
=======
            title="API를 찾을 수 없습니다"
>>>>>>> theirs
            description="정규화된 API graph에 없는 operation입니다."
          />
        )}
      </AsyncState>
    </AppShell>
  );
}
