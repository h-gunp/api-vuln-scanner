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
        kicker="API DETAIL"
        title={operation?.path_template ?? "API not found"}
        description={
          operation
            ? `${operation.method} operation contract fields`
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
              <h2>Inputs</h2>
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
                <p>No declared inputs</p>
              )}
            </section>
            <section className="detail-card">
              <h2>Outputs</h2>
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
            title="API not found"
            description="정규화된 API graph에 없는 operation입니다."
          />
        )}
      </AsyncState>
    </AppShell>
  );
}
