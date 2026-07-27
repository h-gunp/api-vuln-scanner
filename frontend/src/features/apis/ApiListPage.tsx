import { ChevronRight } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { AppShell } from "../../components/layout/AppShell";
import { ContentHeader } from "../../components/layout/ContentHeader";
import { AsyncState } from "../../components/ui/AsyncState";
import { EmptyState } from "../../components/ui/EmptyState";
import { SearchField } from "../../components/ui/SearchField";
import { useApiGraph } from "../scans/scan-queries";
import { filterOperations } from "./api-selectors";
export function ApiListPage() {
  const { scanId = "" } = useParams();
  const query = useApiGraph(scanId);
  const [search, setSearch] = useState("");
  const operations = useMemo(
    () => filterOperations(query.data?.operations ?? [], search),
    [query.data, search],
  );
  return (
    <AppShell>
      <ContentHeader
        kicker="API INVENTORY"
        title="Discovered APIs"
        description="정규화된 API graph의 operation을 탐색하세요."
      />
      <SearchField
        label="Search APIs"
        placeholder="Search method, path, or field"
        value={search}
        onChange={setSearch}
      />
      <AsyncState
        isLoading={query.isLoading}
        error={query.error}
        onRetry={() => void query.refetch()}
      >
        {operations.length ? (
          <div className="table">
            <div className="tr th">
              <span>Method</span>
              <span>Path</span>
              <span>Outputs</span>
              <span />
            </div>
            {operations.map((operation) => (
              <Link
                className="tr"
                key={operation.operation_id}
                to={`/scans/${scanId}/apis/${encodeURIComponent(operation.operation_id)}`}
              >
                <span className="method">{operation.method}</span>
                <b>{operation.path_template}</b>
                <span>{operation.outputs.length} fields</span>
                <ChevronRight />
              </Link>
            ))}
          </div>
        ) : (
          <EmptyState
            title="API를 찾을 수 없습니다"
            description="검색 조건을 변경하세요."
          />
        )}
      </AsyncState>
    </AppShell>
  );
}
