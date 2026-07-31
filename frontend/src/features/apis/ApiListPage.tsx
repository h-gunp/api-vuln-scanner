import { ChevronRight } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { AppShell } from "../../components/layout/AppShell";
import { ContentHeader } from "../../components/layout/ContentHeader";
import { AsyncState } from "../../components/ui/AsyncState";
import { EmptyState } from "../../components/ui/EmptyState";
import { SearchField } from "../../components/ui/SearchField";
import { useEndpoints } from "../scans/scan-queries";
import { filterOperations } from "./api-selectors";
export function ApiListPage() {
  const { scanId = "" } = useParams();
  const query = useEndpoints(scanId);
  const [search, setSearch] = useState("");
  const operations = useMemo(
    () => filterOperations(query.data?.items ?? [], search),
    [query.data, search],
  );
  return (
    <AppShell>
      <ContentHeader
        kicker="API 목록"
        title="발견된 API"
        description="백엔드가 반환한 endpoint를 탐색하세요."
      />
      <SearchField
        label="API 검색"
        placeholder="method, path 또는 operation ID 검색"
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
              <span>Operation ID</span>
              <span />
            </div>
            {operations.map((operation) => (
              <Link
                className="tr"
                key={operation.operationId}
                to={`/scans/${scanId}/apis/${encodeURIComponent(operation.operationId)}`}
              >
                <span className="method">{operation.method}</span>
                <b>{operation.path}</b>
                <span>{operation.operationId}</span>
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
