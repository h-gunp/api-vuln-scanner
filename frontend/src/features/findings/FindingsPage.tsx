import { ChevronRight } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { AppShell } from "../../components/layout/AppShell";
import { ContentHeader } from "../../components/layout/ContentHeader";
import { AsyncState } from "../../components/ui/AsyncState";
import { Badge } from "../../components/ui/Badge";
import { DonutChart } from "../../components/ui/DonutChart";
import { EmptyState } from "../../components/ui/EmptyState";
import { SearchField } from "../../components/ui/SearchField";
import { useFindings } from "../scans/scan-queries";
import { countFindingsByType } from "../overview/overview-selectors";
import { filterFindings } from "./finding-selectors";
export function FindingsPage() {
  const { scanId = "" } = useParams();
  const query = useFindings(scanId);
  const [search, setSearch] = useState("");
  const [moduleId, setModuleId] = useState("ALL");
  const findings = useMemo(
    () =>
      filterFindings(query.data?.items ?? [], {
        query: search,
        moduleId,
      }),
    [query.data, search, moduleId],
  );
  const counts = query.data ? countFindingsByType(query.data.items) : {};
  return (
    <AppShell>
      <ContentHeader
        kicker="검증 결과"
        title="Finding 목록"
        description="백엔드가 반환한 Finding 요약을 살펴보세요."
      />
      <div className="filters">
        <SearchField
          label="Finding 검색"
          placeholder="Finding, operation 또는 field 검색"
          value={search}
          onChange={setSearch}
        />
        <select
          aria-label="Finding 유형"
          value={moduleId}
          onChange={(event) => setModuleId(event.target.value)}
        >
          <option>ALL</option>
          <option>BOLA-001</option>
          <option>AUTHN-001</option>
          <option>INPUT-001</option>
          <option>DATA-001</option>
        </select>
      </div>
      <AsyncState
        isLoading={query.isLoading}
        error={query.error}
        onRetry={() => void query.refetch()}
      >
        {query.data && (
          <>
            <DonutChart
              label="Finding 유형"
              segments={Object.entries(counts).map(([name, value]) => ({
                name,
                value,
              }))}
            />
            {findings.length ? (
              <div className="table findings-results">
                {findings.map((finding) => (
                  <Link
                    className="tr"
                    key={finding.findingId}
                    to={`/scans/${scanId}/findings/${finding.findingId}`}
                  >
                    <Badge tone={finding.moduleId}>
                      {finding.moduleId}
                    </Badge>
                    <b>{finding.targetEndpoint.path}</b>
                    <span>{finding.title}</span>
                    <ChevronRight />
                  </Link>
                ))}
              </div>
            ) : (
              <EmptyState
                title="확정된 Finding이 없습니다"
                description="검색 결과가 없다는 사실은 안전함의 증명이 아닙니다."
              />
            )}
          </>
        )}
      </AsyncState>
    </AppShell>
  );
}
