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
import { useScanResult } from "../scans/scan-queries";
import { countFindingsByType } from "../overview/overview-selectors";
import { filterFindings } from "./finding-selectors";
export function FindingsPage() {
  const { scanId = "" } = useParams();
  const query = useScanResult(scanId);
  const [search, setSearch] = useState("");
  const [type, setType] = useState("ALL");
  const findings = useMemo(
    () =>
      filterFindings(query.data?.findings ?? [], {
        query: search,
        vulnerabilityType: type,
      }),
    [query.data, search, type],
  );
  const counts = query.data ? countFindingsByType(query.data) : {};
  return (
    <AppShell>
      <ContentHeader
        kicker="VERIFIED RESULTS"
        title="Findings"
        description="규칙으로 검증된 Finding과 마스킹된 Evidence를 살펴보세요."
      />
      <div className="filters">
        <SearchField
          label="Search findings"
          placeholder="Search finding, operation, or field"
          value={search}
          onChange={setSearch}
        />
        <select
          aria-label="Finding type"
          value={type}
          onChange={(event) => setType(event.target.value)}
        >
          <option>ALL</option>
          <option>BOLA</option>
          <option>DATA</option>
          <option>AUTH</option>
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
              label="Finding types"
              segments={Object.entries(counts).map(([name, value]) => ({
                name,
                value,
              }))}
            />
            {findings.length ? (
              <div className="table">
                {findings.map((finding) => (
                  <Link
                    className="tr"
                    key={finding.finding_id}
                    to={`/scans/${scanId}/findings/${finding.finding_id}`}
                  >
                    <Badge tone={finding.vulnerability_type}>
                      {finding.vulnerability_type}
                    </Badge>
                    <b>{finding.operation_id}</b>
                    <span>{finding.affected_fields[0]?.field_path}</span>
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
