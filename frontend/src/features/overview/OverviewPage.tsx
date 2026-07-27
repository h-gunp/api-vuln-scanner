import { Activity, Bot, Braces, ChevronRight, ShieldCheck } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { AppShell } from "../../components/layout/AppShell";
import { ContentHeader } from "../../components/layout/ContentHeader";
import { AsyncState } from "../../components/ui/AsyncState";
import { Badge } from "../../components/ui/Badge";
import { DonutChart } from "../../components/ui/DonutChart";
import { EmptyState } from "../../components/ui/EmptyState";
import { MetricCard } from "../../components/ui/MetricCard";
import {
  useAiReport,
  useApiGraph,
  useScanOverview,
  useScanResult,
} from "../scans/scan-queries";
import {
  countFindingsByType,
  countOperationsByMethod,
  selectRecentFindings,
} from "./overview-selectors";
export function OverviewPage() {
  const { scanId = "" } = useParams();
  const overview = useScanOverview(scanId);
  const apis = useApiGraph(scanId);
  const results = useScanResult(scanId);
  const report = useAiReport(scanId);
  const loading =
    overview.isLoading ||
    apis.isLoading ||
    results.isLoading ||
    report.isLoading;
  const error = overview.error || apis.error || results.error || report.error;
  const retry = () =>
    void Promise.all([
      overview.refetch(),
      apis.refetch(),
      results.refetch(),
      report.refetch(),
    ]);
  return (
    <AppShell>
      <ContentHeader
        kicker={`SCAN / ${scanId.toUpperCase()}`}
        title="Security overview"
        description="API 노출 영역과 검증된 Finding을 한눈에 확인하세요."
      />
      <AsyncState isLoading={loading} error={error} onRetry={retry}>
        {overview.data && apis.data && results.data && report.data && (
          <>
            <section className="metrics">
              <MetricCard
                to={`/scans/${scanId}/progress`}
                label="Scan progress"
                value={`${overview.data.progress}%`}
                detail={overview.data.stage}
              />
              <MetricCard
                to={`/scans/${scanId}/apis`}
                label="Discovered APIs"
                value={`${apis.data.operations.length}`}
                detail="24 GET · 4 POST"
              />
              <MetricCard
                to={`/scans/${scanId}/findings`}
                label="Verified findings"
                value={`${results.data.findings.length}`}
                detail="2 high priority"
              />
              <MetricCard
                to={`/scans/${scanId}/ai-report`}
                label="AI Report"
                value="Ready"
                detail="Generated from verified data"
                tone="ready"
              />
            </section>
            <div className="grid">
              <Link className="panel" to={`/scans/${scanId}/progress`}>
                <div className="panel-title">
                  <span>
                    <Activity /> Scan pipeline
                  </span>
                  <ChevronRight />
                </div>
                <div className="progress">
                  <i style={{ width: `${overview.data.progress}%` }} />
                </div>
                <div className="pipeline">
                  <b>Discovery</b>
                  <b>Analysis</b>
                  <b>Verification</b>
                  <span>Reporting</span>
                </div>
              </Link>
              <Link className="panel" to={`/scans/${scanId}/apis`}>
                <div className="panel-title">
                  <span>
                    <Braces /> API discovery
                  </span>
                  <ChevronRight />
                </div>
                <DonutChart
                  label="API methods"
                  segments={Object.entries(
                    countOperationsByMethod(apis.data),
                  ).map(([name, value]) => ({ name, value }))}
                />
              </Link>
              <Link className="panel" to={`/scans/${scanId}/findings`}>
                <div className="panel-title">
                  <span>
                    <ShieldCheck /> Finding breakdown
                  </span>
                  <ChevronRight />
                </div>
                <DonutChart
                  label="Finding types"
                  segments={Object.entries(
                    countFindingsByType(results.data),
                  ).map(([name, value]) => ({ name, value }))}
                />
              </Link>
              <Link
                className="panel report-card"
                to={`/scans/${scanId}/ai-report`}
              >
                <div className="panel-title">
                  <span>
                    <Bot /> AI Report
                  </span>
                  <ChevronRight />
                </div>
                <p>Verified evidence only</p>
                <h2>Executive-ready security brief</h2>
                <p>{report.data.summary}</p>
                <span className="text-link">View report →</span>
              </Link>
            </div>
            <section className="recent">
              <div className="panel-title">
                <span>Recent findings</span>
                <Link to={`/scans/${scanId}/findings`}>View all</Link>
              </div>
              {results.data.findings.length === 0 ? (
                <EmptyState
                  title="확정된 Finding이 없습니다"
                  description="현재 결과는 안전함의 증명이 아닙니다."
                />
              ) : (
                selectRecentFindings(results.data, 3).map((finding) => (
                  <Link
                    to={`/scans/${scanId}/findings/${finding.finding_id}`}
                    key={finding.finding_id}
                  >
                    <Badge tone={finding.vulnerability_type}>
                      {finding.vulnerability_type}
                    </Badge>
                    <b>{finding.operation_id}</b>
                    <small>{finding.affected_fields[0]?.field_path}</small>
                    <ChevronRight />
                  </Link>
                ))
              )}
            </section>
          </>
        )}
      </AsyncState>
    </AppShell>
  );
}
