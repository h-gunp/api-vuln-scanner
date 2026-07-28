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
  useEndpoints,
  useFindings,
  useScanSummary,
} from "../scans/scan-queries";
import {
  countFindingsByType,
  countOperationsByMethod,
  selectRecentFindings,
} from "./overview-selectors";
export function OverviewPage() {
  const { scanId = "" } = useParams();
  const overview = useScanSummary(scanId);
  const apis = useEndpoints(scanId);
  const results = useFindings(scanId);
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
        title="보안 개요"
        description="API 노출 영역과 검증된 Finding을 한눈에 확인하세요."
      />
      <AsyncState isLoading={loading} error={error} onRetry={retry}>
        {overview.data && apis.data && results.data && report.data && (
          <>
            <section className="metrics">
              <MetricCard
                to={`/scans/${scanId}/progress`}
                label="스캔 진행률"
                value={`${overview.data.progress}%`}
                detail={overview.data.stage}
              />
              <MetricCard
                to={`/scans/${scanId}/apis`}
                label="API 발견 수"
                value={`${overview.data.apiCount}`}
                detail={`${apis.data.items.length}개 endpoint 반환`}
              />
              <MetricCard
                to={`/scans/${scanId}/findings`}
                label="검증된 Finding"
                value={`${overview.data.findingCount}`}
                detail={`${results.data.totalElements}개 결과 반환`}
              />
              <MetricCard
                to={`/scans/${scanId}/ai-report`}
                label="AI Report"
                value={overview.data.reportStatus}
                detail="백엔드 리포트 상태"
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
                    <Braces /> API 발견 수
                  </span>
                  <ChevronRight />
                </div>
                <DonutChart
                  label="API 메서드"
                  segments={Object.entries(
                    countOperationsByMethod(apis.data.items),
                  ).map(([name, value]) => ({ name, value }))}
                />
              </Link>
              <Link className="panel" to={`/scans/${scanId}/findings`}>
                <div className="panel-title">
                  <span>
                    <ShieldCheck /> Finding 유형별 현황
                  </span>
                  <ChevronRight />
                </div>
                <DonutChart
                  label="Finding 유형"
                  segments={Object.entries(
                    countFindingsByType(results.data.items),
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
                <p>검증된 Evidence만 사용</p>
                <h2>의사결정용 보안 요약</h2>
                <p>{report.data.summary}</p>
                <span className="text-link">리포트 보기 →</span>
              </Link>
            </div>
            <section className="recent">
              <div className="panel-title">
                <span>최근 Finding</span>
                <Link to={`/scans/${scanId}/findings`}>전체 보기</Link>
              </div>
              {results.data.items.length === 0 ? (
                <EmptyState
                  title="확정된 Finding이 없습니다"
                  description="현재 결과는 안전함의 증명이 아닙니다."
                />
              ) : (
                selectRecentFindings(results.data.items, 3).map((finding) => (
                  <Link
                    to={`/scans/${scanId}/findings/${finding.findingId}`}
                    key={finding.findingId}
                  >
                    <Badge tone={finding.moduleId}>
                      {finding.moduleId}
                    </Badge>
                    <b>{finding.targetEndpoint.path}</b>
                    <small>{finding.title}</small>
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
