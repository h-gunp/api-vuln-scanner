import { useParams } from "react-router-dom";
import { AppShell } from "../../components/layout/AppShell";
import { ContentHeader } from "../../components/layout/ContentHeader";
import { AsyncState } from "../../components/ui/AsyncState";
import { Badge } from "../../components/ui/Badge";
import { EmptyState } from "../../components/ui/EmptyState";
import { useEvidence, useScanResult } from "../scans/scan-queries";
function EvidenceBlock({ evidenceRef }: { evidenceRef: string }) {
  const query = useEvidence(evidenceRef);
  return (
    <AsyncState
      isLoading={query.isLoading}
      error={query.error}
      onRetry={() => void query.refetch()}
    >
      {query.data && (
        <div>
          <h3>{query.data.ref}</h3>
          <pre>{query.data.requestSummary}</pre>
          <pre>{query.data.responseSummary}</pre>
        </div>
      )}
    </AsyncState>
  );
}
export function FindingDetailPage() {
  const { scanId = "", findingId = "" } = useParams();
  const query = useScanResult(scanId);
  const finding = query.data?.findings.find(
    (item) => item.finding_id === findingId,
  );
  return (
    <AppShell>
      <ContentHeader
        kicker="FINDING DETAIL"
        title={finding?.finding_id ?? "Finding not found"}
        description={
          finding?.operation_id ?? "요청한 Finding을 찾을 수 없습니다."
        }
      />
      <AsyncState
        isLoading={query.isLoading}
        error={query.error}
        onRetry={() => void query.refetch()}
      >
        {finding ? (
          <div className="two-col">
            <section className="detail-card">
              <Badge tone={finding.vulnerability_type}>
                {finding.vulnerability_type}
              </Badge>
              <h2>Verification</h2>
              <div className="field">
                <b>Rule</b>
                <span>{finding.verification.rule_id}</span>
              </div>
              {finding.verification.verified_conditions.map((condition) => (
                <div className="field" key={condition}>
                  <b>Verified condition</b>
                  <span>{condition}</span>
                </div>
              ))}
              <h2>Affected fields</h2>
              {finding.affected_fields.map((field) => (
                <div
                  className="field"
                  key={`${field.location}-${field.field_path}`}
                >
                  <b>{field.field_path}</b>
                  <span>
                    {field.location} · {field.data_class}
                  </span>
                </div>
              ))}
            </section>
            <section className="detail-card evidence">
              <h2>Redacted Evidence</h2>
              {finding.evidence_refs.map((ref) => (
                <EvidenceBlock evidenceRef={ref} key={ref} />
              ))}
            </section>
          </div>
        ) : (
          <EmptyState
            title="Finding not found"
            description="확정된 scan result에 없는 Finding입니다."
          />
        )}
      </AsyncState>
    </AppShell>
  );
}
