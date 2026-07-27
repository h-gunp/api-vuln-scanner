export interface AiReport {
  schema_version: "1.2";
  scan_id: string;
  model_name: string;
  prompt_version: string;
  prompt_sha256: string;
  overall_risk: string;
  overall_risk_basis: "rule:max_verified_severity";
  summary: string;
  findings: Array<{
    finding_id: string;
    analysis_id: string;
    root_cause: string;
    attack_flow: string[];
    impact: string;
    recommendation: string;
    severity: string;
    evidence_refs: string[];
  }>;
}
