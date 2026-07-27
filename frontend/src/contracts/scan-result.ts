import type { AffectedLocation, DataClass } from "./common";
export interface ScanResult {
  schema_version: "1.2";
  scan_id: string;
  findings: Array<{
    finding_id: string;
    operation_id: string;
    vulnerability_type: string;
    verification: { rule_id: string; verified_conditions: string[] };
    affected_fields: Array<{
      location: AffectedLocation;
      field_path: string;
      data_class: DataClass;
    }>;
    evidence_refs: string[];
  }>;
}
