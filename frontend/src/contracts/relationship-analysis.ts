import type { InputLocation } from "./common";
export interface RelationshipAnalysis {
  schema_version: "1.2";
  scan_id: string;
  model_name: string;
  prompt_version: string;
  prompt_sha256: string;
  approved_module_ids: string[];
  relationships: Array<{
    relationship_id: string;
    source_operation_id: string;
    target_operation_id: string;
    source_field: string | null;
    target_parameter: string | null;
    target_parameter_location: InputLocation | null;
    relationship_type: string;
    confidence: number;
  }>;
  test_candidates: Array<{
    candidate_id: string;
    module_id: string;
    target_operation_id: string;
    required_object_types: string[];
    rationale: string;
    priority: number;
    executable: boolean;
    missing_requirements: string[];
    binding_hints: Array<{
      parameter: string;
      location: InputLocation;
      binding_type: "object_binding" | "parameter_binding";
      object_type: string | null;
    }>;
  }>;
}
