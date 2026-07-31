import type { InputLocation } from "./common";
export interface ScanPlan {
  schema_version: "1.2";
  plan_id: string;
  scan_id: string;
  model_name: string;
  prompt_version: string;
  prompt_sha256: string;
  status: "PENDING_APPROVAL";
  budget: {
    requests_already_used: number;
    estimated_execution_requests: number;
    max_requests: number;
    within_budget: boolean;
  };
  steps: Array<{
    order: number;
    candidate_id: string;
    module_id: string;
    target_operation_id: string;
    target_endpoint: { method: string; path_template: string };
    input_bindings: Array<{
      parameter: string;
      location: InputLocation;
      binding_type: "object_binding" | "parameter_binding";
      object_type: string | null;
      owner: "user_a" | "user_b" | null;
    }>;
  }>;
}
