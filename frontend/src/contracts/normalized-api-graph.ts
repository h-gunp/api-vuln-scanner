import type { InputLocation, JsonFieldType } from "./common";
export interface NormalizedApiGraph {
  schema_version: "1.1";
  scan_id: string;
  operations: Array<{
    operation_id: string;
    method: string;
    path_template: string;
    inputs: Array<{
      location: InputLocation;
      field_path: string;
      type: JsonFieldType;
    }>;
    outputs: Array<{ field_path: string; type: JsonFieldType }>;
  }>;
}
