export type JsonFieldType =
  "string" | "integer" | "number" | "boolean" | "object" | "array" | "unknown";

export type InputLocation = "path" | "query" | "header" | "body";
export type AffectedLocation = "request" | "response";
export type DataClass =
  | "identity"
  | "account"
  | "financial"
  | "authentication"
  | "transaction"
  | "other";
