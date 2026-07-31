export interface TargetProfile {
  schema_version: "1.1";
  scan_id: string;
  target: {
    base_url: string;
    allowed_paths: string[];
    allowed_methods: string[];
  };
  discovery: { sources: Array<"openapi" | "crawl">; max_depth: number };
  authentication: {
    login: {
      method: string;
      path: string;
      content_type: string;
      username_field: string;
      password_field: string;
      session: { type: string; token_field: string };
    };
    actors: Array<{
      actor_id: "user_a" | "user_b";
      username_env: string;
      password_env: string;
    }>;
  };
  safety_policy: {
    max_requests: number;
    requests_per_second: number;
    state_change_policy: string;
    approved_modules: string[];
  };
}
