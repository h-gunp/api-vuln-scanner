import { ChevronRight, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useCreateScan } from "./scan-queries";
const emptyCredentials = {
  userA: { username: "", password: "" },
  userB: { username: "", password: "" },
};
export function ScanSetupPage() {
  const navigate = useNavigate();
  const { createScan, isPending, error: submitError } = useCreateScan();
  const [targetUrl, setTargetUrl] = useState("");
  const [credentials, setCredentials] = useState(emptyCredentials);
  const [submitted, setSubmitted] = useState(false);
  useEffect(() => () => setCredentials(emptyCredentials), []);
  const urlValid = (() => {
    try {
      const protocol = new URL(targetUrl).protocol;
      return protocol === "http:" || protocol === "https:";
    } catch {
      return false;
    }
  })();
  const field = (
    actor: "userA" | "userB",
    key: "username" | "password",
    label: string,
  ) => (
    <label>
      {label}
      <input
        type={key === "password" ? "password" : "text"}
        autoComplete="new-password"
        value={credentials[actor][key]}
        aria-invalid={submitted && !credentials[actor][key]}
        onChange={(event) =>
          setCredentials((current) => ({
            ...current,
            [actor]: { ...current[actor], [key]: event.target.value },
          }))
        }
      />
      {submitted && !credentials[actor][key] && (
        <small className="error">필수 입력입니다.</small>
      )}
    </label>
  );
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitted(true);
    if (
      !urlValid ||
      !credentials.userA.username ||
      !credentials.userA.password ||
      !credentials.userB.username ||
      !credentials.userB.password
    )
      return;
    const result = await createScan({ targetUrl, ...credentials });
    setCredentials(emptyCredentials);
    navigate(`/scans/${result.scanId}/overview`);
  }
  return (
    <div className="setup">
      <div className="setup-copy">
        <div className="brand large">
          <span>V</span>
          <b>VulnScope</b>
        </div>
<<<<<<< ours
        <p className="eyebrow">SAFE API ASSESSMENT</p>
        <h1>
          See your API
          <br />
          <em>before attackers do.</em>
=======
        <p className="eyebrow">안전한 API 평가</p>
        <h1>
          API를 먼저 확인하고
          <br />
          <em>공격보다 앞서 대응하세요.</em>
>>>>>>> theirs
        </h1>
        <p>
          두 개의 테스트 계정으로 API 권한 경계를 안전하게 검증합니다.
          자격증명은 브라우저 상태에만 머물며 제출 직후 삭제됩니다.
        </p>
        <div className="trust">
          <ShieldCheck />
          <span>
<<<<<<< ours
            <b>Mock-only workspace</b>
=======
            <b>Mock 전용 작업 공간</b>
>>>>>>> theirs
            <small>실제 네트워크 스캔은 실행하지 않습니다.</small>
          </span>
        </div>
      </div>
      <form onSubmit={submit} noValidate>
<<<<<<< ours
        <p className="step">01 / TARGET SETUP</p>
=======
        <p className="step">01 / 대상 설정</p>
>>>>>>> theirs
        <h2>새 스캔 시작</h2>
        <p>테스트 대상과 격리된 사용자 계정을 입력하세요.</p>
        <label>
          Target URL
          <input
            value={targetUrl}
            onChange={(event) => setTargetUrl(event.target.value)}
            placeholder="https://staging.example.test"
            aria-invalid={submitted && !urlValid}
          />
          {submitted && !urlValid && (
            <small className="error">
              http:// 또는 https:// URL을 입력하세요.
            </small>
          )}
        </label>
        <div className="actors">
          {field("userA", "username", "User A username")}
          {field("userA", "password", "User A password")}
          {field("userB", "username", "User B username")}
          {field("userB", "password", "User B password")}
        </div>
        {submitError && (
          <p className="error" role="alert">
            {submitError.message}
          </p>
        )}
        <button className="primary" disabled={isPending} type="submit">
<<<<<<< ours
          {isPending ? "Starting…" : "Start mock scan"}
=======
          {isPending ? "시작 중…" : "Mock 스캔 시작"}
>>>>>>> theirs
          <ChevronRight />
        </button>
        <p className="fine">입력 정보는 저장되거나 로그에 기록되지 않습니다.</p>
      </form>
    </div>
  );
}
