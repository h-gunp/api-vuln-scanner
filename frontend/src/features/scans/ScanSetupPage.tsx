import { ChevronRight, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useCreateScan } from "./scan-queries";
export function ScanSetupPage() {
  const navigate = useNavigate();
  const { createScan, isPending, error: submitError } = useCreateScan();
  const [targetUrl, setTargetUrl] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const urlValid = (() => {
    try {
      const protocol = new URL(targetUrl).protocol;
      return protocol === "http:" || protocol === "https:";
    } catch {
      return false;
    }
  })();
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitted(true);
    if (!urlValid) return;
    const result = await createScan({ targetUrl, scanConfig: null });
    navigate(`/scans/${result.scanId}/overview`);
  }
  return (
    <div className="setup">
      <div className="setup-copy">
        <div className="brand large">
          <span>V</span>
          <b>VulnScope</b>
        </div>
        <p className="eyebrow">안전한 API 평가</p>
        <h1>
          API를 먼저 확인하고
          <br />
          <em>공격보다 앞서 대응하세요.</em>
        </h1>
        <p>
          백엔드 스캔 서비스에 대상 URL을 전달해 API 보안 평가를 시작합니다.
        </p>
        <div className="trust">
          <ShieldCheck />
          <span>
            <b>백엔드 스캔 연동</b>
            <small>스캔 설정은 현재 확정 계약에 따라 비어 있는 값으로 전송됩니다.</small>
          </span>
        </div>
      </div>
      <form onSubmit={submit} noValidate>
        <p className="step">01 / 대상 설정</p>
        <h2>새 스캔 시작</h2>
        <p>스캔할 API 대상 URL을 입력하세요.</p>
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
        {submitError && (
          <p className="error" role="alert">
            {submitError.message}
          </p>
        )}
        <button className="primary" disabled={isPending} type="submit">
          {isPending ? "시작 중…" : "스캔 시작"}
          <ChevronRight />
        </button>
        <p className="fine">추가 인증·스캔 설정 필드는 백엔드 계약 확정 후 제공됩니다.</p>
      </form>
    </div>
  );
}
