import {
  Bot,
  Braces,
  LayoutDashboard,
  Menu,
  ShieldCheck,
  X,
} from "lucide-react";
import { useState } from "react";
import { Link, NavLink, useParams } from "react-router-dom";
const links = [
  ["overview", "개요", LayoutDashboard],
  ["apis", "APIs", Braces],
  ["findings", "Finding", ShieldCheck],
  ["ai-report", "AI 리포트", Bot],
] as const;
export function Sidebar() {
  const { scanId = "scan-001" } = useParams();
  const [open, setOpen] = useState(false);
  return (
    <>
      <header className="mobile-head">
        <b>VulnScope</b>
        <button aria-label="메뉴" onClick={() => setOpen((value) => !value)}>
          {open ? <X /> : <Menu />}
        </button>
      </header>
      <aside className={open ? "open" : ""}>
        <Link className="brand" to="/scans/new">
          <span>V</span>
          <b>VulnScope</b>
        </Link>
        <p className="eyebrow">작업 공간</p>
        <nav aria-label="주요 메뉴">
          {links.map(([path, label, Icon]) => (
            <NavLink
              key={path}
              className={({ isActive }) => (isActive ? "active" : undefined)}
              onClick={() => setOpen(false)}
              to={`/scans/${scanId}/${path}`}
            >
              <Icon aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="side-foot">
          <span className="live-dot" /> 백엔드 작업 공간
          <br />
          <small>API 서버 연결 사용</small>
        </div>
      </aside>
    </>
  );
}
