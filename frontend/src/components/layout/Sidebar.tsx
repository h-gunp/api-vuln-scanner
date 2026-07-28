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
<<<<<<< ours
  ["overview", "Overview", LayoutDashboard],
  ["apis", "APIs", Braces],
  ["findings", "Findings", ShieldCheck],
  ["ai-report", "AI Report", Bot],
=======
  ["overview", "개요", LayoutDashboard],
  ["apis", "APIs", Braces],
  ["findings", "Finding", ShieldCheck],
  ["ai-report", "AI 리포트", Bot],
>>>>>>> theirs
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
<<<<<<< ours
        <p className="eyebrow">WORKSPACE</p>
        <nav aria-label="Main navigation">
=======
        <p className="eyebrow">작업 공간</p>
        <nav aria-label="주요 메뉴">
>>>>>>> theirs
          {links.map(([path, label, Icon]) => (
            <NavLink
              key={path}
              onClick={() => setOpen(false)}
              to={`/scans/${scanId}/${path}`}
            >
              <Icon aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="side-foot">
<<<<<<< ours
          <span className="live-dot" /> Mock workspace
          <br />
          <small>Local data only</small>
=======
          <span className="live-dot" /> Mock 작업 공간
          <br />
          <small>로컬 데이터만 사용</small>
>>>>>>> theirs
        </div>
      </aside>
    </>
  );
}
