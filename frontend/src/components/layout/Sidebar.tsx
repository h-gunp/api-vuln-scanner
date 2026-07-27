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
  ["overview", "Overview", LayoutDashboard],
  ["apis", "APIs", Braces],
  ["findings", "Findings", ShieldCheck],
  ["ai-report", "AI Report", Bot],
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
        <p className="eyebrow">WORKSPACE</p>
        <nav aria-label="Main navigation">
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
          <span className="live-dot" /> Mock workspace
          <br />
          <small>Local data only</small>
        </div>
      </aside>
    </>
  );
}
