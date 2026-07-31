import type { PropsWithChildren } from "react";
import { Sidebar } from "./Sidebar";
export function AppShell({ children }: PropsWithChildren) {
  return (
    <div className="shell">
      <Sidebar />
      <main>{children}</main>
    </div>
  );
}
