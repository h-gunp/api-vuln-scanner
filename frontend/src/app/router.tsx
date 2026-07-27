import {
  Navigate,
  createBrowserRouter,
  type RouteObject,
} from "react-router-dom";
import { ApiDetailPage } from "../features/apis/ApiDetailPage";
import { ApiListPage } from "../features/apis/ApiListPage";
import { FindingDetailPage } from "../features/findings/FindingDetailPage";
import { FindingsPage } from "../features/findings/FindingsPage";
import { OverviewPage } from "../features/overview/OverviewPage";
import { AiReportPage } from "../features/reports/AiReportPage";
import { ReportPreviewPage } from "../features/reports/ReportPreviewPage";
import { ScanProgressPage } from "../features/scans/ScanProgressPage";
import { ScanSetupPage } from "../features/scans/ScanSetupPage";

export const routes: RouteObject[] = [
  { path: "/scans/new", element: <ScanSetupPage /> },
  { path: "/scans/:scanId/overview", element: <OverviewPage /> },
  { path: "/scans/:scanId/progress", element: <ScanProgressPage /> },
  { path: "/scans/:scanId/apis", element: <ApiListPage /> },
  { path: "/scans/:scanId/apis/:operationId", element: <ApiDetailPage /> },
  { path: "/scans/:scanId/findings", element: <FindingsPage /> },
  {
    path: "/scans/:scanId/findings/:findingId",
    element: <FindingDetailPage />,
  },
  { path: "/scans/:scanId/ai-report", element: <AiReportPage /> },
  { path: "/scans/:scanId/ai-report/preview", element: <ReportPreviewPage /> },
  { path: "*", element: <Navigate to="/scans/new" replace /> },
];

export const router = createBrowserRouter(routes);
