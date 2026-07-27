import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { routes } from "../app/router";
import { ServiceProvider } from "../services/service-context";
import { MockScannerService } from "../services/mock/mock-scanner-service";
import type { ScannerService } from "../services/scanner-service";

export function renderRoute(
  path: string,
  options: { service?: ScannerService } = {},
) {
  const service = options.service ?? new MockScannerService();
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  const result = render(
    <ServiceProvider service={service}>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </ServiceProvider>,
  );
  return { ...result, service, queryClient, router };
}
