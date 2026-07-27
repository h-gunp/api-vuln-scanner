import { useState, type PropsWithChildren } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ServiceProvider } from "../services/service-context";
import { defaultScannerService } from "../services/mock/mock-scanner-service";
import type { ScannerService } from "../services/scanner-service";
export function AppProviders({
  children,
  service = defaultScannerService,
}: PropsWithChildren<{ service?: ScannerService }>) {
  const [queryClient] = useState(
    () => new QueryClient({ defaultOptions: { queries: { retry: false } } }),
  );
  return (
    <ServiceProvider service={service}>
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    </ServiceProvider>
  );
}
