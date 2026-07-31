import { useState, type PropsWithChildren } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ServiceProvider } from "../services/service-context";
import { createDefaultScannerService } from "../services/default-scanner-service";
import type { ScannerService } from "../services/scanner-service";
export function AppProviders({
  children,
  service = createDefaultScannerService(),
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
