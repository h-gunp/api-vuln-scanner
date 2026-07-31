import { createContext, useContext, type PropsWithChildren } from "react";
import type { ScannerService } from "./scanner-service";
import { HttpScannerService } from "./http-scanner-service";

const ServiceContext = createContext<ScannerService>(new HttpScannerService());
export function ServiceProvider({
  service,
  children,
}: PropsWithChildren<{ service: ScannerService }>) {
  return (
    <ServiceContext.Provider value={service}>
      {children}
    </ServiceContext.Provider>
  );
}
export function useScannerService() {
  return useContext(ServiceContext);
}
