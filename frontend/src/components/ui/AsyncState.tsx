import type { ReactNode } from "react";
export function AsyncState({
  isLoading,
  error,
  onRetry,
  children,
}: {
  isLoading: boolean;
  error: Error | null;
  onRetry?: () => void;
  children: ReactNode;
}) {
  if (isLoading)
    return (
      <div className="skeleton" role="status" aria-label="Loading content">
        <i />
        <i />
        <i />
      </div>
    );
  if (error)
    return (
      <div className="empty" role="alert">
        <b>데이터를 불러오지 못했습니다</b>
        <p>{error.message}</p>
        {onRetry && (
          <button className="secondary" onClick={onRetry}>
            다시 시도
          </button>
        )}
      </div>
    );
  return <>{children}</>;
}
