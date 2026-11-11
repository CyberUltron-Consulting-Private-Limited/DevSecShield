// Why the estimate or start was refused, under the estimate button; the form keeps what was typed (X1, Nov 11:
// the error view's "Try Again" reloaded the page and wiped it).
export function ScanRequestError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <p role="alert" data-testid="scan-request-error" className="text-xs text-red-400 mt-2">
      {message}
    </p>
  );
}
