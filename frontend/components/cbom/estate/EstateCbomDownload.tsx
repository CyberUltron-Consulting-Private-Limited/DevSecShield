"use client";

// The team's estate CBOM download (CB-26): JSON or XML CycloneDX 1.6, one component per asset across sources, with
// the file's SHA-256 shown after the download (the file is unsigned). Hooks: estate-cbom-json, estate-cbom-xml,
// estate-cbom-sha256.
import { useState } from "react";

import { downloadEstateCbom, type EstateDownload, type EstateFormat } from "./estateCbom";

export function EstateCbomResult({ info }: { info: EstateDownload }) {
  return (
    <p className="text-xs text-zinc-600 dark:text-zinc-400" data-testid="estate-cbom-result">
      {info.fileName}
      {info.assets !== null ? ` · ${info.assets} assets` : ""}
      {info.signature === "unsigned" ? " · unsigned" : ""}
      {info.sha256 && (
        <>
          {" · SHA-256 "}
          <code className="break-all" data-testid="estate-cbom-sha256">{info.sha256}</code>
        </>
      )}
    </p>
  );
}

export function EstateCbomDownload({ teamId }: { teamId: number }) {
  const [busy, setBusy] = useState<EstateFormat | null>(null);
  const [info, setInfo] = useState<EstateDownload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const get = async (format: EstateFormat) => {
    setBusy(format);
    setError(null);
    try {
      setInfo(await downloadEstateCbom(teamId, format));
    } catch {
      setError("Could not build the estate CBOM. Try again in a minute.");
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="space-y-2" data-testid="estate-cbom">
      <div className="flex flex-wrap gap-2">
        {(["json", "xml"] as EstateFormat[]).map((format) => (
          <button key={format} type="button" disabled={busy !== null} data-testid={`estate-cbom-${format}`}
                  className="rounded-md border border-zinc-300 px-2.5 py-1 text-xs font-medium dark:border-zinc-700"
                  onClick={() => get(format)}>
            {busy === format ? "Preparing…" : `Download CycloneDX ${format.toUpperCase()}`}
          </button>
        ))}
      </div>
      {info && <EstateCbomResult info={info} />}
      {error && <p className="text-xs text-red-600" role="alert">{error}</p>}
    </div>
  );
}
