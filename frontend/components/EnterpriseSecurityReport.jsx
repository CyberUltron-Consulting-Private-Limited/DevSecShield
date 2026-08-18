"use client";

/**
 * EnterpriseSecurityReport — premium static SAST / SBOM report UI.
 * Presentation only. Mock data built-in for CTO-ready demos.
 *
 * Local preview only: /enterprise-security-report-preview (404 in production).
 */

import { useMemo, useState } from "react";
import styles from "./EnterpriseSecurityReport.module.css";

/* -------------------------------------------------------------------------- */
/* Mock data                                                                  */
/* -------------------------------------------------------------------------- */

const MOCK = {
  projectName: "payments-api",
  org: "Acme Financial",
  scannedAt: "Jul 22, 2026 · 10:14 AM IST",
  commit: "a7f3c91e2b8d4e6f0a1c3b5d7e9f2468",
  branch: "main",
  scanDuration: "2m 14s",
  scanner: "Zero Shield · Unified AppSec",
  sast: [
    {
      id: "SAST-001",
      severity: "Critical",
      title: "SQL injection via string-concatenated query",
      path: "services/query_builder.py",
      line: 87,
      snippet: 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
      cwe: "CWE-89",
    },
    {
      id: "SAST-002",
      severity: "High",
      title: "Exposed database URL written to stdout",
      path: "backup.py",
      line: 42,
      snippet: "print(db_url)",
      cwe: "CWE-532",
    },
    {
      id: "SAST-003",
      severity: "High",
      title: "Plaintext passwords copied into backup artifacts",
      path: "backup.py",
      line: 118,
      snippet: "password=user.password,",
      cwe: "CWE-312",
    },
    {
      id: "SAST-004",
      severity: "Medium",
      title: "Hard-coded restore path reduces environment isolation",
      path: "restore.py",
      line: 23,
      snippet: 'sqlite_file_name = "backups/26-11-2025-Backup.db"',
      cwe: "CWE-798",
    },
    {
      id: "SAST-005",
      severity: "Low",
      title: "Verbose exception details returned to clients",
      path: "api/errors.py",
      line: 55,
      snippet: 'return JSONResponse({"detail": str(exc)}, status_code=500)',
      cwe: "CWE-209",
    },
  ],
  sbom: [
    {
      name: "pillow",
      version: "10.2.0",
      license: "HPND",
      ecosystem: "PyPI",
      cves: ["CVE-2024-28219"],
      severity: "Critical",
    },
    {
      name: "cryptography",
      version: "41.0.7",
      license: "Apache-2.0 OR BSD-3-Clause",
      ecosystem: "PyPI",
      cves: ["CVE-2023-50782"],
      severity: "High",
    },
    {
      name: "urllib3",
      version: "1.26.18",
      license: "MIT",
      ecosystem: "PyPI",
      cves: ["CVE-2024-37891"],
      severity: "Medium",
    },
    {
      name: "requests",
      version: "2.31.0",
      license: "Apache-2.0",
      ecosystem: "PyPI",
      cves: [],
      severity: "Low",
    },
    {
      name: "sqlalchemy",
      version: "2.0.25",
      license: "MIT",
      ecosystem: "PyPI",
      cves: [],
      severity: "Low",
    },
  ],
};

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function pillClass(severity) {
  const s = String(severity || "").toLowerCase();
  if (s === "critical") return styles.pillCritical;
  if (s === "high") return styles.pillHigh;
  if (s === "medium") return styles.pillMedium;
  return styles.pillLow;
}

function countSeverity(items, key = "severity") {
  return items.reduce(
    (acc, item) => {
      const s = String(item[key] || "").toLowerCase();
      if (s === "critical") acc.critical += 1;
      else if (s === "high") acc.high += 1;
      else if (s === "medium") acc.medium += 1;
      else if (s === "low") acc.low += 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0 }
  );
}

function shortHash(hash) {
  if (!hash) return "—";
  return hash.length > 12 ? `${hash.slice(0, 7)}…${hash.slice(-4)}` : hash;
}

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 3l7 3v5c0 4.5-2.8 8.4-7 10-4.2-1.6-7-5.5-7-10V6l7-3z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path d="M9.5 12.2l1.8 1.8 3.4-3.6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function CodeIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M8 16l-4-4 4-4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M16 8l4 4-4 4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M13.5 6l-3 12" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

function PackageIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
      <path d="M12 12l8-4.5M12 12v9M12 12L4 7.5" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.8" />
      <path d="M8.5 12.5l2.3 2.3 4.7-5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/* -------------------------------------------------------------------------- */
/* Component                                                                  */
/* -------------------------------------------------------------------------- */

export default function EnterpriseSecurityReport({ data = MOCK }) {
  const [tab, setTab] = useState("sast");

  const sastCounts = useMemo(() => countSeverity(data.sast), [data.sast]);
  const sbomCveCount = useMemo(
    () => data.sbom.reduce((n, row) => n + (row.cves?.length || 0), 0),
    [data.sbom]
  );
  const totalIssues = data.sast.length + sbomCveCount;

  return (
    <div className={styles.wrap}>
      <div className={styles.shell}>
        {/* Header */}
        <div className={styles.topBar}>
          <div className={styles.brandRow}>
            <div className={styles.logoMark} aria-hidden="true">
              <ShieldIcon />
            </div>
            <div>
              <p className={styles.kicker}>{data.org} · Security Assessment</p>
              <h1 className={styles.title}>{data.projectName}</h1>
              <p className={styles.subtitle}>{data.scanner}</p>
            </div>
          </div>
          <div className={`${styles.actions} ${styles.noPrint}`}>
            <button type="button" className={styles.btn}>
              Share
            </button>
            <button type="button" className={`${styles.btn} ${styles.btnPrimary}`} onClick={() => window.print()}>
              Export PDF
            </button>
          </div>
        </div>

        {/* Meta */}
        <div className={styles.metaStrip}>
          <div className={styles.metaChip}>
            <div className={styles.metaLabel}>Project</div>
            <div className={styles.metaValue}>{data.projectName}</div>
          </div>
          <div className={styles.metaChip}>
            <div className={styles.metaLabel}>Scan timestamp</div>
            <div className={styles.metaValue}>{data.scannedAt}</div>
          </div>
          <div className={styles.metaChip}>
            <div className={styles.metaLabel}>Commit</div>
            <div className={`${styles.metaValue} ${styles.mono}`} title={data.commit}>
              {shortHash(data.commit)}
            </div>
          </div>
          <div className={styles.metaChip}>
            <div className={styles.metaLabel}>Branch</div>
            <div className={`${styles.metaValue} ${styles.mono}`}>{data.branch}</div>
          </div>
        </div>

        {/* Executive summary KPIs */}
        <section aria-label="Executive summary">
          <div className={styles.kpiGrid}>
            <article className={`${styles.kpiCard} ${styles.kpiNeutral}`}>
              <div className={styles.kpiLabel}>Total Issues</div>
              <div className={styles.kpiValue}>{totalIssues}</div>
              <div className={styles.kpiHint}>
                {data.sast.length} SAST · {sbomCveCount} SBOM CVEs
              </div>
            </article>
            <article className={`${styles.kpiCard} ${styles.kpiCritical}`}>
              <div className={styles.kpiLabel}>Critical</div>
              <div className={styles.kpiValue}>{sastCounts.critical}</div>
              <div className={styles.kpiHint}>Immediate remediation required</div>
            </article>
            <article className={`${styles.kpiCard} ${styles.kpiHigh}`}>
              <div className={styles.kpiLabel}>High</div>
              <div className={styles.kpiValue}>{sastCounts.high}</div>
              <div className={styles.kpiHint}>Prioritize in current sprint</div>
            </article>
            <article className={`${styles.kpiCard} ${styles.kpiTime}`}>
              <div className={styles.kpiLabel}>Scan Time</div>
              <div className={styles.kpiValue} style={{ fontSize: 26 }}>
                {data.scanDuration}
              </div>
              <div className={styles.kpiHint}>Completed successfully</div>
            </article>
          </div>
        </section>

        {/* Tabs */}
        <div className={`${styles.tabs} ${styles.noPrint}`} role="tablist" aria-label="Report sections">
          <button
            type="button"
            role="tab"
            className={`${styles.tab} ${tab === "sast" ? styles.tabActive : ""}`}
            aria-selected={tab === "sast"}
            onClick={() => setTab("sast")}
          >
            SAST ({data.sast.length})
          </button>
          <button
            type="button"
            role="tab"
            className={`${styles.tab} ${tab === "sbom" ? styles.tabActive : ""}`}
            aria-selected={tab === "sbom"}
            onClick={() => setTab("sbom")}
          >
            SBOM ({data.sbom.length})
          </button>
        </div>

        {/* SAST table */}
        <section className={`${styles.panel} ${tab !== "sast" ? styles.hidden : ""}`}>
          <div className={styles.panelHead}>
            <h2 className={styles.panelTitle}>
              <span className={styles.panelTitleIcon}>
                <CodeIcon />
              </span>
              SAST Findings
            </h2>
            <span className={styles.panelMeta}>{data.sast.length} issues</span>
          </div>

          {data.sast.length === 0 ? (
            <div className={styles.empty}>
              <div className={styles.emptyIcon}>
                <CheckIcon />
              </div>
              No static analysis findings detected.
            </div>
          ) : (
            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>Location</th>
                  </tr>
                </thead>
                <tbody>
                  {data.sast.map((f) => (
                    <tr key={f.id}>
                      <td>
                        <div className={styles.mono}>{f.id}</div>
                        {f.cwe ? (
                          <div className={styles.mono} style={{ color: "var(--muted)", marginTop: 4 }}>
                            {f.cwe}
                          </div>
                        ) : null}
                      </td>
                      <td>
                        <span className={`${styles.pill} ${pillClass(f.severity)}`}>{f.severity}</span>
                      </td>
                      <td>
                        <div className={styles.findingTitle}>{f.title}</div>
                        {f.snippet ? <pre className={styles.snippet}>{f.snippet}</pre> : null}
                      </td>
                      <td>
                        <div className={styles.mono}>
                          {f.path}
                          <span style={{ color: "var(--muted)" }}>:{f.line}</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* SBOM table */}
        <section className={`${styles.panel} ${tab !== "sbom" ? styles.hidden : ""}`}>
          <div className={styles.panelHead}>
            <h2 className={styles.panelTitle}>
              <span className={styles.panelTitleIcon}>
                <PackageIcon />
              </span>
              SBOM Dependencies
            </h2>
            <span className={styles.panelMeta}>{data.sbom.length} components</span>
          </div>

          {data.sbom.length === 0 ? (
            <div className={styles.empty}>
              <div className={styles.emptyIcon}>
                <CheckIcon />
              </div>
              No dependency inventory available.
            </div>
          ) : (
            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>Component</th>
                    <th>Version</th>
                    <th>License</th>
                    <th>Severity</th>
                    <th>CVEs</th>
                  </tr>
                </thead>
                <tbody>
                  {data.sbom.map((c) => (
                    <tr key={`${c.name}@${c.version}`}>
                      <td>
                        <div className={styles.mono} style={{ fontWeight: 650 }}>
                          {c.name}
                        </div>
                        {c.ecosystem ? (
                          <div style={{ color: "var(--muted)", fontSize: 11, marginTop: 3 }}>{c.ecosystem}</div>
                        ) : null}
                      </td>
                      <td>
                        <span className={styles.mono}>{c.version}</span>
                      </td>
                      <td>
                        <span className={styles.mono}>{c.license || "—"}</span>
                      </td>
                      <td>
                        <span className={`${styles.pill} ${pillClass(c.severity)}`}>{c.severity}</span>
                      </td>
                      <td>
                        {c.cves?.length ? (
                          <div className={styles.cveList}>
                            {c.cves.map((cve) => (
                              <span key={cve} className={styles.cve}>
                                {cve}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span style={{ color: "var(--muted)", fontSize: 12 }}>None</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <p className={styles.footerNote}>Confidential · Zero Shield Enterprise Security Report · Mock preview data</p>
      </div>
    </div>
  );
}

export { MOCK };
