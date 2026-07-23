"use client";

/**
 * SecurityReportTemplate — premium Refined Light AppSec report.
 * Mock data built-in. Wire real props later; no data-fetching here.
 *
 * Preview: /security-report-preview
 */

import { useMemo, useState } from "react";
import styles from "./SecurityReportTemplate.module.css";

const MOCK_META = {
  projectName: "payments-api",
  org: "Acme Financial",
  scanTimestamp: "Jul 22, 2026 · 10:14 AM IST",
  commitHash: "a7f3c91e2b8d4e6f0a1c3b5d7e9f2468",
  branch: "main",
  scanner: "Zero Shield · Unified AppSec",
  scanDuration: "2m 14s",
};

const MOCK_SAST = [
  {
    id: "SAST-001",
    severity: "Critical",
    title: "SQL injection via string-concatenated query",
    path: "services/query_builder.py",
    line: 87,
    snippet: 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
    cwe: "CWE-89",
    description:
      "User-controlled input is concatenated into a SQL statement, allowing query logic alteration and data exfiltration.",
    remediation: "Use parameterized queries. Never concatenate user input into SQL.",
  },
  {
    id: "SAST-002",
    severity: "High",
    title: "Exposed database URL written to stdout",
    path: "backup.py",
    line: 42,
    snippet: "print(db_url)",
    cwe: "CWE-532",
    description: "Connection details printed to stdout may land in shared logs.",
    remediation: "Remove secret logging. Use structured logs with redaction.",
  },
  {
    id: "SAST-003",
    severity: "High",
    title: "Plaintext passwords copied into backup artifacts",
    path: "backup.py",
    line: 118,
    snippet: "password=user.password,",
    cwe: "CWE-312",
    description: "Credential fields are persisted into backup payloads in cleartext.",
    remediation: "Exclude credential fields from backups; store hashed secrets only.",
  },
  {
    id: "SAST-004",
    severity: "Medium",
    title: "Hard-coded restore path reduces environment isolation",
    path: "restore.py",
    line: 23,
    snippet: 'sqlite_file_name = "backups/26-11-2025-Backup.db"',
    cwe: "CWE-798",
    description: "Fixed backup path can cause incorrect restores across environments.",
    remediation: "Load restore paths from configuration or environment variables.",
  },
  {
    id: "SAST-005",
    severity: "Low",
    title: "Verbose exception details returned to clients",
    path: "api/errors.py",
    line: 55,
    snippet: 'return JSONResponse({"detail": str(exc)}, status_code=500)',
    cwe: "CWE-209",
    description: "Raw exception strings in API responses may leak internals.",
    remediation: "Return generic client errors; log full details server-side only.",
  },
];

const MOCK_SBOM = [
  {
    name: "pillow",
    version: "10.2.0",
    license: "HPND",
    ecosystem: "PyPI",
    cves: ["CVE-2024-28219"],
    highestSeverity: "Critical",
  },
  {
    name: "cryptography",
    version: "41.0.7",
    license: "Apache-2.0 OR BSD-3-Clause",
    ecosystem: "PyPI",
    cves: ["CVE-2023-50782"],
    highestSeverity: "High",
  },
  {
    name: "urllib3",
    version: "1.26.18",
    license: "MIT",
    ecosystem: "PyPI",
    cves: ["CVE-2024-37891"],
    highestSeverity: "Medium",
  },
  {
    name: "requests",
    version: "2.31.0",
    license: "Apache-2.0",
    ecosystem: "PyPI",
    cves: [],
    highestSeverity: "Low",
  },
  {
    name: "sqlalchemy",
    version: "2.0.25",
    license: "MIT",
    ecosystem: "PyPI",
    cves: [],
    highestSeverity: "Low",
  },
];

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"];
const SEV_WEIGHT = { Critical: 10, High: 5, Medium: 2, Low: 1 };

function badgeClass(severity) {
  const s = String(severity || "").toLowerCase();
  if (s === "critical") return styles.sevCritical;
  if (s === "high") return styles.sevHigh;
  if (s === "medium") return styles.sevMedium;
  if (s === "low") return styles.sevLow;
  return styles.sevUnknown;
}

function barSegClass(severity) {
  const s = String(severity || "").toLowerCase();
  if (s === "critical") return styles.barCritical;
  if (s === "high") return styles.barHigh;
  if (s === "medium") return styles.barMedium;
  return styles.barLow;
}

function countBySeverity(items, key = "severity") {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const item of items) {
    const raw = item[key] || item.highestSeverity || "";
    const label = SEVERITY_ORDER.find((x) => x.toLowerCase() === String(raw).toLowerCase());
    if (label) counts[label] += 1;
  }
  return counts;
}

function computeRisk(counts) {
  const weighted =
    counts.Critical * SEV_WEIGHT.Critical +
    counts.High * SEV_WEIGHT.High +
    counts.Medium * SEV_WEIGHT.Medium +
    counts.Low * SEV_WEIGHT.Low;
  const score = Math.min(100, weighted * 4);
  let grade = "A";
  let band = "Low risk";
  if (score >= 70) {
    grade = "F";
    band = "Critical risk";
  } else if (score >= 50) {
    grade = "D";
    band = "High risk";
  } else if (score >= 30) {
    grade = "C";
    band = "Elevated risk";
  } else if (score >= 15) {
    grade = "B";
    band = "Moderate risk";
  }
  return { score, grade, band, weighted };
}

function shortHash(hash) {
  if (!hash) return "—";
  return hash.length > 12 ? `${hash.slice(0, 7)}…${hash.slice(-4)}` : hash;
}

function Chevron({ open }) {
  return (
    <svg className={`${styles.chevron} ${open ? styles.chevronOpen : ""}`} viewBox="0 0 20 20" aria-hidden="true">
      <path d="M5 7.5L10 12.5L15 7.5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function SeverityBar({ counts }) {
  const total = SEVERITY_ORDER.reduce((n, s) => n + (counts[s] || 0), 0) || 1;
  return (
    <div className={styles.barBlock}>
      <div className={styles.barTrack} role="img" aria-label="Severity distribution">
        {SEVERITY_ORDER.map((sev) => {
          const n = counts[sev] || 0;
          if (!n) return null;
          const pct = Math.max(4, (n / total) * 100);
          return (
            <div
              key={sev}
              className={`${styles.barSeg} ${barSegClass(sev)}`}
              style={{ flexGrow: n, flexBasis: 0, minWidth: `${pct * 0.2}%` }}
              title={`${sev}: ${n}`}
            />
          );
        })}
      </div>
      <div className={styles.barLegend}>
        {SEVERITY_ORDER.map((sev) => (
          <span key={sev} className={styles.legendItem}>
            <i className={`${styles.legendDot} ${barSegClass(sev)}`} />
            {sev}
            <strong>{counts[sev] || 0}</strong>
          </span>
        ))}
      </div>
    </div>
  );
}

function FindingAccordion({ findings, filter }) {
  const [openId, setOpenId] = useState(null);
  const visible = useMemo(() => {
    if (!filter || filter === "All") return findings;
    return findings.filter((f) => String(f.severity).toLowerCase() === filter.toLowerCase());
  }, [findings, filter]);

  if (!visible.length) {
    return <div className={styles.empty}>No findings match this filter.</div>;
  }

  return (
    <div className={styles.accordion}>
      {visible.map((f) => {
        const open = openId === f.id;
        return (
          <div key={f.id} className={styles.accItem}>
            <button
              type="button"
              className={styles.accTrigger}
              aria-expanded={open}
              onClick={() => setOpenId(open ? null : f.id)}
            >
              <span className={`${styles.badge} ${badgeClass(f.severity)}`}>{f.severity}</span>
              <span className={styles.accMain}>
                <span className={styles.accTitle}>{f.title}</span>
                <span className={`${styles.mono} ${styles.accPath}`}>
                  {f.path}
                  <span className={styles.muted}>:{f.line}</span>
                </span>
              </span>
              <span className={`${styles.mono} ${styles.accId}`}>{f.id}</span>
              <Chevron open={open} />
            </button>
            {open ? (
              <div className={styles.accPanel}>
                <div className={styles.accMeta}>
                  {f.cwe ? (
                    <span className={styles.metaChip}>
                      <span className={styles.metaChipLabel}>CWE</span>
                      <span className={styles.mono}>{f.cwe}</span>
                    </span>
                  ) : null}
                  <span className={styles.metaChip}>
                    <span className={styles.metaChipLabel}>Location</span>
                    <span className={styles.mono}>
                      {f.path}:{f.line}
                    </span>
                  </span>
                </div>
                {f.description ? <p className={styles.accBody}>{f.description}</p> : null}
                {f.snippet ? <pre className={styles.snippet}>{f.snippet}</pre> : null}
                {f.remediation ? (
                  <p className={styles.accRemediation}>
                    <strong>Remediation</strong> — {f.remediation}
                  </p>
                ) : null}
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

/**
 * Enterprise SAST + SBOM report presentation template.
 */
export default function SecurityReportTemplate({
  meta = MOCK_META,
  sastFindings = MOCK_SAST,
  sbomComponents = MOCK_SBOM,
  defaultTab = "sast",
}) {
  const [tab, setTab] = useState(defaultTab);
  const [sevFilter, setSevFilter] = useState("All");

  const sastCounts = useMemo(() => countBySeverity(sastFindings, "severity"), [sastFindings]);
  const sbomCounts = useMemo(
    () => countBySeverity(sbomComponents.filter((c) => c.cves?.length), "highestSeverity"),
    [sbomComponents]
  );
  const combinedCounts = useMemo(
    () => ({
      Critical: sastCounts.Critical + sbomCounts.Critical,
      High: sastCounts.High + sbomCounts.High,
      Medium: sastCounts.Medium + sbomCounts.Medium,
      Low: sastCounts.Low + sbomCounts.Low,
    }),
    [sastCounts, sbomCounts]
  );
  const risk = useMemo(() => computeRisk(combinedCounts), [combinedCounts]);
  const sbomVulnCount = useMemo(
    () => sbomComponents.reduce((n, c) => n + (c.cves?.length || 0), 0),
    [sbomComponents]
  );
  const totalIssues = sastFindings.length + sbomVulnCount;

  const gradeTone =
    risk.grade === "F" || risk.grade === "D"
      ? styles.gradeBad
      : risk.grade === "C"
        ? styles.gradeWarn
        : styles.gradeOk;

  return (
    <div className={styles.srtRoot}>
      <div className={styles.shell}>
        {/* Masthead */}
        <header className={styles.masthead}>
          <div className={styles.brandRow}>
            <div className={styles.logoMark} aria-hidden="true">
              ZS
            </div>
            <div>
              <p className={styles.kicker}>
                {meta.org || "Zero Shield"} · Security Assessment
              </p>
              <h1 className={styles.title}>{meta.projectName}</h1>
              <p className={styles.subtitle}>{meta.scanner || "SAST + SBOM/SCA"}</p>
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
        </header>

        {/* Meta strip */}
        <div className={styles.metaStrip}>
          <div className={styles.metaItem}>
            <div className={styles.metaLabel}>Project</div>
            <div className={styles.metaValue}>{meta.projectName}</div>
          </div>
          <div className={styles.metaItem}>
            <div className={styles.metaLabel}>Scan timestamp</div>
            <div className={styles.metaValue}>{meta.scanTimestamp}</div>
          </div>
          <div className={styles.metaItem}>
            <div className={styles.metaLabel}>Commit</div>
            <div className={`${styles.metaValue} ${styles.mono}`} title={meta.commitHash}>
              {shortHash(meta.commitHash)}
            </div>
          </div>
          <div className={styles.metaItem}>
            <div className={styles.metaLabel}>Branch</div>
            <div className={`${styles.metaValue} ${styles.mono}`}>{meta.branch || "—"}</div>
          </div>
        </div>

        {/* Executive summary: KPIs + risk + chart */}
        <section className={styles.summaryGrid} aria-label="Executive summary">
          <article className={`${styles.kpi} ${styles.kpiRisk}`}>
            <div className={styles.kpiLabel}>Risk score</div>
            <div className={styles.riskRow}>
              <div className={`${styles.grade} ${gradeTone}`} aria-label={`Grade ${risk.grade}`}>
                {risk.grade}
              </div>
              <div>
                <div className={styles.kpiValue}>{risk.score}</div>
                <div className={styles.kpiHint}>{risk.band} · 0–100 scale</div>
              </div>
            </div>
          </article>
          <article className={styles.kpi}>
            <div className={styles.kpiLabel}>Total issues</div>
            <div className={styles.kpiValue}>{totalIssues}</div>
            <div className={styles.kpiHint}>
              {sastFindings.length} SAST · {sbomVulnCount} SBOM CVEs
            </div>
          </article>
          <article className={`${styles.kpi} ${styles.kpiCritical}`}>
            <div className={styles.kpiLabel}>Critical</div>
            <div className={styles.kpiValue}>{combinedCounts.Critical}</div>
            <div className={styles.kpiHint}>Immediate remediation</div>
          </article>
          <article className={`${styles.kpi} ${styles.kpiHigh}`}>
            <div className={styles.kpiLabel}>High</div>
            <div className={styles.kpiValue}>{combinedCounts.High}</div>
            <div className={styles.kpiHint}>Current sprint priority</div>
          </article>
          <article className={styles.kpi}>
            <div className={styles.kpiLabel}>Scan time</div>
            <div className={styles.kpiValueSm}>{meta.scanDuration || "—"}</div>
            <div className={styles.kpiHint}>Completed successfully</div>
          </article>
        </section>

        <section className={styles.chartCard}>
          <div className={styles.chartHead}>
            <h2>Vulnerability breakdown</h2>
            <span className={`${styles.mono} ${styles.muted}`}>{totalIssues} total</span>
          </div>
          <SeverityBar counts={combinedCounts} />
        </section>

        {/* Tabs + filters */}
        <div className={`${styles.toolbar} ${styles.noPrint}`}>
          <div className={styles.tabs} role="tablist" aria-label="Report sections">
            <button
              type="button"
              role="tab"
              className={`${styles.tab} ${tab === "sast" ? styles.tabActive : ""}`}
              aria-selected={tab === "sast"}
              onClick={() => {
                setTab("sast");
                setSevFilter("All");
              }}
            >
              SAST ({sastFindings.length})
            </button>
            <button
              type="button"
              role="tab"
              className={`${styles.tab} ${tab === "sbom" ? styles.tabActive : ""}`}
              aria-selected={tab === "sbom"}
              onClick={() => setTab("sbom")}
            >
              SBOM ({sbomComponents.length})
            </button>
          </div>
          {tab === "sast" ? (
            <div className={styles.filters} role="group" aria-label="Severity filter">
              {["All", ...SEVERITY_ORDER].map((f) => (
                <button
                  key={f}
                  type="button"
                  className={`${styles.filterChip} ${sevFilter === f ? styles.filterChipActive : ""}`}
                  onClick={() => setSevFilter(f)}
                >
                  {f}
                </button>
              ))}
            </div>
          ) : null}
        </div>

        {/* SAST accordion */}
        <section className={`${styles.panel} ${tab !== "sast" ? styles.panelHidden : ""}`}>
          <div className={styles.panelHead}>
            <h2>SAST findings</h2>
            <span className={`${styles.mono} ${styles.muted}`}>{sastFindings.length} issues</span>
          </div>
          {sastFindings.length === 0 ? (
            <div className={styles.empty}>No SAST findings in this scan.</div>
          ) : (
            <FindingAccordion findings={sastFindings} filter={sevFilter} />
          )}
        </section>

        {/* SBOM dense table */}
        <section className={`${styles.panel} ${tab !== "sbom" ? styles.panelHidden : ""}`}>
          <div className={styles.panelHead}>
            <h2>SBOM dependencies</h2>
            <span className={`${styles.mono} ${styles.muted}`}>{sbomComponents.length} components</span>
          </div>
          {sbomComponents.length === 0 ? (
            <div className={styles.empty}>No SBOM components in this scan.</div>
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
                  {sbomComponents.map((c) => (
                    <tr key={`${c.name}@${c.version}`}>
                      <td>
                        <div className={`${styles.mono} ${styles.compName}`}>{c.name}</div>
                        {c.ecosystem ? <div className={styles.compEco}>{c.ecosystem}</div> : null}
                      </td>
                      <td>
                        <span className={styles.mono}>{c.version}</span>
                      </td>
                      <td>
                        <span className={styles.mono}>{c.license || "—"}</span>
                      </td>
                      <td>
                        <span className={`${styles.badge} ${badgeClass(c.highestSeverity || "Low")}`}>
                          {c.highestSeverity || "Low"}
                        </span>
                      </td>
                      <td>
                        {c.cves?.length ? (
                          <div className={styles.pillList}>
                            {c.cves.map((cve) => (
                              <span key={cve} className={styles.cve}>
                                {cve}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className={styles.muted} style={{ fontSize: 12 }}>
                            None
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <p className={styles.footerNote}>Confidential · Zero Shield Enterprise Security Report</p>
      </div>
    </div>
  );
}

export { MOCK_META, MOCK_SAST, MOCK_SBOM, computeRisk, countBySeverity };
