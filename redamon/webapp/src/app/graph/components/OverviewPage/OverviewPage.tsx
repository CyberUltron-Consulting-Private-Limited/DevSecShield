'use client'

import { useMemo, useState } from 'react'
import {
  Activity,
  ArrowRight,
  Bot,
  Bug,
  Crosshair,
  Download,
  Github,
  Globe,
  Loader2,
  Network,
  Play,
  Radar,
  RefreshCw,
  ShieldAlert,
  Terminal,
  TerminalSquare,
} from 'lucide-react'
import type { TableRow } from '../../hooks/useTableData'
import styles from './OverviewPage.module.css'

interface ConversationSummary {
  id: string
  title: string
  currentPhase: string
  iterationCount: number
  agentRunning: boolean
  sessionId: string
}

interface OverviewPageProps {
  projectName?: string
  targetDomain?: string
  stealthMode?: boolean
  rows: TableRow[]
  nodeTypeCounts: Record<string, number>
  reconStatus?: string
  gvmStatus?: string
  githubHuntStatus?: string
  hasReconData?: boolean
  hasGvmData?: boolean
  hasGithubHuntData?: boolean
  agentActiveCount?: number
  agentConversations?: ConversationSummary[]
  sessionCount?: number
  attackChainCount?: number
  onOpenGraph: () => void
  onOpenAssets: () => void
  onOpenAssessments: () => void
  onRefresh: () => void
  // Scan controls (Recon, GVM, GitHub)
  onStartRecon?: () => void
  onStartGvm?: () => void
  onStartGithubHunt?: () => void
  onToggleReconLogs?: () => void
  onToggleGvmLogs?: () => void
  onToggleGithubHuntLogs?: () => void
  onDownloadRecon?: () => void
  onDownloadGvm?: () => void
  onDownloadGithubHunt?: () => void
  isReconLogsOpen?: boolean
  isGvmLogsOpen?: boolean
  isGithubHuntLogsOpen?: boolean
}

type RiskLevel = 'critical' | 'high' | 'medium' | 'low'

const CHAIN_NODE_TYPES = new Set(['AttackChain', 'ChainStep', 'ChainDecision', 'ChainFailure', 'ChainFinding'])

function getRiskLevel(row: TableRow): RiskLevel {
  const severity = String(row.node.properties?.severity || '').toLowerCase()
  if (severity === 'critical') return 'critical'
  if (severity === 'high') return 'high'
  if (severity === 'medium') return 'medium'
  if (severity === 'low' || severity === 'info') return 'low'

  const connectedVuln = [...row.connectionsIn, ...row.connectionsOut].some(
    conn => conn.nodeType === 'Vulnerability' || conn.nodeType === 'CVE'
  )
  return connectedVuln ? 'medium' : 'low'
}

function formatStatus(status?: string) {
  if (!status) return 'idle'
  return status.replace('_', ' ')
}

function getStatusTone(status?: string, hasData?: boolean) {
  if (status === 'running' || status === 'starting') return 'running'
  if (status === 'completed' || hasData) return 'ready'
  if (status === 'error') return 'error'
  return 'idle'
}

interface SeriesPoint {
  label: string
  shortLabel: string
  value: number
  tone?: RiskLevel
}

function buildChartGeometry(series: SeriesPoint[], width: number, height: number, padding: number) {
  const baseY = height - padding
  const leftX = padding
  const usableWidth = width - padding * 2
  const usableHeight = height - padding * 2
  const maxValue = Math.max(...series.map(item => item.value), 1)

  const points = series.map((item, index) => {
    const x = series.length === 1
      ? leftX + usableWidth / 2
      : leftX + (usableWidth / Math.max(series.length - 1, 1)) * index
    const y = baseY - (item.value / maxValue) * usableHeight
    return { ...item, x, y }
  })

  const path = points.length > 0
    ? `M ${points.map(point => `${point.x} ${point.y}`).join(' L ')}`
    : ''

  const areaPath = points.length > 0
    ? `${path} L ${points[points.length - 1].x} ${baseY} L ${points[0].x} ${baseY} Z`
    : ''

  return { points, path, areaPath, maxValue, baseY }
}

export function OverviewPage({
  projectName,
  targetDomain,
  stealthMode = false,
  rows,
  nodeTypeCounts,
  reconStatus = 'idle',
  gvmStatus = 'idle',
  githubHuntStatus = 'idle',
  hasReconData = false,
  hasGvmData = false,
  hasGithubHuntData = false,
  agentActiveCount = 0,
  agentConversations = [],
  sessionCount = 0,
  attackChainCount = 0,
  onOpenGraph,
  onOpenAssets,
  onOpenAssessments,
  onStartRecon,
  onStartGvm,
  onStartGithubHunt,
  onToggleReconLogs,
  onToggleGvmLogs,
  onToggleGithubHuntLogs,
  onDownloadRecon,
  onDownloadGvm,
  onDownloadGithubHunt,
  isReconLogsOpen = false,
  isGvmLogsOpen = false,
  isGithubHuntLogsOpen = false,
  onRefresh,
}: OverviewPageProps) {
  const assetRows = useMemo(
    () => rows.filter(row => !CHAIN_NODE_TYPES.has(row.node.type)),
    [rows]
  )

  const riskStats = useMemo(() => {
    return assetRows.reduce(
      (acc, row) => {
        acc[getRiskLevel(row)] += 1
        return acc
      },
      { critical: 0, high: 0, medium: 0, low: 0 }
    )
  }, [assetRows])

  const assetMix = useMemo(() => {
    const keys = ['Domain', 'Subdomain', 'IP', 'Service', 'Technology', 'Vulnerability', 'CVE', 'BaseURL', 'Endpoint']
    return keys
      .map(type => ({ type, count: nodeTypeCounts[type] || 0 }))
      .filter(item => item.count > 0)
      .sort((a, b) => b.count - a.count)
      .slice(0, 6)
  }, [nodeTypeCounts])

  const topAssets = useMemo(() => {
    return assetRows
      .filter(row => row.node.type !== 'Domain')
      .map(row => {
        const risk = getRiskLevel(row)
        const exposure = row.connectionsIn.length + row.connectionsOut.length + row.level2.length
        return { row, risk, exposure }
      })
      .sort((a, b) => {
        const riskWeight = { critical: 4, high: 3, medium: 2, low: 1 }
        const riskDiff = riskWeight[b.risk] - riskWeight[a.risk]
        if (riskDiff !== 0) return riskDiff
        return b.exposure - a.exposure
      })
      .slice(0, 5)
  }, [assetRows])

  const maxExposure = Math.max(...topAssets.map(item => item.exposure), 1)
  const [hoveredExposureIndex, setHoveredExposureIndex] = useState<number | null>(null)
  const [hoveredMixIndex, setHoveredMixIndex] = useState<number | null>(null)

  const exposureSeries = useMemo(() => (
    topAssets
      .slice()
      .sort((a, b) => b.exposure - a.exposure)
      .map(item => ({
        label: item.row.node.name,
        shortLabel: item.row.node.name.length > 14 ? `${item.row.node.name.slice(0, 14)}...` : item.row.node.name,
        value: item.exposure,
        tone: item.risk,
      }))
  ), [topAssets])

  const mixSeries = useMemo(() => (
    assetMix.map(item => ({
      label: item.type,
      shortLabel: item.type,
      value: item.count,
    }))
  ), [assetMix])

  const exposureGeometry = useMemo(
    () => buildChartGeometry(exposureSeries, 640, 240, 24),
    [exposureSeries]
  )

  const mixGeometry = useMemo(
    () => buildChartGeometry(mixSeries, 360, 220, 20),
    [mixSeries]
  )

  const activeExposure = exposureSeries[hoveredExposureIndex ?? 0] || null
  const activeMix = mixSeries[hoveredMixIndex ?? 0] || null

  const isReconRunning = reconStatus === 'running' || reconStatus === 'starting'
  const isGvmRunning = gvmStatus === 'running' || gvmStatus === 'starting'
  const isGithubHuntRunning = githubHuntStatus === 'running' || githubHuntStatus === 'starting'

  const operationCards = [
    {
      id: 'recon',
      label: 'Recon',
      value: nodeTypeCounts.Subdomain || nodeTypeCounts.Domain || 0,
      helper: `${formatStatus(reconStatus)}${hasReconData ? ' · data ready' : ''}`,
      icon: Radar,
      tone: getStatusTone(reconStatus, hasReconData),
      running: isReconRunning,
      status: reconStatus,
      hasData: hasReconData,
      onStart: onStartRecon,
      onToggleLogs: onToggleReconLogs,
      isLogsOpen: isReconLogsOpen,
      onDownload: onDownloadRecon,
    },
    {
      id: 'gvm',
      label: 'GVM',
      value: (nodeTypeCounts.Vulnerability || 0) + (nodeTypeCounts.CVE || 0),
      helper: `${formatStatus(gvmStatus)}${hasGvmData ? ' · results ready' : ''}`,
      icon: ShieldAlert,
      tone: getStatusTone(gvmStatus, hasGvmData),
      running: isGvmRunning,
      status: gvmStatus,
      hasData: hasGvmData,
      onStart: onStartGvm,
      onToggleLogs: onToggleGvmLogs,
      isLogsOpen: isGvmLogsOpen,
      onDownload: onDownloadGvm,
    },
    {
      id: 'github',
      label: 'GitHub',
      value: (nodeTypeCounts.GithubRepository || 0) + (nodeTypeCounts.GithubSecret || 0) + (nodeTypeCounts.GithubSensitiveFile || 0),
      helper: `${formatStatus(githubHuntStatus)}${hasGithubHuntData ? ' · results ready' : ''}`,
      icon: Github,
      tone: getStatusTone(githubHuntStatus, hasGithubHuntData),
      running: isGithubHuntRunning,
      status: githubHuntStatus,
      hasData: hasGithubHuntData,
      onStart: onStartGithubHunt,
      onToggleLogs: onToggleGithubHuntLogs,
      isLogsOpen: isGithubHuntLogsOpen,
      onDownload: onDownloadGithubHunt,
    },
  ]

  const runningConversations = agentConversations.filter(item => item.agentRunning).slice(0, 4)

  return (
    <div className={styles.container}>
      <section className={styles.hero}>
        <div className={styles.heroPrimary}>
          <div className={styles.heroTitleRow}>
            <div className={styles.heroIconWrap}>
              <Crosshair size={20} />
            </div>
            <div>
              <h1 className={styles.title}>{projectName || 'Overview'}</h1>
              <p className={styles.subtitle}>
                {targetDomain || 'No target selected'}
                {stealthMode ? ' · stealth mode enabled' : ' · standard collection mode'}
              </p>
            </div>
          </div>

          <div className={styles.heroMeta}>
            <span className={styles.metaChip}><Globe size={12} /> {assetRows.length} assets tracked</span>
            <span className={styles.metaChip}><Bot size={12} /> {agentConversations.length} conversations</span>
            <span className={styles.metaChip}><TerminalSquare size={12} /> {sessionCount} active sessions</span>
            <span className={styles.metaChip}><Activity size={12} /> {attackChainCount} attack chains</span>
          </div>
        </div>

        <div className={styles.heroStatus}>
          <span className={styles.heroStatusLabel}>Mission Status</span>
          <span className={`${styles.heroStatusValue} ${agentActiveCount > 0 ? styles.statusRunning : styles.statusReady}`}>
            {agentActiveCount > 0 ? 'Active' : 'Monitoring'}
          </span>
          <button type="button" className={styles.refreshBtn} onClick={onRefresh}>
            <RefreshCw size={14} />
            Refresh
          </button>
        </div>
      </section>

      <section className={styles.kpiGrid}>
        <div className={`${styles.kpiCard} ${styles.kpiCritical}`}>
          <div className={styles.kpiHeader}><ShieldAlert size={16} /> High Priority Risk</div>
          <div className={styles.kpiValue}>{riskStats.critical + riskStats.high}</div>
          <div className={styles.kpiHelper}>Critical and high severity exposures</div>
        </div>
        <div className={`${styles.kpiCard} ${styles.kpiAccent}`}>
          <div className={styles.kpiHeader}><Bug size={16} /> Findings</div>
          <div className={styles.kpiValue}>{(nodeTypeCounts.Vulnerability || 0) + (nodeTypeCounts.CVE || 0)}</div>
          <div className={styles.kpiHelper}>Validated and linked vulnerability nodes</div>
        </div>
        <div className={`${styles.kpiCard} ${styles.kpiInfo}`}>
          <div className={styles.kpiHeader}><Network size={16} /> Infrastructure Reach</div>
          <div className={styles.kpiValue}>{(nodeTypeCounts.IP || 0) + (nodeTypeCounts.Service || 0) + (nodeTypeCounts.Port || 0)}</div>
          <div className={styles.kpiHelper}>IPs, services, and ports in scope</div>
        </div>
        <div className={`${styles.kpiCard} ${styles.kpiSuccess}`}>
          <div className={styles.kpiHeader}><Bot size={16} /> Active Automation</div>
          <div className={styles.kpiValue}>{agentActiveCount}</div>
          <div className={styles.kpiHelper}>Agent workflows currently running</div>
        </div>
      </section>

      <section className={styles.mainGrid}>
        <div className={styles.leftColumn}>
          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <div>
                <h2 className={styles.panelTitle}>Exposure Graph</h2>
                <p className={styles.panelSubtitle}>Interactive exposure ranking for the most relevant assets</p>
              </div>
              {activeExposure && (
                <div className={styles.chartMeta}>
                  <span className={styles.chartMetaLabel}>{activeExposure.label}</span>
                  <span className={styles.chartMetaValue}>{activeExposure.value} exposure</span>
                </div>
              )}
            </div>

            {exposureGeometry.points.length === 0 ? (
              <div className={styles.emptyState}>No asset exposure data yet.</div>
            ) : (
              <div className={styles.chartBlock}>
                <svg viewBox="0 0 640 240" className={styles.chartSvg} role="img" aria-label="Asset exposure graph">
                  {[0, 1, 2, 3].map(step => {
                    const y = 24 + ((240 - 48) / 3) * step
                    return <line key={step} x1="24" y1={y} x2="616" y2={y} className={styles.chartGrid} />
                  })}
                  <path d={exposureGeometry.areaPath} className={styles.exposureArea} />
                  <path d={exposureGeometry.path} className={styles.exposureLine} />
                  {exposureGeometry.points.map((point, index) => (
                    <g key={`${point.label}-${index}`}>
                      <circle
                        cx={point.x}
                        cy={point.y}
                        r={hoveredExposureIndex === index ? 6 : 4}
                        className={`${styles.chartPoint} ${styles[`point${(point.tone || 'low').charAt(0).toUpperCase()}${(point.tone || 'low').slice(1)}`]}`}
                        onMouseEnter={() => setHoveredExposureIndex(index)}
                        onFocus={() => setHoveredExposureIndex(index)}
                        tabIndex={0}
                      />
                      <text x={point.x} y="230" textAnchor="middle" className={styles.chartLabel}>
                        {point.shortLabel}
                      </text>
                    </g>
                  ))}
                </svg>

                <div className={styles.riskLegendCompact}>
                  <div className={styles.legendItem}>
                    <span className={`${styles.legendDot} ${styles.dotCritical}`} />
                    <span>Critical</span>
                    <strong>{riskStats.critical}</strong>
                  </div>
                  <div className={styles.legendItem}>
                    <span className={`${styles.legendDot} ${styles.dotHigh}`} />
                    <span>High</span>
                    <strong>{riskStats.high}</strong>
                  </div>
                  <div className={styles.legendItem}>
                    <span className={`${styles.legendDot} ${styles.dotMedium}`} />
                    <span>Medium</span>
                    <strong>{riskStats.medium}</strong>
                  </div>
                  <div className={styles.legendItem}>
                    <span className={`${styles.legendDot} ${styles.dotLow}`} />
                    <span>Low</span>
                    <strong>{riskStats.low}</strong>
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <div>
                <h2 className={styles.panelTitle}>Top Exposed Assets</h2>
                <p className={styles.panelSubtitle}>Most connected or risky assets worth reviewing first</p>
              </div>
            </div>

            <div className={styles.assetList}>
              {topAssets.length === 0 ? (
                <div className={styles.emptyState}>No asset exposure data yet.</div>
              ) : topAssets.map(item => (
                <div key={item.row.node.id} className={styles.assetRow}>
                  <div className={styles.assetMeta}>
                    <span className={styles.assetName}>{item.row.node.name}</span>
                    <span className={styles.assetType}>{item.row.node.type}</span>
                  </div>
                  <div className={styles.assetBarWrap}>
                    <div className={styles.assetBarTrack}>
                      <div
                        className={`${styles.assetBarFill} ${styles[`bar${item.risk.charAt(0).toUpperCase()}${item.risk.slice(1)}`]}`}
                        style={{ width: `${(item.exposure / maxExposure) * 100}%` }}
                      />
                    </div>
                    <span className={styles.assetScore}>{item.exposure}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <div>
                <h2 className={styles.panelTitle}>Operational Coverage</h2>
                <p className={styles.panelSubtitle}>Collection pipelines and result readiness</p>
              </div>
            </div>

            <div className={styles.operationGrid}>
              {operationCards.map(card => {
                const Icon = card.icon
                return (
                  <div key={card.id} className={styles.operationCard}>
                    <div className={styles.operationHeader}>
                      <span className={styles.operationIcon}><Icon size={15} /></span>
                      <span className={styles.operationLabel}>{card.label}</span>
                      <span className={`${styles.operationStatus} ${styles[`tone${card.tone.charAt(0).toUpperCase()}${card.tone.slice(1)}`]}`}>
                        {card.tone}
                      </span>
                    </div>
                    <div className={styles.operationValue}>{card.value}</div>
                    <div className={styles.operationHelper}>{card.helper}</div>
                    <div className={styles.operationActions}>
                      {card.onStart && (
                        <button
                          type="button"
                          className={styles.operationBtn}
                          onClick={card.onStart}
                          disabled={card.running}
                          title={card.running ? 'Scan in progress' : `Start ${card.label}`}
                        >
                          {card.running ? <Loader2 size={12} className={styles.spinner} /> : <Play size={12} />}
                          <span>{card.running ? 'Running' : 'Start'}</span>
                        </button>
                      )}
                      {card.onToggleLogs && (
                        <button
                          type="button"
                          className={`${styles.operationBtn} ${card.isLogsOpen ? styles.operationBtnActive : ''}`}
                          onClick={card.onToggleLogs}
                          title={`View ${card.label} logs`}
                        >
                          <Terminal size={12} />
                          <span>Logs</span>
                        </button>
                      )}
                      {card.onDownload && (
                        <button
                          type="button"
                          className={styles.operationBtn}
                          onClick={card.onDownload}
                          disabled={!card.hasData || card.running}
                          title={card.hasData ? `Download ${card.label} output` : `No ${card.label} data yet`}
                        >
                          <Download size={12} />
                          <span>Download</span>
                        </button>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

        </div>

        <div className={styles.rightColumn}>
          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <div>
                <h2 className={styles.panelTitle}>Surface Mix</h2>
                <p className={styles.panelSubtitle}>Interactive category counts from the current scope</p>
              </div>
              {activeMix && (
                <div className={styles.chartMeta}>
                  <span className={styles.chartMetaLabel}>{activeMix.label}</span>
                  <span className={styles.chartMetaValue}>{activeMix.value} nodes</span>
                </div>
              )}
            </div>

            {mixGeometry.points.length === 0 ? (
              <div className={styles.emptyState}>No composition data available.</div>
            ) : (
              <div className={styles.chartBlockCompact}>
                <svg viewBox="0 0 360 220" className={styles.chartSvgCompact} role="img" aria-label="Surface mix graph">
                  {[0, 1, 2, 3].map(step => {
                    const y = 20 + ((220 - 40) / 3) * step
                    return <line key={step} x1="20" y1={y} x2="340" y2={y} className={styles.chartGrid} />
                  })}
                  <path d={mixGeometry.areaPath} className={styles.mixArea} />
                  <path d={mixGeometry.path} className={styles.mixLine} />
                  {mixGeometry.points.map((point, index) => (
                    <g key={`${point.label}-${index}`}>
                      <circle
                        cx={point.x}
                        cy={point.y}
                        r={hoveredMixIndex === index ? 5 : 3.5}
                        className={styles.chartPointNeutral}
                        onMouseEnter={() => setHoveredMixIndex(index)}
                        onFocus={() => setHoveredMixIndex(index)}
                        tabIndex={0}
                      />
                      <text x={point.x} y="212" textAnchor="middle" className={styles.chartLabelCompact}>
                        {point.shortLabel}
                      </text>
                    </g>
                  ))}
                </svg>
              </div>
            )}
          </div>

          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <div>
                <h2 className={styles.panelTitle}>Live Operations</h2>
                <p className={styles.panelSubtitle}>Current agent workflows and offensive activity</p>
              </div>
            </div>

            <div className={styles.liveList}>
              {runningConversations.length === 0 ? (
                <div className={styles.emptyState}>No active agent conversations right now.</div>
              ) : runningConversations.map(item => (
                <div key={item.id} className={styles.liveItem}>
                  <div className={styles.liveItemHeader}>
                    <span className={styles.liveTitle}>{item.title || 'Untitled conversation'}</span>
                    <span className={styles.liveBadge}>Step {item.iterationCount || 0}</span>
                  </div>
                  <div className={styles.livePhase}>{item.currentPhase.replace('_', ' ')}</div>
                </div>
              ))}
            </div>
          </div>

          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <div>
                <h2 className={styles.panelTitle}>Quick Navigation</h2>
                <p className={styles.panelSubtitle}>Jump into the views analysts use most</p>
              </div>
            </div>

            <div className={styles.quickActions}>
              <button type="button" className={styles.quickAction} onClick={onOpenGraph}>
                <div>
                  <span className={styles.quickTitle}>Attack Surface</span>
                  <span className={styles.quickDesc}>Inspect relationships and infrastructure paths</span>
                </div>
                <ArrowRight size={16} />
              </button>
              <button type="button" className={styles.quickAction} onClick={onOpenAssets}>
                <div>
                  <span className={styles.quickTitle}>Assets</span>
                  <span className={styles.quickDesc}>Review inventory, exposure, and risky nodes</span>
                </div>
                <ArrowRight size={16} />
              </button>
              <button type="button" className={styles.quickAction} onClick={onOpenAssessments}>
                <div>
                  <span className={styles.quickTitle}>Assessments</span>
                  <span className={styles.quickDesc}>Monitor sessions, chains, and operator progress</span>
                </div>
                <ArrowRight size={16} />
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}
