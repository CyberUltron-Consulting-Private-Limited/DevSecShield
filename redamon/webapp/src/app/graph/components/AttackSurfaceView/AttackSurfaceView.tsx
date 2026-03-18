'use client'

import { useMemo, useRef } from 'react'
import { RotateCcw, Maximize2, Search, Filter } from 'lucide-react'
import { GraphToolbar } from '../GraphToolbar'
import { GraphCanvas } from '../GraphCanvas'
import { getNodeSeverity } from '../../utils/nodeHelpers'
import { useDimensions } from '../../hooks'
import type { GraphData, GraphNode } from '../../types'
import styles from './AttackSurfaceView.module.css'

// Filter pill labels - map to node types
const FILTER_PRESETS: { id: string; label: string; types: string[] }[] = [
  { id: 'all', label: 'All', types: [] },
  { id: 'subdomain', label: 'Subdomain', types: ['Subdomain'] },
  { id: 'ip', label: 'IP', types: ['IP'] },
  { id: 'vulnerability', label: 'Vulnerability', types: ['Vulnerability', 'CVE'] },
  { id: 'infrastructure', label: 'Infrastructure', types: ['Port', 'Service', 'BaseURL', 'Endpoint', 'Technology', 'Domain'] },
]

interface AttackSurfaceViewProps {
  data: GraphData | undefined
  isLoading: boolean
  error: Error | null
  projectId: string
  is3D: boolean
  showLabels: boolean
  selectedNode: GraphNode | null
  isDark?: boolean
  sessionId?: string
  // GraphToolbar / Assessment Workspace props
  onToggle3D: (value: boolean) => void
  onToggleLabels: (value: boolean) => void
  onToggleAI?: () => void
  isAIOpen?: boolean
  targetDomain?: string
  subdomainList?: string[]
  onStartRecon?: () => void
  onDownloadJSON?: () => void
  onToggleLogs?: () => void
  reconStatus?: string
  hasReconData?: boolean
  isLogsOpen?: boolean
  onStartGvm?: () => void
  onDownloadGvmJSON?: () => void
  onToggleGvmLogs?: () => void
  gvmStatus?: string
  hasGvmData?: boolean
  isGvmLogsOpen?: boolean
  onStartGithubHunt?: () => void
  onDownloadGithubHuntJSON?: () => void
  onToggleGithubHuntLogs?: () => void
  githubHuntStatus?: string
  hasGithubHuntData?: boolean
  isGithubHuntLogsOpen?: boolean
  stealthMode?: boolean
  agentActiveCount?: number
  agentConversations?: Array<{
    id: string
    title: string
    currentPhase: string
    iterationCount: number
    agentRunning: boolean
    sessionId: string
  }>
  // Filter props
  activeNodeTypes: Set<string>
  nodeTypeCounts: Record<string, number>
  onToggleNodeType: (type: string) => void
  onSelectAllTypes: () => void
  onClearAllTypes: () => void
  globalFilter: string
  onGlobalFilterChange: (value: string) => void
  // Graph actions
  onNodeClick: (node: GraphNode) => void
  graphRef?: React.RefObject<{ zoomToFit: (d?: number, p?: number) => void } | null>
}

export function AttackSurfaceView({
  data,
  isLoading,
  error,
  projectId,
  is3D,
  showLabels,
  selectedNode,
  isDark = true,
  sessionId,
  onToggle3D,
  onToggleLabels,
  onToggleAI,
  isAIOpen,
  targetDomain,
  subdomainList = [],
  onStartRecon,
  onDownloadJSON,
  onToggleLogs,
  reconStatus = 'idle',
  hasReconData = false,
  isLogsOpen = false,
  onStartGvm,
  onDownloadGvmJSON,
  onToggleGvmLogs,
  gvmStatus = 'idle',
  hasGvmData = false,
  isGvmLogsOpen = false,
  onStartGithubHunt,
  onDownloadGithubHuntJSON,
  onToggleGithubHuntLogs,
  githubHuntStatus = 'idle',
  hasGithubHuntData = false,
  isGithubHuntLogsOpen = false,
  stealthMode = false,
  agentActiveCount = 0,
  agentConversations = [],
  activeNodeTypes,
  nodeTypeCounts,
  onToggleNodeType,
  onSelectAllTypes,
  onClearAllTypes,
  globalFilter,
  onGlobalFilterChange,
  onNodeClick,
  graphRef,
}: AttackSurfaceViewProps) {
  const graphAreaRef = useRef<HTMLDivElement>(null)
  const dimensions = useDimensions(graphAreaRef)

  // Risk counts from Vulnerability and CVE nodes by severity
  const riskCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, total: 0 }
    if (!data?.nodes) return counts
    data.nodes.forEach((node: GraphNode) => {
      counts.total++
      if (node.type === 'Vulnerability' || node.type === 'CVE') {
        const sev = getNodeSeverity(node)
        if (sev === 'critical') counts.critical++
        else if (sev === 'high') counts.high++
        else if (sev === 'medium') counts.medium++
        else if (sev === 'low' || sev === 'info') counts.low++
      }
    })
    return counts
  }, [data?.nodes])

  const handleFitView = () => {
    graphRef?.current?.zoomToFit?.(800, 50)
  }

  const handleReset = () => {
    graphRef?.current?.zoomToFit?.(800, 50)
  }

  // Check if preset is currently active
  const isPresetActive = (preset: typeof FILTER_PRESETS[0]) => {
    const allTypes = Object.keys(nodeTypeCounts || {})
    if (preset.id === 'all') {
      return allTypes.length === 0 || allTypes.every(t => activeNodeTypes.has(t))
    }
    const presetTypesInData = preset.types.filter(t => allTypes.includes(t))
    if (presetTypesInData.length === 0) return false
    const activeCount = allTypes.filter(t => activeNodeTypes.has(t)).length
    return activeCount === presetTypesInData.length &&
      presetTypesInData.every(t => activeNodeTypes.has(t))
  }

  const handlePresetClick = (preset: typeof FILTER_PRESETS[0]) => {
    if (preset.id === 'all') {
      onSelectAllTypes()
    } else if (preset.types.length > 0) {
      const allTypes = Object.keys(nodeTypeCounts || {})
      const toActivate = preset.types.filter(t => allTypes.includes(t))
      onClearAllTypes()
      if (toActivate.length > 0) {
        toActivate.forEach(t => onToggleNodeType(t))
      } else {
        onSelectAllTypes()
      }
    }
  }

  return (
    <div className={styles.wrapper}>
      {/* Header */}
      <header className={styles.header}>
        <div className={styles.headerLeft}>
          <h1 className={styles.title}>Attack Surface Map</h1>
          <p className={styles.subtitle}>Interactive network topology and asset relationships</p>
        </div>
        <div className={styles.headerActions}>
          <button
            type="button"
            className={styles.headerBtn}
            onClick={handleReset}
            title="Reset view"
          >
            <RotateCcw size={14} />
            Reset
          </button>
          <button
            type="button"
            className={styles.headerBtn}
            onClick={handleFitView}
            title="Fit view"
          >
            <Maximize2 size={14} />
            Fit View
          </button>
        </div>
      </header>

      {/* Risk cards */}
      <div className={styles.riskCards}>
        <div className={styles.riskCard}>
          <span className={styles.riskLabel}>TOTAL NODES</span>
          <span className={styles.riskValue}>{riskCounts.total}</span>
        </div>
        <div className={`${styles.riskCard} ${styles.riskCritical}`}>
          <span className={styles.riskLabel}>CRITICAL</span>
          <span className={styles.riskValue}>{riskCounts.critical}</span>
        </div>
        <div className={`${styles.riskCard} ${styles.riskHigh}`}>
          <span className={styles.riskLabel}>HIGH RISK</span>
          <span className={styles.riskValue}>{riskCounts.high}</span>
        </div>
        <div className={`${styles.riskCard} ${styles.riskMedium}`}>
          <span className={styles.riskLabel}>MEDIUM RISK</span>
          <span className={styles.riskValue}>{riskCounts.medium}</span>
        </div>
        <div className={`${styles.riskCard} ${styles.riskLow}`}>
          <span className={styles.riskLabel}>LOW RISK</span>
          <span className={styles.riskValue}>{riskCounts.low}</span>
        </div>
      </div>

      {/* Search & filter bar + Assessment Workspace */}
      <div className={styles.toolbar}>
        <div className={styles.searchFilter}>
          <div className={styles.searchWrapper}>
            <Search size={14} className={styles.searchIcon} />
            <input
              type="text"
              className={styles.searchInput}
              placeholder="Search nodes..."
              value={globalFilter}
              onChange={e => onGlobalFilterChange(e.target.value)}
              aria-label="Search nodes"
            />
          </div>
          <div className={styles.filterPills}>
            <Filter size={12} className={styles.filterIcon} />
            {FILTER_PRESETS.map(preset => (
              <button
                key={preset.id}
                type="button"
                className={`${styles.filterPill} ${isPresetActive(preset) ? styles.filterPillActive : ''}`}
                onClick={() => handlePresetClick(preset)}
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>
        <div className={styles.viewControls}>
          <GraphToolbar
            projectId={projectId}
            is3D={is3D}
            showLabels={showLabels}
            onToggle3D={onToggle3D}
            onToggleLabels={onToggleLabels}
            onToggleAI={onToggleAI}
            isAIOpen={isAIOpen}
            targetDomain={targetDomain}
            subdomainList={subdomainList}
            onStartRecon={onStartRecon}
            onDownloadJSON={onDownloadJSON}
            onToggleLogs={onToggleLogs}
            reconStatus={reconStatus as any}
            hasReconData={hasReconData}
            isLogsOpen={isLogsOpen}
            onStartGvm={onStartGvm}
            onDownloadGvmJSON={onDownloadGvmJSON}
            onToggleGvmLogs={onToggleGvmLogs}
            gvmStatus={gvmStatus as any}
            hasGvmData={hasGvmData}
            isGvmLogsOpen={isGvmLogsOpen}
            onStartGithubHunt={onStartGithubHunt}
            onDownloadGithubHuntJSON={onDownloadGithubHuntJSON}
            onToggleGithubHuntLogs={onToggleGithubHuntLogs}
            githubHuntStatus={githubHuntStatus as any}
            hasGithubHuntData={hasGithubHuntData}
            isGithubHuntLogsOpen={isGithubHuntLogsOpen}
            stealthMode={stealthMode}
            agentActiveCount={agentActiveCount}
            agentConversations={agentConversations}
          />
        </div>
      </div>

      {/* Graph canvas */}
      <div ref={graphAreaRef} className={styles.graphArea}>
        <GraphCanvas
          ref={graphRef}
          data={data}
          isLoading={isLoading}
          error={error}
          projectId={projectId}
          is3D={is3D}
          width={Math.max(dimensions.width, 400)}
          height={Math.max(dimensions.height, 300)}
          showLabels={showLabels}
          selectedNode={selectedNode}
          onNodeClick={onNodeClick}
          isDark={isDark}
          activeChainId={sessionId}
        />
      </div>
    </div>
  )
}
