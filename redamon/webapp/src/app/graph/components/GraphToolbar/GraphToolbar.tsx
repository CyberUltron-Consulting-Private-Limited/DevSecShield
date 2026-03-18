'use client'

import { useState, useRef, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { Activity, ChevronDown, Download, Loader2, MessageSquare, Shield, Target, Terminal, Zap } from 'lucide-react'
import { StealthIcon } from '@/components/icons/StealthIcon'
import { Toggle } from '@/components/ui'
import type { ReconStatus, GvmStatus, GithubHuntStatus } from '@/lib/recon-types'
import styles from './GraphToolbar.module.css'

interface GraphToolbarProps {
  projectId: string
  is3D: boolean
  showLabels: boolean
  onToggle3D: (value: boolean) => void
  onToggleLabels: (value: boolean) => void
  onToggleAI?: () => void
  isAIOpen?: boolean
  // Target info
  targetDomain?: string
  subdomainList?: string[]
  // Recon props
  onStartRecon?: () => void
  onDownloadJSON?: () => void
  onToggleLogs?: () => void
  reconStatus?: ReconStatus
  hasReconData?: boolean
  isLogsOpen?: boolean
  // GVM props
  onStartGvm?: () => void
  onDownloadGvmJSON?: () => void
  onToggleGvmLogs?: () => void
  gvmStatus?: GvmStatus
  hasGvmData?: boolean
  isGvmLogsOpen?: boolean
  // GitHub Hunt props
  onStartGithubHunt?: () => void
  onDownloadGithubHuntJSON?: () => void
  onToggleGithubHuntLogs?: () => void
  githubHuntStatus?: GithubHuntStatus
  hasGithubHuntData?: boolean
  isGithubHuntLogsOpen?: boolean
  // Stealth mode
  stealthMode?: boolean
  // Agent status
  agentActiveCount?: number
  agentConversations?: Array<{
    id: string
    title: string
    currentPhase: string
    iterationCount: number
    agentRunning: boolean
    sessionId: string
  }>
}

export function GraphToolbar({
  is3D,
  showLabels,
  onToggle3D,
  onToggleLabels,
  // Target info
  targetDomain,
  subdomainList = [],
  // Recon props
  onDownloadJSON,
  onToggleLogs,
  reconStatus = 'idle',
  hasReconData = false,
  isLogsOpen = false,
  // GVM props
  onDownloadGvmJSON,
  onToggleGvmLogs,
  gvmStatus = 'idle',
  hasGvmData = false,
  isGvmLogsOpen = false,
  // GitHub Hunt props
  onDownloadGithubHuntJSON,
  onToggleGithubHuntLogs,
  githubHuntStatus = 'idle',
  hasGithubHuntData = false,
  isGithubHuntLogsOpen = false,
  // Stealth mode
  stealthMode = false,
  // Agent status
  agentActiveCount = 0,
  agentConversations = [],
}: GraphToolbarProps) {
  const isReconRunning = reconStatus === 'running' || reconStatus === 'starting'
  const isGvmRunning = gvmStatus === 'running' || gvmStatus === 'starting'
  const isGithubHuntRunning = githubHuntStatus === 'running' || githubHuntStatus === 'starting'

  // Agent status derived values
  const runningAgent = agentConversations.find(c => c.agentRunning)
  const totalConversations = agentConversations.length

  const PHASE_STYLES: Record<string, { color: string; bg: string; icon: typeof Shield }> = {
    informational: { color: '#059669', bg: 'rgba(5, 150, 105, 0.1)', icon: Shield },
    exploitation: { color: 'var(--status-warning)', bg: 'rgba(245, 158, 11, 0.1)', icon: Target },
    post_exploitation: { color: 'var(--status-error)', bg: 'rgba(239, 68, 68, 0.1)', icon: Zap },
  }

  const [isOpen, setIsOpen] = useState(false)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const [dropdownRect, setDropdownRect] = useState<{ top: number; left: number; width: number } | null>(null)

  useEffect(() => {
    if (!isOpen || !triggerRef.current) {
      setDropdownRect(null)
      return
    }
    const updateRect = () => {
      if (triggerRef.current) {
        const rect = triggerRef.current.getBoundingClientRect()
        setDropdownRect({ top: rect.bottom + 4, left: rect.left, width: Math.max(rect.width, 320) })
      }
    }
    updateRect()
    window.addEventListener('scroll', updateRect, true)
    window.addEventListener('resize', updateRect)
    return () => {
      window.removeEventListener('scroll', updateRect, true)
      window.removeEventListener('resize', updateRect)
    }
  }, [isOpen])

  const scanCards = [
    {
      key: 'recon',
      label: 'Recon',
      running: isReconRunning,
      status: reconStatus,
      hasData: hasReconData,
      colorClass: styles.reconTone,
      statusClass: isReconRunning ? styles.statusRunning : hasReconData ? styles.statusReady : styles.statusIdle,
      onToggleLogs,
      isLogsOpen,
      onDownload: onDownloadJSON,
    },
    {
      key: 'gvm',
      label: 'GVM',
      running: isGvmRunning,
      status: gvmStatus,
      hasData: hasGvmData,
      colorClass: styles.gvmTone,
      statusClass: isGvmRunning ? styles.statusRunning : hasGvmData ? styles.statusReady : styles.statusIdle,
      onToggleLogs: onToggleGvmLogs,
      isLogsOpen: isGvmLogsOpen,
      onDownload: onDownloadGvmJSON,
    },
    {
      key: 'github',
      label: 'GitHub',
      running: isGithubHuntRunning,
      status: githubHuntStatus,
      hasData: hasGithubHuntData,
      colorClass: styles.githubTone,
      statusClass: isGithubHuntRunning ? styles.statusRunning : hasGithubHuntData ? styles.statusReady : styles.statusIdle,
      onToggleLogs: onToggleGithubHuntLogs,
      isLogsOpen: isGithubHuntLogsOpen,
      onDownload: onDownloadGithubHuntJSON,
    },
  ]

  const dropdownPortal = isOpen && dropdownRect && typeof document !== 'undefined' && createPortal(
    <>
      <div
        className={styles.dropdownBackdrop}
        onClick={() => setIsOpen(false)}
        aria-hidden="true"
      />
      <div
        className={`${styles.dropdownContentPortal} ${styles.workspaceCard}`}
        style={{
          position: 'fixed',
          top: dropdownRect.top,
          left: dropdownRect.left,
          width: dropdownRect.width,
          zIndex: 9999,
        }}
      >
        <div className={styles.dropdownContent}>
            <div className={styles.workspaceMeta}>
              {targetDomain ? (
                <span className={styles.targetDomain}>{targetDomain}</span>
              ) : (
                <span className={styles.targetDomainMuted}>No target selected</span>
              )}
              {subdomainList.length > 0 && (
                <span className={styles.subdomainCount}>
                  {subdomainList.length} subdomain{subdomainList.length === 1 ? '' : 's'}
                </span>
              )}
              {stealthMode && (
                <div className={styles.stealthBadge} title="Stealth Mode is active — passive/low-noise techniques only">
                  <StealthIcon size={12} />
                  <span>Stealth</span>
                </div>
              )}
            </div>

            <div className={styles.toggleRow}>
              <div className={styles.toggleItem}>
                <span className={styles.toggleLabel}>Graph</span>
                <Toggle
                  checked={is3D}
                  onChange={onToggle3D}
                  labelOff="2D"
                  labelOn="3D"
                  aria-label="Toggle 2D/3D view"
                />
              </div>
              <div className={styles.toggleItem}>
                <span className={styles.toggleLabel}>Labels</span>
                <Toggle
                  checked={showLabels}
                  onChange={onToggleLabels}
                  labelOff="Off"
                  labelOn="On"
                  aria-label="Toggle labels"
                />
              </div>
            </div>

            <div className={styles.scanGrid}>
              {scanCards.map((scan) => (
                <div key={scan.key} className={`${styles.scanCardItem} ${scan.colorClass}`}>
                  <div className={styles.scanHeader}>
                    <span className={styles.scanLabel}>{scan.label}</span>
                    <span className={`${styles.scanStatus} ${scan.statusClass}`}>
                      {scan.running ? 'Running' : scan.hasData ? 'Ready' : 'Idle'}
                    </span>
                  </div>
                  <div className={styles.scanActions}>
                    {scan.running && (
                      <button
                        className={`${styles.iconButton} ${scan.isLogsOpen ? styles.iconButtonActive : ''}`}
                        onClick={scan.onToggleLogs}
                        title={`View ${scan.label} logs`}
                      >
                        {scan.status === 'starting' ? <Loader2 size={14} className={styles.spinner} /> : <Terminal size={14} />}
                      </button>
                    )}
                    <button
                      className={styles.iconButton}
                      onClick={scan.onDownload}
                      disabled={!scan.hasData || scan.running}
                      title={scan.hasData ? `Download ${scan.label} output` : `No ${scan.label} data yet`}
                    >
                      <Download size={14} />
                    </button>
                  </div>
                </div>
              ))}
            </div>

            <div className={styles.agentStatus}>
              {agentActiveCount > 0 ? (
                <div className={styles.agentActiveBadge}>
                  <span className={styles.agentDot} />
                  <span>{agentActiveCount} active</span>
                </div>
              ) : (
                <div className={styles.agentIdleBadge}>
                  <MessageSquare size={10} />
                  <span>{totalConversations} chat{totalConversations !== 1 ? 's' : ''}</span>
                </div>
              )}
              {runningAgent && (() => {
                const phase = PHASE_STYLES[runningAgent.currentPhase] || PHASE_STYLES.informational
                const PhaseIcon = phase.icon
                return (
                  <div
                    className={styles.agentPhaseBadge}
                    style={{ color: phase.color, backgroundColor: phase.bg, borderColor: phase.color }}
                  >
                    <PhaseIcon size={10} />
                    <span>{runningAgent.currentPhase.replace('_', ' ')}</span>
                    {runningAgent.iterationCount > 0 && (
                      <span className={styles.agentStep}>Step {runningAgent.iterationCount}</span>
                    )}
                  </div>
                )
              })()}
            </div>
        </div>
      </div>
    </>,
    document.body
  )

  return (
    <div className={styles.toolbar}>
      <div className={styles.workspaceCard}>
        <button
          ref={triggerRef}
          type="button"
          className={`${styles.dropdownHeader} ${isOpen ? styles.dropdownHeaderOpen : ''}`}
          onClick={() => setIsOpen(!isOpen)}
        >
          <Activity size={14} />
          <span>Assessment Workspace</span>
          {targetDomain && (
            <span className={styles.headerTarget}>{targetDomain}</span>
          )}
          <span className={styles.headerMeta}>
            {totalConversations} chat{totalConversations !== 1 ? 's' : ''}
          </span>
          <ChevronDown size={14} className={styles.dropdownChevron} />
        </button>
      </div>
      {dropdownPortal}
    </div>
  )
}
