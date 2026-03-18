'use client'

import { useState, useRef, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { Activity, ChevronDown } from 'lucide-react'
import { StealthIcon } from '@/components/icons/StealthIcon'
import { Toggle } from '@/components/ui'
import styles from './GraphToolbar.module.css'

interface GraphToolbarProps {
  is3D: boolean
  showLabels: boolean
  onToggle3D: (value: boolean) => void
  onToggleLabels: (value: boolean) => void
  // Target info
  targetDomain?: string
  subdomainList?: string[]
  // Stealth mode
  stealthMode?: boolean
}

export function GraphToolbar({
  is3D,
  showLabels,
  onToggle3D,
  onToggleLabels,
  targetDomain,
  subdomainList = [],
  stealthMode = false,
}: GraphToolbarProps) {
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
          <ChevronDown size={14} className={styles.dropdownChevron} />
        </button>
      </div>
      {dropdownPortal}
    </div>
  )
}
