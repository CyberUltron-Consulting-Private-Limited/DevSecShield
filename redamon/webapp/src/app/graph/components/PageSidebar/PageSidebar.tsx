'use client'

import { memo, useState, useRef, useEffect } from 'react'
import { LayoutDashboard, Crosshair, Database, Terminal, Search, Download, TerminalSquare, ChevronDown, PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import styles from './PageSidebar.module.css'

export type PageView = 'overview' | 'graph' | 'table' | 'sessions'

export type ConsoleType = 'recon' | 'gvm' | 'githubHunt'

interface PageSidebarProps {
  activeView: PageView
  onViewChange: (view: PageView) => void
  // Table-only controls (shown when Assets is active)
  globalFilter?: string
  onGlobalFilterChange?: (value: string) => void
  onExport?: () => void
  totalRows?: number
  filteredRows?: number
  // Sessions badge
  sessionCount?: number
  // Console - open scan logs anytime
  onOpenConsole?: (type: ConsoleType) => void
}

const MENU_ITEMS: { id: PageView; label: string; icon: typeof LayoutDashboard }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'graph', label: 'Attack Surface', icon: Crosshair },
  { id: 'table', label: 'Assets', icon: Database },
  { id: 'sessions', label: 'Assessments', icon: Terminal },
]

const CONSOLE_OPTIONS: { id: ConsoleType; label: string }[] = [
  { id: 'recon', label: 'Recon Logs' },
  { id: 'gvm', label: 'GVM Logs' },
  { id: 'githubHunt', label: 'GitHub Hunt Logs' },
]

export const PageSidebar = memo(function PageSidebar({
  activeView,
  onViewChange,
  globalFilter,
  onGlobalFilterChange,
  onExport,
  totalRows,
  filteredRows,
  sessionCount,
  onOpenConsole,
}: PageSidebarProps) {
  const [consoleOpen, setConsoleOpen] = useState(false)
  const [isCollapsed, setIsCollapsed] = useState(false)
  const consoleRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!consoleOpen) return
    const handleClickOutside = (e: MouseEvent) => {
      if (consoleRef.current && !consoleRef.current.contains(e.target as Node)) {
        setConsoleOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [consoleOpen])

  return (
    <aside className={`${styles.sidebar} ${isCollapsed ? styles.sidebarCollapsed : ''}`}>
      <div className={styles.sidebarHeader}>
        {!isCollapsed && <span className={styles.sidebarTitle}>Navigation</span>}
        <button
          type="button"
          className={styles.collapseBtn}
          onClick={() => {
            setIsCollapsed(prev => !prev)
            setConsoleOpen(false)
          }}
          aria-label={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {isCollapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
        </button>
      </div>

      <nav className={styles.nav} aria-label="Page navigation">
        {MENU_ITEMS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            role="tab"
            aria-selected={activeView === id}
            className={`${styles.navItem} ${activeView === id ? styles.navItemActive : ''}`}
            onClick={() => onViewChange(id)}
            title={isCollapsed ? label : undefined}
          >
            <Icon size={18} className={styles.navIcon} />
            {!isCollapsed && <span className={styles.navLabel}>{label}</span>}
            {id === 'sessions' && !isCollapsed && sessionCount != null && sessionCount > 0 && (
              <span className={styles.badge}>{sessionCount}</span>
            )}
          </button>
        ))}
      </nav>

      {onOpenConsole && (
        <div className={styles.consoleWrap} ref={consoleRef}>
          <button
            type="button"
            className={styles.consoleBtn}
            onClick={() => setConsoleOpen(prev => !prev)}
            aria-expanded={consoleOpen}
            aria-haspopup="true"
            title={isCollapsed ? 'Console' : undefined}
          >
            <TerminalSquare size={18} className={styles.navIcon} />
            {!isCollapsed && <span className={styles.navLabel}>Console</span>}
            {!isCollapsed && <ChevronDown size={14} className={styles.consoleChevron} />}
          </button>
          {consoleOpen && (
            <div className={styles.consoleDropdown}>
              {CONSOLE_OPTIONS.map(({ id, label }) => (
                <button
                  key={id}
                  type="button"
                  className={styles.consoleOption}
                  onClick={() => {
                    onOpenConsole(id)
                    setConsoleOpen(false)
                  }}
                >
                  {label}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {!isCollapsed && activeView === 'table' && onGlobalFilterChange && (
        <div className={styles.tableControls}>
          <div className={styles.searchWrapper}>
            <Search size={12} className={styles.searchIcon} />
            <input
              type="text"
              className={styles.searchInput}
              placeholder="Search..."
              value={globalFilter || ''}
              onChange={e => onGlobalFilterChange(e.target.value)}
              aria-label="Search nodes"
            />
          </div>
          <span className={styles.rowCount}>
            {filteredRows === totalRows
              ? `${totalRows}`
              : `${filteredRows}/${totalRows}`}
          </span>
          <button className={styles.exportBtn} onClick={onExport} aria-label="Export to Excel">
            <Download size={12} />
            <span>XLSX</span>
          </button>
        </div>
      )}
    </aside>
  )
})
