'use client'

import { memo } from 'react'
import { Waypoints, Table2, Terminal, Search, Download } from 'lucide-react'
import styles from './ViewTabs.module.css'

export type ViewMode = 'graph' | 'table' | 'sessions'

interface ViewTabsProps {
  activeView: ViewMode
  onViewChange: (view: ViewMode) => void
  // Table-only controls
  globalFilter?: string
  onGlobalFilterChange?: (value: string) => void
  onExport?: () => void
  totalRows?: number
  filteredRows?: number
  // Sessions badge
  sessionCount?: number
}

export const ViewTabs = memo(function ViewTabs({
  activeView,
  onViewChange,
  globalFilter,
  onGlobalFilterChange,
  onExport,
  totalRows,
  filteredRows,
  sessionCount,
}: ViewTabsProps) {
  return (
    <div className={styles.tabBar}>
      <div className={styles.tabs} role="tablist" aria-label="View mode">
        <button
          role="tab"
          aria-selected={activeView === 'graph'}
          className={`${styles.tab} ${activeView === 'graph' ? styles.tabActive : ''}`}
          onClick={() => onViewChange('graph')}
        >
          <Waypoints size={14} />
          <span>Graph Map</span>
        </button>
        <button
          role="tab"
          aria-selected={activeView === 'table'}
          className={`${styles.tab} ${activeView === 'table' ? styles.tabActive : ''}`}
          onClick={() => onViewChange('table')}
        >
          <Table2 size={14} />
          <span>Data Table</span>
        </button>
        <button
          role="tab"
          aria-selected={activeView === 'sessions'}
          className={`${styles.tab} ${activeView === 'sessions' ? styles.tabActive : ''}`}
          onClick={() => onViewChange('sessions')}
        >
          <Terminal size={14} />
          <span>Remote Shells</span>
          {sessionCount != null && sessionCount > 0 && (
            <span className={styles.badge}>{sessionCount}</span>
          )}
        </button>
      </div>

      {activeView === 'table' && onGlobalFilterChange && (
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
    </div>
  )
})
