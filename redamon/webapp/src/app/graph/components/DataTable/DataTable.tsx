'use client'

import { useState, useMemo, memo, Fragment } from 'react'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getPaginationRowModel,
  getExpandedRowModel,
  flexRender,
  createColumnHelper,
  type SortingState,
  type ExpandedState,
} from '@tanstack/react-table'
import {
  Search,
  RefreshCw,
  Download,
  Filter,
  ChevronDown,
  ChevronRight,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  ChevronRight as ChevronRightPage,
  Loader2,
  AlertCircle,
  Database,
} from 'lucide-react'
import type { GraphData, GraphNode } from '../../types'
import { NODE_COLORS } from '../../config'
import type { TableRow } from '../../hooks/useTableData'
import { ExpandedRowDetail } from './ExpandedRowDetail'
import styles from './DataTable.module.css'

interface DataTableProps {
  data: GraphData | undefined
  isLoading: boolean
  error: Error | null
  rows: TableRow[]
  globalFilter: string
  onGlobalFilterChange: (value: string) => void
  nodeTypeCounts: Record<string, number>
  activeNodeTypes: Set<string>
  onToggleNodeType: (type: string) => void
  onSelectAllTypes: () => void
  onExport: () => void
  onRefresh: () => void
  onViewInGraph: (node: GraphNode) => void
}

const columnHelper = createColumnHelper<TableRow>()
const HIDDEN_KEYS = new Set(['project_id', 'user_id', 'created_at', 'updated_at'])
const PRIORITY_TYPES = ['Subdomain', 'Domain', 'IP', 'Port', 'Vulnerability', 'Service']

type RiskLevel = 'critical' | 'high' | 'medium' | 'low'

function getRowRiskLevel(row: TableRow): RiskLevel {
  const severity = String(row.node.properties?.severity || '').toLowerCase()
  if (severity === 'critical') return 'critical'
  if (severity === 'high') return 'high'
  if (severity === 'medium') return 'medium'
  if (severity === 'low' || severity === 'info') return 'low'

  const hasDirectVuln = [...row.connectionsIn, ...row.connectionsOut].some(
    conn => conn.nodeType === 'Vulnerability' || conn.nodeType === 'CVE'
  )
  if (hasDirectVuln) return 'medium'
  return 'low'
}

function getRiskToneClass(risk: RiskLevel) {
  if (risk === 'critical') return styles.riskCritical
  if (risk === 'high') return styles.riskHigh
  if (risk === 'medium') return styles.riskMedium
  return styles.riskLow
}

function getConnectionToneClass(count: number, kind: 'in' | 'out' | 'l1' | 'l2') {
  if (count <= 0) return styles.metricLow
  if (kind === 'out' && count >= 10) return styles.metricCritical
  if (count >= 7) return styles.metricHigh
  if (count >= 4) return styles.metricMedium
  return styles.metricLow
}

function getNodeDetails(row: TableRow) {
  const entry = Object.entries(row.node.properties || {}).find(([key, value]) => {
    if (HIDDEN_KEYS.has(key)) return false
    if (key === 'severity') return false
    return typeof value === 'string' || typeof value === 'number'
  })

  if (!entry) return '---'
  const [, value] = entry
  const text = String(value)
  return text.length > 28 ? `${text.slice(0, 28)}...` : text
}

export const DataTable = memo(function DataTable({
  data,
  isLoading,
  error,
  rows,
  globalFilter,
  onGlobalFilterChange,
  nodeTypeCounts,
  activeNodeTypes,
  onToggleNodeType,
  onSelectAllTypes,
  onExport,
  onRefresh,
  onViewInGraph,
}: DataTableProps) {
  const [sorting, setSorting] = useState<SortingState>([])
  const [expanded, setExpanded] = useState<ExpandedState>({})

  const searchableRows = useMemo(() => {
    const search = globalFilter.trim().toLowerCase()
    if (!search) return rows
    return rows.filter(row =>
      row.node.name?.toLowerCase().includes(search) ||
      row.node.type?.toLowerCase().includes(search)
    )
  }, [rows, globalFilter])

  const visibleTypes = useMemo(() => {
    const remaining = Object.keys(nodeTypeCounts)
      .filter(type => !PRIORITY_TYPES.includes(type))
      .sort()
    return [...PRIORITY_TYPES.filter(type => nodeTypeCounts[type]), ...remaining].slice(0, 8)
  }, [nodeTypeCounts])

  const riskStats = useMemo(() => {
    return searchableRows.reduce(
      (acc, row) => {
        const risk = getRowRiskLevel(row)
        acc[risk] += 1
        return acc
      },
      { critical: 0, high: 0, medium: 0, low: 0 }
    )
  }, [searchableRows])

  const columns = useMemo(() => [
    columnHelper.display({
      id: 'expand',
      header: '',
      size: 40,
      cell: ({ row }) => (
        <button
          className={styles.expandBtn}
          onClick={row.getToggleExpandedHandler()}
          aria-expanded={row.getIsExpanded()}
          aria-label={row.getIsExpanded() ? 'Collapse row' : 'Expand row'}
        >
          {row.getIsExpanded() ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </button>
      ),
    }),
    columnHelper.accessor(row => row.node.type, {
      id: 'type',
      header: 'Type',
      size: 120,
      cell: info => {
        const type = info.getValue()
        const color = NODE_COLORS[type] || NODE_COLORS.Default
        return (
          <span className={styles.typeBadge} style={{ background: color }}>
            {type}
          </span>
        )
      },
    }),
    columnHelper.accessor(row => row.node.name, {
      id: 'name',
      header: 'Name',
      size: 230,
      cell: info => (
        <span className={styles.nameCell} title={info.getValue()}>
          {info.getValue()}
        </span>
      ),
    }),
    columnHelper.display({
      id: 'details',
      header: 'Details',
      size: 180,
      cell: ({ row }) => (
        <span className={styles.detailsCell}>{getNodeDetails(row.original)}</span>
      ),
    }),
    columnHelper.accessor(row => row.connectionsIn.length, {
      id: 'connectionsIn',
      header: 'In',
      size: 72,
      cell: info => {
        const count = info.getValue()
        return (
          <span className={`${styles.metricBadge} ${getConnectionToneClass(count, 'in')}`}>
            {count}
          </span>
        )
      },
    }),
    columnHelper.accessor(row => row.connectionsOut.length, {
      id: 'connectionsOut',
      header: 'Out',
      size: 72,
      cell: info => {
        const count = info.getValue()
        return (
          <span className={`${styles.metricBadge} ${getConnectionToneClass(count, 'out')}`}>
            {count}
          </span>
        )
      },
    }),
    columnHelper.display({
      id: 'level1',
      header: 'L1',
      size: 72,
      cell: ({ row }) => {
        const count = row.original.connectionsIn.length + row.original.connectionsOut.length
        return (
          <span className={`${styles.metricBadge} ${getConnectionToneClass(count, 'l1')}`}>
            {count}
          </span>
        )
      },
    }),
    columnHelper.accessor(row => row.level2.length, {
      id: 'level2',
      header: 'L2',
      size: 72,
      cell: info => {
        const count = info.getValue()
        return (
          <span className={`${styles.metricBadge} ${getConnectionToneClass(count, 'l2')}`}>
            {count}
          </span>
        )
      },
    }),
    columnHelper.display({
      id: 'status',
      header: 'Status',
      size: 110,
      cell: () => <span className={styles.statusBadge}>Active</span>,
    }),
    columnHelper.display({
      id: 'risk',
      header: 'Risk Level',
      size: 120,
      cell: ({ row }) => {
        const risk = getRowRiskLevel(row.original)
        return (
          <span className={`${styles.riskBadge} ${getRiskToneClass(risk)}`}>
            {risk}
          </span>
        )
      },
    }),
    columnHelper.display({
      id: 'actions',
      header: 'Actions',
      size: 130,
      cell: ({ row }) => (
        <button
          type="button"
          className={styles.actionBtn}
          onClick={() => onViewInGraph(row.original.node)}
        >
          Investigate
        </button>
      ),
    }),
  ], [onViewInGraph])

  const table = useReactTable({
    data: searchableRows,
    columns,
    state: { sorting, expanded },
    onSortingChange: setSorting,
    onExpandedChange: setExpanded,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getExpandedRowModel: getExpandedRowModel(),
    initialState: {
      pagination: { pageSize: 20 },
    },
    getRowCanExpand: () => true,
  })

  const pageCount = table.getPageCount() || 1
  const pageIndex = table.getState().pagination.pageIndex
  const pageNumbers = Array.from({ length: Math.min(pageCount, 3) }, (_, i) => {
    const start = Math.max(0, Math.min(pageIndex - 1, pageCount - 3))
    return start + i
  })

  if (isLoading) {
    return (
      <div className={styles.stateContainer}>
        <Loader2 size={32} className={styles.spinner} />
        <p className={styles.stateText}>Loading graph data...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className={styles.stateContainer}>
        <AlertCircle size={32} className={styles.errorIcon} />
        <p className={styles.stateText}>Failed to load graph data</p>
        <p className={styles.stateSubtext}>{error.message}</p>
      </div>
    )
  }

  if (!data || data.nodes.length === 0) {
    return (
      <div className={styles.stateContainer}>
        <Database size={32} className={styles.emptyIcon} />
        <p className={styles.stateText}>No data yet</p>
        <p className={styles.stateSubtext}>Run a reconnaissance scan to populate the graph.</p>
      </div>
    )
  }

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <div>
          <h1 className={styles.title}>Asset Intelligence</h1>
          <p className={styles.subtitle}>{searchableRows.length} of {rows.length} assets discovered</p>
        </div>
        <div className={styles.headerActions}>
          <button type="button" className={styles.headerBtn} onClick={onRefresh}>
            <RefreshCw size={14} />
            Refresh
          </button>
          <button type="button" className={styles.headerBtn} onClick={onExport}>
            <Download size={14} />
            Export
          </button>
        </div>
      </header>

      <div className={styles.riskCards}>
        <div className={`${styles.riskCard} ${styles.cardCritical}`}>
          <span className={styles.cardLabel}>Critical Risk</span>
          <span className={styles.cardValue}>{riskStats.critical}</span>
        </div>
        <div className={`${styles.riskCard} ${styles.cardHigh}`}>
          <span className={styles.cardLabel}>High Risk</span>
          <span className={styles.cardValue}>{riskStats.high}</span>
        </div>
        <div className={`${styles.riskCard} ${styles.cardMedium}`}>
          <span className={styles.cardLabel}>Medium Risk</span>
          <span className={styles.cardValue}>{riskStats.medium}</span>
        </div>
        <div className={`${styles.riskCard} ${styles.cardLow}`}>
          <span className={styles.cardLabel}>Low Risk</span>
          <span className={styles.cardValue}>{riskStats.low}</span>
        </div>
      </div>

      <div className={styles.filterBar}>
        <div className={styles.searchWrapper}>
          <Search size={14} className={styles.searchIcon} />
          <input
            type="text"
            className={styles.searchInput}
            placeholder="Search assets..."
            value={globalFilter}
            onChange={e => onGlobalFilterChange(e.target.value)}
            aria-label="Search assets"
          />
        </div>
        <div className={styles.filterPills}>
          <Filter size={12} className={styles.filterIcon} />
          <button
            type="button"
            className={`${styles.filterPill} ${activeNodeTypes.size === Object.keys(nodeTypeCounts).length ? styles.filterPillActive : ''}`}
            onClick={onSelectAllTypes}
          >
            All
          </button>
          {visibleTypes.map(type => (
            <button
              key={type}
              type="button"
              className={`${styles.filterPill} ${activeNodeTypes.has(type) ? styles.filterPillActive : ''}`}
              onClick={() => onToggleNodeType(type)}
            >
              {type}
            </button>
          ))}
        </div>
      </div>

      <div className={styles.tableWrapper}>
        <table className={styles.table}>
          <thead>
            {table.getHeaderGroups().map(headerGroup => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map(header => (
                  <th
                    key={header.id}
                    className={styles.th}
                    style={{ width: header.getSize() }}
                    onClick={header.column.getCanSort() ? header.column.getToggleSortingHandler() : undefined}
                    aria-sort={
                      header.column.getIsSorted() === 'asc'
                        ? 'ascending'
                        : header.column.getIsSorted() === 'desc'
                          ? 'descending'
                          : 'none'
                    }
                  >
                    <div className={styles.thContent}>
                      {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                      {header.column.getCanSort() && (
                        <span className={styles.sortIcon}>
                          {header.column.getIsSorted() === 'asc'
                            ? <ArrowUp size={12} />
                            : header.column.getIsSorted() === 'desc'
                              ? <ArrowDown size={12} />
                              : <ArrowUpDown size={12} />}
                        </span>
                      )}
                    </div>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map(row => (
              <Fragment key={row.id}>
                <tr className={`${styles.tr} ${row.getIsExpanded() ? styles.trExpanded : ''}`}>
                  {row.getVisibleCells().map(cell => (
                    <td key={cell.id} className={styles.td}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
                {row.getIsExpanded() && (
                  <tr className={styles.trExpandedDetail}>
                    <td colSpan={columns.length} className={styles.tdExpanded}>
                      <ExpandedRowDetail
                        row={row.original}
                        onViewInGraph={() => onViewInGraph(row.original.node)}
                      />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>

      <div className={styles.pagination}>
        <div className={styles.paginationInfo}>Showing {searchableRows.length} of {rows.length} assets</div>
        <div className={styles.paginationControls}>
          <button
            className={styles.pageBtn}
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
          >
            Previous
          </button>
          {pageNumbers.map(page => (
            <button
              key={page}
              className={`${styles.pageNumberBtn} ${page === pageIndex ? styles.pageNumberBtnActive : ''}`}
              onClick={() => table.setPageIndex(page)}
            >
              {page + 1}
            </button>
          ))}
          <button
            className={styles.pageBtn}
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
          >
            Next
          </button>
          <button
            className={styles.pageIconBtn}
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
            aria-label="Next page"
          >
            <ChevronRightPage size={14} />
          </button>
        </div>
      </div>
    </div>
  )
})
