'use client'

import { memo, useMemo } from 'react'
import { NODE_COLORS } from '../../config'
import { formatPropertyValue } from '../../utils/formatters'
import type { TableRow } from '../../hooks/useTableData'
import styles from './ExpandedRowDetail.module.css'

interface ExpandedRowDetailProps {
  row: TableRow
  onViewInGraph: () => void
}

const HIDDEN_KEYS = new Set(['project_id', 'user_id'])

export const ExpandedRowDetail = memo(function ExpandedRowDetail({ row, onViewInGraph }: ExpandedRowDetailProps) {
  const properties = Object.entries(row.node.properties)
    .filter(([key]) => !HIDDEN_KEYS.has(key))
    .sort(([a], [b]) => a.localeCompare(b))

  const lastActivity = String(row.node.properties.updated_at || row.node.properties.created_at || '--')
  const severity = String(row.node.properties.severity || '').toLowerCase()
  const tags = useMemo(() => {
    const values = [row.node.type.toLowerCase()]
    if (severity && severity !== 'unknown') values.push(severity)
    values.push('verified')
    return values
  }, [row.node.type, severity])

  const securityNote = severity === 'critical' || severity === 'high'
    ? 'Critical findings present'
    : severity === 'medium'
      ? 'Medium-priority findings detected'
      : 'No critical findings'

  return (
    <div className={styles.detail}>
      <div className={styles.summaryGrid}>
        <div className={styles.summaryItem}>
          <span className={styles.summaryLabel}>Discovery Source</span>
          <span className={styles.summaryValue}>{row.node.type}</span>
        </div>
        <div className={styles.summaryItem}>
          <span className={styles.summaryLabel}>Associated Nodes</span>
          <span className={styles.summaryValue}>{row.connectionsIn.length + row.connectionsOut.length} connected nodes</span>
        </div>
        <div className={styles.summaryItem}>
          <span className={styles.summaryLabel}>Last Activity</span>
          <span className={styles.summaryValue}>{lastActivity}</span>
        </div>
        <div className={styles.summaryItem}>
          <span className={styles.summaryLabel}>Tags</span>
          <div className={styles.tags}>
            {tags.map(tag => (
              <span key={tag} className={styles.tag}>{tag}</span>
            ))}
          </div>
        </div>
        <div className={styles.summaryItem}>
          <span className={styles.summaryLabel}>Attack Vector</span>
          <button type="button" className={styles.inlineAction} onClick={onViewInGraph}>
            View in Graph
          </button>
        </div>
        <div className={styles.summaryItem}>
          <span className={styles.summaryLabel}>Security Notes</span>
          <span className={styles.summaryValue}>{securityNote}</span>
        </div>
      </div>

      <div className={styles.sections}>
        <div className={styles.section}>
          <h4 className={styles.sectionTitle}>Properties</h4>
          {properties.length === 0 ? (
            <p className={styles.empty}>No properties</p>
          ) : (
            <div className={styles.propsGrid}>
              {properties.map(([key, value]) => (
                <div key={key} className={styles.propRow}>
                  <span className={styles.propKey}>{key}</span>
                  <span className={styles.propValue}>{formatPropertyValue(value)}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className={styles.section}>
          <h4 className={styles.sectionTitle}>
            Connections In
            <span className={styles.connCount}>{row.connectionsIn.length}</span>
          </h4>
          {row.connectionsIn.length === 0 ? (
            <p className={styles.empty}>No incoming connections</p>
          ) : (
            <div className={styles.connList}>
              {row.connectionsIn.map((conn, i) => (
                <div key={`${conn.nodeId}-${conn.relationType}-${i}`} className={styles.connItem}>
                  <span className={styles.connDot} style={{ background: NODE_COLORS[conn.nodeType] || NODE_COLORS.Default }} />
                  <span className={styles.connType}>{conn.nodeType}</span>
                  <span className={styles.connName}>{conn.nodeName}</span>
                  <span className={styles.connRel}>{conn.relationType}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className={styles.section}>
          <h4 className={styles.sectionTitle}>
            Connections Out
            <span className={styles.connCount}>{row.connectionsOut.length}</span>
          </h4>
          {row.connectionsOut.length === 0 ? (
            <p className={styles.empty}>No outgoing connections</p>
          ) : (
            <div className={styles.connList}>
              {row.connectionsOut.map((conn, i) => (
                <div key={`${conn.nodeId}-${conn.relationType}-${i}`} className={styles.connItem}>
                  <span className={styles.connDot} style={{ background: NODE_COLORS[conn.nodeType] || NODE_COLORS.Default }} />
                  <span className={styles.connType}>{conn.nodeType}</span>
                  <span className={styles.connName}>{conn.nodeName}</span>
                  <span className={styles.connRel}>{conn.relationType}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className={styles.section}>
          <h4 className={styles.sectionTitle}>
            Nearby Assets
            <span className={styles.connCount}>{row.level2.length + row.level3.length}</span>
          </h4>
          {row.level2.length === 0 && row.level3.length === 0 ? (
            <p className={styles.empty}>No nearby assets</p>
          ) : (
            <div className={styles.connList}>
              {[...row.level2, ...row.level3].map((conn, i) => (
                <div key={`nearby-${conn.nodeId}-${i}`} className={styles.connItem}>
                  <span className={styles.connDot} style={{ background: NODE_COLORS[conn.nodeType] || NODE_COLORS.Default }} />
                  <span className={styles.connType}>{conn.nodeType}</span>
                  <span className={styles.connName}>{conn.nodeName}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
})
