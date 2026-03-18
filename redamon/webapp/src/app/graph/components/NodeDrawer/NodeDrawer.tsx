'use client'

import { useState, useMemo } from 'react'
import { AlertTriangle, X } from 'lucide-react'
import { Drawer } from '@/components/ui'
import { GraphNode, GraphData, GraphLink } from '../../types'
import { getNodeColor } from '../../utils'
import { getNodeSeverity } from '../../utils/nodeHelpers'
import { formatPropertyValue } from '../../utils/formatters'
import styles from './NodeDrawer.module.css'

function getNodeId(endpoint: string | GraphNode): string {
  return typeof endpoint === 'string' ? endpoint : endpoint.id
}

interface NodeDrawerProps {
  node: GraphNode | null
  isOpen: boolean
  onClose: () => void
  onDeleteNode?: (nodeId: string) => Promise<void>
  onInvestigate?: () => void
  graphData?: GraphData
}

export function NodeDrawer({ node, isOpen, onClose, onDeleteNode, onInvestigate, graphData }: NodeDrawerProps) {
  const [isDeleting, setIsDeleting] = useState(false)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [showConnections, setShowConnections] = useState(false)

  const handleDeleteClick = () => setShowDeleteConfirm(true)
  const handleDeleteConfirm = async () => {
    if (!node || !onDeleteNode) return
    setIsDeleting(true)
    try {
      await onDeleteNode(node.id)
      setShowDeleteConfirm(false)
      onClose()
    } finally {
      setIsDeleting(false)
    }
  }
  const handleDeleteCancel = () => setShowDeleteConfirm(false)

  const connections = useMemo(() => {
    if (!node || !graphData) return { in: [], out: [] }
    const nodeMap = new Map(graphData.nodes.map(n => [n.id, n]))
    const inList: { nodeName: string; nodeType: string; relationType: string }[] = []
    const outList: { nodeName: string; nodeType: string; relationType: string }[] = []
    graphData.links.forEach((link: GraphLink) => {
      const srcId = getNodeId(link.source)
      const tgtId = getNodeId(link.target)
      const srcNode = nodeMap.get(srcId)
      const tgtNode = nodeMap.get(tgtId)
      if (tgtId === node.id) {
        inList.push({
          nodeName: srcNode?.name || srcId,
          nodeType: srcNode?.type || 'Unknown',
          relationType: link.type,
        })
      } else if (srcId === node.id) {
        outList.push({
          nodeName: tgtNode?.name || tgtId,
          nodeType: tgtNode?.type || 'Unknown',
          relationType: link.type,
        })
      }
    })
    return { in: inList, out: outList }
  }, [node, graphData])

  const hiddenKeys = ['project_id', 'user_id']
  const sortedProperties = node
    ? Object.entries(node.properties || {})
        .filter(([key]) => !hiddenKeys.includes(key))
        .sort(([a], [b]) => {
          const bottomKeys = ['created_at', 'updated_at']
          const aIsBottom = bottomKeys.includes(a)
          const bIsBottom = bottomKeys.includes(b)
          if (aIsBottom && !bIsBottom) return 1
          if (!aIsBottom && bIsBottom) return -1
          if (aIsBottom && bIsBottom) return bottomKeys.indexOf(a) - bottomKeys.indexOf(b)
          return 0
        })
    : []

  const typeInitial = node?.type?.charAt(0)?.toUpperCase() || '?'
  const severity = node ? getNodeSeverity(node) : ''
  const showRiskBadge = node && (node.type === 'Vulnerability' || node.type === 'CVE') && severity && severity !== 'unknown'
  const riskLabel = severity ? severity.charAt(0).toUpperCase() + severity.slice(1) : ''

  return (
    <Drawer
      isOpen={isOpen}
      onClose={onClose}
      position="left"
      mode="overlay"
      width="340px"
      title={undefined}
    >
      {node && (
        <>
          <div className={styles.nodeHeader}>
            <div className={styles.headerTop}>
              <div
                className={styles.typeIcon}
                style={{ backgroundColor: getNodeColor(node) }}
              >
                {typeInitial}
              </div>
              <div className={styles.headerMeta}>
                <span className={styles.typeLabel}>{node.type.toUpperCase()}</span>
                {showRiskBadge && (
                  <span
                    className={`${styles.riskBadge} ${
                      severity === 'critical' ? styles.riskCritical
                      : severity === 'high' ? styles.riskHigh
                      : severity === 'medium' ? styles.riskMedium
                      : severity === 'low' ? styles.riskLow
                      : styles.riskLow
                    }`}
                  >
                    {riskLabel.charAt(0).toUpperCase() + riskLabel.slice(1)}
                  </span>
                )}
              </div>
              <button
                type="button"
                className={styles.closeBtn}
                onClick={onClose}
                aria-label="Close"
              >
                <X size={18} />
              </button>
            </div>

            <div className={styles.nameSection}>
              <span className={styles.fieldLabel}>NAME</span>
              <span className={styles.nameValue}>{node.name}</span>
            </div>

            <div className={styles.divider} />

            <div className={styles.actionsSection}>
              <span className={styles.fieldLabel}>ACTIONS</span>
              <div className={styles.actionButtons}>
                {onInvestigate && (
                  <button
                    type="button"
                    className={styles.primaryBtn}
                    onClick={() => { onInvestigate(); onClose(); }}
                  >
                    Investigate Asset
                  </button>
                )}
                {graphData && (connections.in.length > 0 || connections.out.length > 0) && (
                  <button
                    type="button"
                    className={styles.secondaryBtn}
                    onClick={() => setShowConnections(!showConnections)}
                  >
                    View Connections
                  </button>
                )}
              </div>
            </div>

            {showConnections && graphData && (connections.in.length > 0 || connections.out.length > 0) && (
              <div className={styles.connectionsSection}>
                {connections.in.length > 0 && (
                  <div className={styles.connGroup}>
                    <span className={styles.connLabel}>Connections In ({connections.in.length})</span>
                    <ul className={styles.connList}>
                      {connections.in.map((c, i) => (
                        <li key={`in-${i}`}>
                          <span className={styles.connName}>{c.nodeName}</span>
                          <span className={styles.connType}>{c.nodeType}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {connections.out.length > 0 && (
                  <div className={styles.connGroup}>
                    <span className={styles.connLabel}>Connections Out ({connections.out.length})</span>
                    <ul className={styles.connList}>
                      {connections.out.map((c, i) => (
                        <li key={`out-${i}`}>
                          <span className={styles.connName}>{c.nodeName}</span>
                          <span className={styles.connType}>{c.nodeType}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            <div className={styles.divider} />

            <div className={styles.section}>
              <div className={styles.sectionHeader}>
                <h3 className={styles.sectionTitleBasicInfo}>Basic Info</h3>
                {node.type !== 'Domain' && node.type !== 'Subdomain' && onDeleteNode && (
                  <button
                    className={styles.deleteButton}
                    onClick={handleDeleteClick}
                    disabled={isDeleting}
                    title="Delete node"
                  >
                    {isDeleting ? '...' : '\uD83D\uDDD1'}
                  </button>
                )}
              </div>
              <div className={styles.propertyRow}>
                <span className={styles.propertyKey}>Type</span>
                <span className={styles.propertyBadge} style={{ backgroundColor: getNodeColor(node) }}>
                  {node.type}
                </span>
              </div>
              <div className={styles.propertyRow}>
                <span className={styles.propertyKey}>ID</span>
                <span className={styles.propertyValue}>{node.id}</span>
              </div>
            </div>

            <div className={styles.section}>
              <h3 className={styles.sectionTitleProperties}>Properties</h3>
              {sortedProperties.map(([key, value]) => (
                <div key={key} className={styles.propertyRow}>
                  <span className={styles.propertyKey}>{key}</span>
                  <span className={styles.propertyValue}>{formatPropertyValue(value)}</span>
                </div>
              ))}
              {sortedProperties.length === 0 && (
                <p className={styles.emptyProperties}>No additional properties</p>
              )}
            </div>
          </div>

          {showDeleteConfirm && (
            <div className={styles.confirmOverlay} onClick={handleDeleteCancel}>
              <div className={styles.confirmModal} onClick={(e) => e.stopPropagation()}>
                <div className={styles.confirmIcon}>
                  <AlertTriangle size={28} />
                </div>
                <h4 className={styles.confirmTitle}>Delete Node</h4>
                <p className={styles.confirmText}>
                  Deleting <strong>{node.type}: {node.name}</strong> will permanently remove
                  this node and all its relationships from the graph.
                </p>
                <p className={styles.confirmWarning}>
                  This may break the connectivity of the graph and affect
                  the agent&apos;s ability to interpret the attack chain context.
                </p>
                <div className={styles.confirmActions}>
                  <button className={styles.confirmCancelBtn} onClick={handleDeleteCancel}>Cancel</button>
                  <button
                    className={styles.confirmDeleteBtn}
                    onClick={handleDeleteConfirm}
                    disabled={isDeleting}
                  >
                    {isDeleting ? 'Deleting...' : 'Delete'}
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </Drawer>
  )
}
