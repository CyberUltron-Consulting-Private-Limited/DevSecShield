'use client'

import { LayoutDashboard } from 'lucide-react'
import styles from './OverviewPage.module.css'

export function OverviewPage() {
  return (
    <div className={styles.container}>
      <div className={styles.empty}>
        <LayoutDashboard size={48} className={styles.icon} />
        <h2 className={styles.title}>Overview</h2>
        <p className={styles.description}>
          Project summary and key metrics will appear here.
        </p>
      </div>
    </div>
  )
}
