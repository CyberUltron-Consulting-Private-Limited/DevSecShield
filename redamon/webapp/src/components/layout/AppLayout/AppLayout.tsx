'use client'

import { useSearchParams } from 'next/navigation'
import { GlobalHeader } from '../GlobalHeader'
import { Footer } from '../Footer'
import styles from './AppLayout.module.css'

interface AppLayoutProps {
  children: React.ReactNode
}

export function AppLayout({ children }: AppLayoutProps) {
  const searchParams = useSearchParams()
  const isEmbed = searchParams.get('embed') === 'true'

  if (isEmbed) {
    return (
      <div className={styles.layout}>
        <main className={styles.main}>{children}</main>
      </div>
    )
  }

  return (
    <div className={styles.layout}>
      <GlobalHeader />
      <main className={styles.main}>{children}</main>
      <Footer />
    </div>
  )
}
