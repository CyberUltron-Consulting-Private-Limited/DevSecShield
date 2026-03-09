'use client'

import styles from './Footer.module.css'

export function Footer() {
  const currentYear = new Date().getFullYear()

  return (
    <footer className={styles.footer}>
      <div className={styles.content}>
        <span className={styles.copyright}>
          © {currentYear} DevSecShield. All rights reserved.
        </span>
        <span className={styles.version}>Red Team</span>
      </div>
    </footer>
  )
}
