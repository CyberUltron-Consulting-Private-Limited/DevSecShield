'use client'

import { useState, useMemo } from 'react'
import { ChevronDown, Target } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface TargetSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  mode?: 'create' | 'edit'
}

// Helper to convert stored format (with dots) to display format (without dots)
function toDisplayPrefixes(subdomainList: string[]): string {
  return subdomainList
    .filter(s => s !== '.')  // Exclude root domain marker
    .map(s => s.endsWith('.') ? s.slice(0, -1) : s)  // Remove trailing dot
    .join(', ')
}

// Helper to convert display format to stored format (with trailing dots)
function toStoredPrefixes(displayValue: string, includeRoot: boolean): string[] {
  const prefixes = displayValue
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map(s => s.endsWith('.') ? s : s + '.')  // Add trailing dot if missing

  if (includeRoot) {
    prefixes.push('.')
  }

  return prefixes
}

export function TargetSection({ data, updateField, mode = 'create' }: TargetSectionProps) {
  const isLocked = mode === 'edit'
  const [isOpen, setIsOpen] = useState(true)

  // Check if root domain is included in the list
  const includesRootDomain = useMemo(() => data.subdomainList.includes('.'), [data.subdomainList])

  // Display value without dots
  const displayPrefixes = useMemo(() => toDisplayPrefixes(data.subdomainList), [data.subdomainList])

  const handlePrefixesChange = (value: string) => {
    updateField('subdomainList', toStoredPrefixes(value, includesRootDomain))
  }

  const handleRootDomainToggle = (checked: boolean) => {
    const currentPrefixes = toDisplayPrefixes(data.subdomainList)
    updateField('subdomainList', toStoredPrefixes(currentPrefixes, checked))
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Target size={16} />
          Target Configuration
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Define the primary target for your security assessment. The target domain serves as the starting point for all reconnaissance activities, from subdomain enumeration to vulnerability scanning.
          </p>
          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={`${styles.fieldLabel} ${styles.fieldLabelRequired}`}>
                Project Name
              </label>
              <input
                type="text"
                className="textInput"
                value={data.name}
                onChange={(e) => updateField('name', e.target.value)}
                placeholder="My Security Project"
              />
            </div>
            <div className={styles.fieldGroup}>
              <label className={`${styles.fieldLabel} ${styles.fieldLabelRequired}`}>
                Target Domain
              </label>
              <input
                type="text"
                className="textInput"
                value={data.targetDomain}
                onChange={(e) => updateField('targetDomain', e.target.value)}
                placeholder="example.com"
                disabled={isLocked}
                title={isLocked ? 'Target domain cannot be changed after creation. Create a new project instead.' : undefined}
              />
            </div>
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Description</label>
            <textarea
              className="textarea"
              value={data.description || ''}
              onChange={(e) => updateField('description', e.target.value)}
              placeholder="Project description (optional)"
              rows={2}
            />
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Subdomain Prefixes</label>
            <input
              type="text"
              className="textInput"
              value={displayPrefixes}
              onChange={(e) => handlePrefixesChange(e.target.value)}
              placeholder="www, api, admin (comma-separated)"
              disabled={isLocked}
              title={isLocked ? 'Subdomain list cannot be changed after creation. Create a new project instead.' : undefined}
            />
            <span className={styles.fieldHint}>
              {isLocked
                ? 'Target domain and subdomains are locked after project creation to keep graph data consistent. To change them, create a new project.'
                : 'Leave empty to discover all subdomains. Enter prefixes without dots (e.g., "www, api, gpigs").'}
            </span>
          </div>

          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Include Root Domain</span>
              <p className={styles.toggleDescription}>
                Also scan the root domain (e.g., example.com without subdomain)
              </p>
            </div>
            <Toggle
              checked={includesRootDomain}
              onChange={handleRootDomainToggle}
              disabled={isLocked}
            />
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Domain Verification</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Verify Domain Ownership</span>
                <p className={styles.toggleDescription}>
                  Require DNS TXT record verification before scanning
                </p>
              </div>
              <Toggle
                checked={data.verifyDomainOwnership}
                onChange={(checked) => updateField('verifyDomainOwnership', checked)}
              />
            </div>

            {data.verifyDomainOwnership && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Ownership Token</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.ownershipToken}
                    onChange={(e) => updateField('ownershipToken', e.target.value)}
                  />
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>TXT Record Prefix</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.ownershipTxtPrefix}
                    onChange={(e) => updateField('ownershipTxtPrefix', e.target.value)}
                  />
                </div>
              </div>
            )}
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Stealth Mode</h3>
            <div className={styles.toggleRow} style={{ gap: 'var(--space-4)' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <span className={styles.toggleLabel}>Enable Stealth Mode</span>
                <p className={styles.toggleDescription}>
                  Force the entire pipeline to use only passive and low-noise techniques.
                  Active scanners (Kiterunner, banner grabbing) are disabled. Port scanning
                  switches to passive mode. Nuclei disables DAST and interactsh. The AI agent
                  uses only stealthy methods and will stop if stealth is impossible for a
                  requested action.
                </p>
              </div>
              <Toggle
                checked={data.stealthMode}
                onChange={(checked) => updateField('stealthMode', checked)}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
