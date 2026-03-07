'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { MsfSession, MsfJob, NonMsfSession, SessionInteractResult } from '@/lib/websocket-types'

interface UseActiveSessionsOptions {
  enabled?: boolean
  fastPoll?: boolean // 3s when true, 10s when false
}

interface UseActiveSessionsReturn {
  sessions: MsfSession[]
  jobs: MsfJob[]
  nonMsfSessions: NonMsfSession[]
  agentBusy: boolean
  isLoading: boolean
  error: string | null
  totalCount: number
  interactWithSession: (sessionId: number, command: string) => Promise<SessionInteractResult>
  killSession: (sessionId: number) => Promise<void>
  upgradeSession: (sessionId: number) => Promise<void>
  killJob: (jobId: number) => Promise<void>
  refetch: () => Promise<void>
}

const FAST_INTERVAL = 3000
const SLOW_INTERVAL = 10000

export function useActiveSessions({
  enabled = true,
  fastPoll = false,
}: UseActiveSessionsOptions = {}): UseActiveSessionsReturn {
  const [sessions, setSessions] = useState<MsfSession[]>([])
  const [jobs, setJobs] = useState<MsfJob[]>([])
  const [nonMsfSessions, setNonMsfSessions] = useState<NonMsfSession[]>([])
  const [agentBusy, setAgentBusy] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const pollingRef = useRef<NodeJS.Timeout | null>(null)

  const fetchSessions = useCallback(async () => {
    try {
      const resp = await fetch('/api/agent/sessions', { cache: 'no-store' })
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`)
      }
      const data = await resp.json()
      setSessions(data.sessions || [])
      setJobs(data.jobs || [])
      setNonMsfSessions(data.non_msf_sessions || [])
      setAgentBusy(data.agent_busy || false)
      setError(null)
    } catch (err) {
      // Don't clear sessions on transient errors — keep showing last known state
      setError(err instanceof Error ? err.message : 'Failed to fetch sessions')
    }
  }, [])

  const interactWithSession = useCallback(async (sessionId: number, command: string): Promise<SessionInteractResult> => {
    try {
      const resp = await fetch(`/api/agent/sessions/${sessionId}/interact`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command }),
      })
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`)
      }
      return await resp.json()
    } catch (err) {
      return { busy: false, output: `[ERROR] ${err instanceof Error ? err.message : 'Unknown error'}` }
    }
  }, [])

  const killSession = useCallback(async (sessionId: number) => {
    try {
      await fetch(`/api/agent/sessions/${sessionId}/kill`, { method: 'POST' })
      // Immediately remove from local state for snappy UX
      setSessions(prev => prev.filter(s => s.id !== sessionId))
    } catch {
      // Will be corrected on next poll
    }
  }, [])

  const upgradeSession = useCallback(async (sessionId: number) => {
    try {
      await fetch(`/api/agent/sessions/${sessionId}/upgrade`, { method: 'POST' })
      // Refresh to pick up the new meterpreter session
      await fetchSessions()
    } catch {
      // Will be corrected on next poll
    }
  }, [fetchSessions])

  const killJob = useCallback(async (jobId: number) => {
    try {
      await fetch(`/api/agent/jobs/${jobId}/kill`, { method: 'POST' })
      setJobs(prev => prev.filter(j => j.id !== jobId))
    } catch {
      // Will be corrected on next poll
    }
  }, [])

  // Initial fetch
  useEffect(() => {
    if (!enabled) return
    setIsLoading(true)
    fetchSessions().finally(() => setIsLoading(false))
  }, [enabled, fetchSessions])

  // Smart polling
  useEffect(() => {
    if (!enabled) return

    if (pollingRef.current) {
      clearInterval(pollingRef.current)
    }

    const interval = fastPoll ? FAST_INTERVAL : SLOW_INTERVAL
    pollingRef.current = setInterval(fetchSessions, interval)

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = null
      }
    }
  }, [enabled, fastPoll, fetchSessions])

  const totalCount = sessions.length + nonMsfSessions.length

  return {
    sessions,
    jobs,
    nonMsfSessions,
    agentBusy,
    isLoading,
    error,
    totalCount,
    interactWithSession,
    killSession,
    upgradeSession,
    killJob,
    refetch: fetchSessions,
  }
}

export default useActiveSessions
