import { NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

// GET /api/models - Fetch available AI models from all configured providers
export async function GET() {
  try {
    const res = await fetch(`${AGENT_API_URL}/models`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    })

    if (!res.ok) {
      console.error('Failed to fetch models from agent API:', await res.text())
      return NextResponse.json(
        { error: 'Failed to fetch models from agent API' },
        { status: 503 }
      )
    }

    const data = await res.json()
    return NextResponse.json(data)
  } catch (error) {
    console.error('Failed to connect to agent API for models:', error)
    return NextResponse.json(
      { error: 'Failed to connect to agent API' },
      { status: 503 }
    )
  }
}
