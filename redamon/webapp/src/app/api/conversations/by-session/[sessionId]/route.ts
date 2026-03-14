import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

// GET /api/conversations/by-session/[sessionId] - Lookup by session
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ sessionId: string }> }
) {
  try {
    const { sessionId } = await params

    const conversation = await prisma.conversation.findUnique({
      where: { sessionId },
      include: {
        messages: {
          orderBy: { sequenceNum: 'asc' },
        },
      },
    })

    if (!conversation) {
      return NextResponse.json(
        { error: 'Conversation not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(conversation)
  } catch (error) {
    console.error('Failed to fetch conversation by session:', error)
    return NextResponse.json(
      { error: 'Failed to fetch conversation' },
      { status: 500 }
    )
  }
}

// PATCH /api/conversations/by-session/[sessionId] - Update by session
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ sessionId: string }> }
) {
  try {
    const { sessionId } = await params
    const body = await request.json()

    const allowedFields = ['title', 'status', 'agentRunning', 'currentPhase', 'iterationCount']
    const data: Record<string, unknown> = {}
    for (const field of allowedFields) {
      if (body[field] !== undefined) {
        data[field] = body[field]
      }
    }

    const conversation = await prisma.conversation.update({
      where: { sessionId },
      data,
    })

    return NextResponse.json(conversation)
  } catch (error: any) {
    // P2025 = "Record to update not found" — happens when the agent sends
    // a metadata update (e.g. agentRunning) before the first message
    // auto-creates the conversation. This is non-critical.
    if (error?.code === 'P2025') {
      return NextResponse.json({ ignored: true, reason: 'conversation not yet created' })
    }
    console.error('Failed to update conversation by session:', error)
    return NextResponse.json(
      { error: 'Failed to update conversation' },
      { status: 500 }
    )
  }
}
