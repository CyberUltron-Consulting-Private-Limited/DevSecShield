import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

// POST /api/conversations/by-session/[sessionId]/messages
// Append messages by session ID (used by agent backend)
// Auto-creates conversation if body includes projectId + userId
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ sessionId: string }> }
) {
  try {
    const { sessionId } = await params
    const body = await request.json()

    // Find or create conversation
    let conversation = await prisma.conversation.findUnique({
      where: { sessionId },
    })

    if (!conversation) {
      const { projectId, userId: rawUserId } = body
      if (!projectId || !rawUserId) {
        return NextResponse.json(
          { error: 'Conversation not found. Provide projectId and userId to auto-create.' },
          { status: 404 }
        )
      }

      // Resolve valid userId: if the provided userId doesn't exist as a User,
      // fall back to the project owner's userId. This handles the case when
      // the agent backend sends 'default_user' (which isn't a real User record).
      let resolvedUserId = rawUserId
      const userExists = await prisma.user.findUnique({ where: { id: rawUserId }, select: { id: true } })
      if (!userExists) {
        const project = await prisma.project.findUnique({ where: { id: projectId }, select: { userId: true } })
        if (!project) {
          return NextResponse.json({ error: 'Project not found' }, { status: 404 })
        }
        resolvedUserId = project.userId
      }

      conversation = await prisma.conversation.create({
        data: { projectId, userId: resolvedUserId, sessionId },
      })
    }

    // Support single or batch messages
    const items: Array<{ type: string; data: unknown }> = body.messages
      ? body.messages
      : [{ type: body.type, data: body.data }]

    // Get current max sequence number
    const maxSeq = await prisma.chatMessage.aggregate({
      where: { conversationId: conversation.id },
      _max: { sequenceNum: true },
    })
    let nextSeq = (maxSeq._max.sequenceNum ?? -1) + 1

    const created = await prisma.chatMessage.createMany({
      data: items.map((item) => ({
        conversationId: conversation.id,
        sequenceNum: nextSeq++,
        type: item.type,
        data: item.data as any,
      })),
    })

    // Auto-set title from first user message if title is empty
    if (!conversation.title && items.some(i => i.type === 'user_message')) {
      const firstUserMsg = items.find(i => i.type === 'user_message')
      if (firstUserMsg && typeof (firstUserMsg.data as any)?.content === 'string') {
        const title = (firstUserMsg.data as any).content.substring(0, 100)
        await prisma.conversation.update({
          where: { id: conversation.id },
          data: { title },
        })
      }
    }

    // Touch updatedAt
    await prisma.conversation.update({
      where: { id: conversation.id },
      data: { updatedAt: new Date() },
    })

    return NextResponse.json({ count: created.count, conversationId: conversation.id }, { status: 201 })
  } catch (error) {
    console.error('Failed to save messages by session:', error)
    return NextResponse.json(
      { error: 'Failed to save messages' },
      { status: 500 }
    )
  }
}
