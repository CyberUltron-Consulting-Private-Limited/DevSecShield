import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { resolveTeamUserId } from '@/lib/team-auth'

// GET /api/projects - List projects scoped to the requesting team
export async function GET(request: NextRequest) {
  try {
    const userIdOrError = await resolveTeamUserId(request)
    if (userIdOrError instanceof NextResponse) return userIdOrError

    const projects = await prisma.project.findMany({
      where: { userId: userIdOrError },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        userId: true,
        name: true,
        description: true,
        targetDomain: true,
        createdAt: true,
        updatedAt: true,
        user: {
          select: {
            id: true,
            name: true,
            email: true
          }
        }
      }
    })

    return NextResponse.json(projects)
  } catch (error) {
    console.error('Failed to fetch projects:', error)
    return NextResponse.json(
      { error: 'Failed to fetch projects' },
      { status: 500 }
    )
  }
}

// POST /api/projects - Create a new project under the requesting team
export async function POST(request: NextRequest) {
  try {
    const userIdOrError = await resolveTeamUserId(request)
    if (userIdOrError instanceof NextResponse) return userIdOrError

    const body = await request.json()
    const { userId: _ignored, name, targetDomain, ...optionalParams } = body

    if (!name || !targetDomain) {
      return NextResponse.json(
        { error: 'name and targetDomain are required' },
        { status: 400 }
      )
    }

    const project = await prisma.project.create({
      data: {
        userId: userIdOrError,
        name,
        targetDomain,
        ...optionalParams
      }
    })

    return NextResponse.json(project, { status: 201 })
  } catch (error) {
    console.error('Failed to create project:', error)
    return NextResponse.json(
      { error: 'Failed to create project' },
      { status: 500 }
    )
  }
}
