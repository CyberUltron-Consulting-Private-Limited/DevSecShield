import { NextRequest, NextResponse } from 'next/server'
import prisma from './prisma'

const COOKIE_NAME = 'dss-team-id'
const INTERNAL_KEY = process.env.INTERNAL_SERVICE_KEY || 'redamon-internal-service'

/**
 * Returns true if the request comes from an internal backend service
 * (recon orchestrator, agent, gvm scanner, etc.) that sent the shared key.
 */
function isInternalService(request: NextRequest): boolean {
  return request.headers.get('x-internal-key') === INTERNAL_KEY
}

/**
 * Resolves the RedAmon userId for a DevSecShield team.
 * Auto-creates the team user on first access (upsert).
 *
 * Reads teamId from (in order of priority):
 *   1. X-DSS-Team-Id header (set by proxy or middleware)
 *   2. dss-team-id cookie (set by middleware on iframe load)
 *
 * Returns the RedAmon user ID string, or a NextResponse error.
 */
export async function resolveTeamUserId(
  request: NextRequest
): Promise<string | NextResponse> {
  const teamId =
    request.headers.get('x-dss-team-id') ||
    request.cookies.get(COOKIE_NAME)?.value

  if (!teamId) {
    return NextResponse.json(
      { error: 'Unauthorized: missing team context' },
      { status: 401 }
    )
  }

  const email = `team_${teamId}@devsecshield.local`

  const user = await prisma.user.upsert({
    where: { email },
    update: {},
    create: {
      name: `Team ${teamId}`,
      email,
    },
  })

  return user.id
}

/**
 * Checks that a project belongs to the requesting team.
 * Internal services (recon, agent, gvm) bypass this check.
 * Returns the userId if it matches, or a 404 NextResponse.
 */
export async function verifyProjectOwnership(
  request: NextRequest,
  projectId: string
) {
  if (isInternalService(request)) {
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { userId: true },
    })
    if (!project) {
      return {
        error: NextResponse.json(
          { error: 'Project not found' },
          { status: 404 }
        ),
      }
    }
    return { userId: project.userId }
  }

  const userIdOrError = await resolveTeamUserId(request)
  if (userIdOrError instanceof NextResponse) return { error: userIdOrError }

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: { userId: true },
  })

  if (!project || project.userId !== userIdOrError) {
    return {
      error: NextResponse.json(
        { error: 'Project not found' },
        { status: 404 }
      ),
    }
  }

  return { userId: userIdOrError }
}
