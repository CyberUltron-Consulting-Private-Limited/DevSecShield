import { NextRequest, NextResponse } from 'next/server'

const DSS_LOGIN_URL = process.env.DSS_LOGIN_URL || 'http://localhost:8080/login'
const COOKIE_NAME = 'dss-team-id'
const INTERNAL_KEY = process.env.INTERNAL_SERVICE_KEY || 'redamon-internal-service'

/**
 * Middleware for team-based auth integration with DevSecShield.
 *
 * Team context is resolved from (in priority order):
 *   1. X-DSS-Team-Id header (set by DevSecShield proxy)
 *   2. teamId query parameter (set by DevSecShield iframes)
 *   3. dss-team-id cookie (persisted from a prior iframe load)
 *
 * Internal backend services (recon, gvm, agent, etc.) bypass team
 * auth by sending X-Internal-Key. These services run on the same
 * Docker network and need direct access to project data.
 *
 * Direct browser access without any team context is redirected to
 * the DevSecShield login page.
 */
export function middleware(request: NextRequest) {
  const { pathname, searchParams } = request.nextUrl

  const internalKey = request.headers.get('x-internal-key')
  if (internalKey === INTERNAL_KEY) {
    return NextResponse.next()
  }

  const teamIdParam = searchParams.get('teamId')
  const teamIdHeader = request.headers.get('x-dss-team-id')
  const teamIdCookie = request.cookies.get(COOKIE_NAME)?.value

  const teamId = teamIdHeader || teamIdParam || teamIdCookie

  if (pathname.startsWith('/api/')) {
    if (!teamId) return NextResponse.next()

    const response = NextResponse.next({
      request: {
        headers: new Headers({
          ...Object.fromEntries(request.headers),
          'x-dss-team-id': teamId,
        }),
      },
    })

    if (teamIdParam && teamIdParam !== teamIdCookie) {
      response.cookies.set(COOKIE_NAME, teamIdParam, {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
      })
    }

    return response
  }

  if (teamId) {
    const response = NextResponse.next()

    if (teamIdParam && teamIdParam !== teamIdCookie) {
      response.cookies.set(COOKIE_NAME, teamIdParam, {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
      })
    }

    return response
  }

  return NextResponse.redirect(DSS_LOGIN_URL)
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon\\.ico|favicon\\.png|.*\\.svg$).*)',
  ],
}
