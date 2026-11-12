/** Build identity (CB-03): the commit this frontend was built from, put into every page as <meta name="zs-build">.
 * NEXT_PUBLIC_BUILD_SHA is a build argument of frontend/Dockerfile (scripts/deploy/build_images.sh passes the git
 * commit); the backend reports the same commit in GET /health and the X-ZS-Build header. */
const SHA = /^[0-9a-f]{40}$/

/** The full 40-character commit, or "unknown" for anything else (never echoed into the page as given). */
export function buildSha(raw: string | undefined | null): string {
  const value = (raw ?? "").trim().toLowerCase()
  return SHA.test(value) ? value : "unknown"
}

/** Next.js metadata fragment: `metadata.other` renders as <meta name="zs-build" content="...">. */
export function buildMeta(raw: string | undefined | null): { other: { "zs-build": string } } {
  return { other: { "zs-build": buildSha(raw) } }
}
