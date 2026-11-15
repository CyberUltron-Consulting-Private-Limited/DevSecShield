/** Build identity (CB-03): the commit this frontend was built from, as <meta name="zs-build"> on every page, only
 * where the deployment exposes its build: NEXT_PUBLIC_BUILD_SHA is a build argument of frontend/Dockerfile that
 * scripts/deploy/build_images.sh fills only with DSS_EXPOSE_BUILD=1 (local stack, lab, staging). Without it (the
 * production default) no meta tag is written; signed-in users read the build from the API's GET /version. */
const SHA = /^[0-9a-f]{40}$/

/** The full 40-character commit, or "unknown" for anything else (never echoed into the page as given). */
export function buildSha(raw: string | undefined | null): string {
  const value = (raw ?? "").trim().toLowerCase()
  return SHA.test(value) ? value : "unknown"
}

/** Next.js metadata fragment: `metadata.other` renders as <meta name="zs-build" content="...">; nothing at all
 * without a commit. */
export function buildMeta(raw: string | undefined | null): { other: { "zs-build": string } } | Record<string, never> {
  const sha = buildSha(raw)
  return sha === "unknown" ? {} : { other: { "zs-build": sha } }
}
