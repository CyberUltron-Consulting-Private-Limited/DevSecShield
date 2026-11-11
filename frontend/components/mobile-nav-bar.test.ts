/**
 * X1 (round 5 customer walkthrough, 390x844): on a phone the team pages (/13, /13/cbom, /13/dast/70, ...) and /home
 * had no navigation: below 768px the shadcn Sidebar renders as a closed sheet that only a SidebarTrigger opens, and
 * neither layout rendered one (no visible button on /13 at phone width).
 * Browser check after a rebuild: 390x844 /13 > "Open navigation" opens the menu; tapping CBOM opens /13/cbom with the
 * menu closed. At 1440x900 the bar is not shown.
 * Run: npx --yes tsx components/mobile-nav-bar.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

const root = path.join(__dirname, "..")
const bar = fs.readFileSync(path.join(__dirname, "mobile-nav-bar.tsx"), "utf8")
assert.ok(bar.includes('<SidebarTrigger aria-label="Open navigation" />'), "the bar holds the trigger")
assert.ok(bar.includes("if (!isMobile) return null"), "desktop keeps its layout")
assert.ok(/useEffect\(\(\) => \{\s*setOpenMobile\(false\)\s*\}, \[pathname, setOpenMobile\]\)/.test(bar), "following a link closes the sheet")

const sidebar = fs.readFileSync(path.join(root, "components/ui/sidebar.tsx"), "utf8")
assert.ok(sidebar.includes("return isMobile ? setOpenMobile((open) => !open) : setOpen((open) => !open)"), "the trigger toggles the phone sheet")

for (const layout of ["app/[team_id]/layout.tsx", "app/home/layout.tsx"]) {
  const src = fs.readFileSync(path.join(root, layout), "utf8")
  assert.ok(src.includes('import { MobileNavBar } from "@/components/mobile-nav-bar";'), `${layout}: imports the bar`)
  const inset = src.slice(src.indexOf('<SidebarInset className="overflow-auto">'), src.indexOf("</SidebarInset>"))
  assert.ok(inset.includes("<MobileNavBar />"), `${layout}: renders the bar inside SidebarInset (inside SidebarProvider)`)
  assert.ok(inset.indexOf("<MobileNavBar />") < inset.indexOf("{children}"), `${layout}: above the page`)
}

console.log("mobile nav bar tests passed")
