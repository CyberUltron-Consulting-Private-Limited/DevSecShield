"use client"

import { useEffect } from "react"
import { usePathname } from "next/navigation"

import { SidebarTrigger, useSidebar } from "@/components/ui/sidebar"

/**
 * Below 768px the sidebar is a sheet that only a SidebarTrigger opens, and no layout rendered one: on a phone the
 * team and home pages had no navigation at all (X1, round 5, 390x844). This bar shows the trigger on phones only and
 * closes the sheet after a link is followed.
 */
export function MobileNavBar({ title = "Menu" }: { title?: string }) {
  const { isMobile, setOpenMobile } = useSidebar()
  const pathname = usePathname()

  useEffect(() => {
    setOpenMobile(false)
  }, [pathname, setOpenMobile])

  if (!isMobile) return null
  return (
    <div
      data-testid="mobile-nav-bar"
      className="sticky top-0 z-30 flex items-center gap-2 border-b border-border bg-background px-4 py-2 md:hidden"
    >
      <SidebarTrigger aria-label="Open navigation" />
      <span className="text-sm font-medium truncate">{title}</span>
    </div>
  )
}
