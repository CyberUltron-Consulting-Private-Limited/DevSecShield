/**
 * The header row of every scan results page (SAST, SCA + SBOM, IaC, DAST, MCP, LLM, AI BOM, data leakage, agent
 * discovery; CBOM has its own, the same idea): back button and title on the left, the page's actions (report
 * downloads, "Chat with the Results") on the right, and on a narrow screen the actions wrap under the title instead of
 * running off its right edge. Staging QA 23 Nov 2026: at 390 px "Download Scan Report" overflowed the viewport by
 * 6 px and "Chat with the Results" was off screen altogether, while the title was squeezed to one word per line.
 * components/resultsHeaderLayout.test.ts measures it in a real browser at 390, 820 and 1440 px.
 */
export const RESULTS_HEADER = {
  // wraps: the actions take a line of their own when title and actions do not fit side by side
  row: "flex flex-wrap items-center justify-between gap-4",
  // may shrink below its content (min-w-0), so a long title wraps inside the screen
  lead: "flex min-w-0 items-center gap-4",
  title: "min-w-0 break-words",
  // the buttons wrap too, one under another when even one row of them is wider than the screen
  actions: "flex flex-wrap items-center gap-2 lg:justify-end",
} as const;

/**
 * The scan chat page's header (components/ai/ChatWindow.tsx, every scan type): "SAST › <scan title>", progress, scan
 * status and Refresh. Staging QA 23 Nov 2026: on a tablet, where the chat column is narrow beside the options sidebar,
 * the breadcrumb could not shrink (shrink-0) and drew the scan title under the Refresh button. The title now
 * truncates (its full text in a tooltip), the status keeps its divider, and Refresh wraps to a line of its own when
 * the column is too narrow for both.
 */
export const SCAN_CHAT_HEADER = {
  row: "flex flex-wrap items-center justify-between gap-x-3 gap-y-2 border-b bg-muted/50 px-4 py-3",
  // 12rem of breadcrumb before Refresh wraps; it wraps its own parts (crumb, progress, status) inside that
  lead: "flex min-w-0 flex-1 basis-48 flex-wrap items-center gap-x-3 gap-y-1",
  crumb: "flex min-w-0 max-w-full items-center gap-2",
  crumbTitle: "min-w-0 truncate text-neutral-200 font-medium",
  status: "flex shrink-0 items-center gap-3",
  actions: "ml-auto flex shrink-0 flex-row items-center justify-end gap-3",
} as const;
