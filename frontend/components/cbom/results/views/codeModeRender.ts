// Tests only: renders CbomResults in code mode (no `source`) with the code-mode fixture, inside the providers the App
// Router gives a page (router, search params, path params) and a react-query client. React's generated ids (useId) are
// replaced by a placeholder: they follow the tree's shape, not what the page shows.
import "./testCssStub";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AppRouterContext } from "next/dist/shared/lib/app-router-context.shared-runtime";
import { PathnameContext, PathParamsContext, SearchParamsContext } from "next/dist/shared/lib/hooks-client-context.shared-runtime";

import CbomResults from "@/components/CbomResults";
import { CODE_DASHBOARD, CODE_DATA, CODE_FINDINGS, CODE_METADATA } from "./codeModeFixture";

const h = React.createElement;
const router = { push() {}, replace() {}, refresh() {}, back() {}, forward() {}, prefetch() {} };

export function withAppRouter(node: React.ReactNode, search = "", params: Record<string, string> = { team_id: "2", scan_id: "5" }): React.ReactElement {
  return h(QueryClientProvider, { client: new QueryClient() },
    h(AppRouterContext.Provider, { value: router as never },
      h(SearchParamsContext.Provider, { value: new URLSearchParams(search) as never },
        h(PathnameContext.Provider, { value: "/2/cbom/5/results" },
          h(PathParamsContext.Provider, { value: params }, node)))));
}

export const normaliseIds = (html: string) => html.replace(/_R_[0-9a-zA-Z_]*?_(?=[^0-9a-zA-Z_]|$)/g, "_ID_").replace(/«[^»]*»/g, "«ID»");

export function renderCodeMode(): string {
  return normaliseIds(renderToStaticMarkup(withAppRouter(h(CbomResults, {
    data: CODE_DATA, conversationId: 5, teamId: "2", dashboard: CODE_DASHBOARD, findings: CODE_FINDINGS,
    scanMetadata: CODE_METADATA, integrationSettings: {}, onIntegrationSettingsUpdated: () => undefined, onFindingsUpdated: () => undefined,
  }))));
}
