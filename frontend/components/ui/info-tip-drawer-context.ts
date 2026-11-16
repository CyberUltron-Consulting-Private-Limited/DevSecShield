"use client";

// The Explanations drawer's context, apart from the drawer itself so <InfoTip> (on every page) imports only this
// small module, not the drawer's Sheet, search field and manifest. See info-tip-drawer.tsx.
import { createContext, useContext } from "react";

import type { InfoTipId } from "@/content/infotips";
import type { DrawerView } from "@/content/infotips/drawerManifest";

export interface InfoTipDrawerApi {
  /** opens the drawer, scrolled to this tip when given */
  open: (id?: InfoTipId) => void;
  close: () => void;
  isOpen: boolean;
  view: DrawerView;
}

export const DrawerContext = createContext<InfoTipDrawerApi | null>(null);

/** The nearest drawer, or null when no provider is above (InfoTip then behaves as it always did). */
export function useInfoTipDrawer(): InfoTipDrawerApi | null {
  return useContext(DrawerContext);
}
