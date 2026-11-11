import type { Metadata } from "next";

// Single-use team invitation links: never indexed, and the token in the URL is never sent to another site as a Referer.
export const metadata: Metadata = {
  title: "Team invitation · DevSecShield",
  referrer: "no-referrer",
  robots: { index: false, follow: false },
};

export default function InviteLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return children;
}
