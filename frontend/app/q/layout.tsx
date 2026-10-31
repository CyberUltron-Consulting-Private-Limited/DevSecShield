import type { Metadata } from "next";

// Public, single-use vendor questionnaire links: never indexed, and the token in the URL is never sent
// to another site as a Referer.
export const metadata: Metadata = {
  title: "Questionnaire · ZeroShield",
  referrer: "no-referrer",
  robots: { index: false, follow: false },
};

export default function QuestionnaireLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return children;
}
