import type { Metadata } from "next";

// "Choose your password" link of an account an administrator created (token in the URL fragment): never indexed.
export const metadata: Metadata = {
  title: "Choose your password · DevSecShield",
  referrer: "no-referrer",
  robots: { index: false, follow: false },
};

export default function SetPasswordLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return children;
}
