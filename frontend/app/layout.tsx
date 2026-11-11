import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider"
import { Toaster } from "sonner"
// errors 8 s with a close button, successes 4 s, up to 3 at once (utils/toast.ts, utils/toastPolicy.ts; was 1.5 s and one at a time)
import { TOAST_SUCCESS_MS, TOASTS_VISIBLE } from "@/utils/toastPolicy"

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "DevSecShield",
  description: "DevSecShield is a platform for developers to secure their applications.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <ThemeProvider
            attribute="class"
            defaultTheme="dark"
            enableSystem
            disableTransitionOnChange
          >
            {children}
          </ThemeProvider>
          <Toaster
          richColors
          position="bottom-right"
          expand
          duration={TOAST_SUCCESS_MS}
          visibleToasts={TOASTS_VISIBLE}
          theme="dark"
          />
      </body>
    </html>
  );
}
