import type { Metadata } from 'next'
import { Suspense } from 'react'
import '@/styles/index.css'
import { QueryProvider } from '@/providers/QueryProvider'
import { ProjectProvider } from '@/providers/ProjectProvider'
import { ToastProvider } from '@/components/ui'
import { AppLayout } from '@/components/layout'

export const metadata: Metadata = {
  title: 'DevSecShield - Red Team',
  description: 'Red team operations - reconnaissance, exploitation, and remediation',
  icons: {
    icon: '/favicon.ico',
    apple: '/favicon.png',
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                try {
                  var theme = localStorage.getItem('redamon-theme');
                  if (theme === 'dark' || theme === 'light') {
                    document.documentElement.setAttribute('data-theme', theme);
                  } else if (window.matchMedia('(prefers-color-scheme: light)').matches) {
                    document.documentElement.setAttribute('data-theme', 'light');
                  } else {
                    document.documentElement.setAttribute('data-theme', 'dark');
                  }
                } catch (e) {
                  document.documentElement.setAttribute('data-theme', 'dark');
                }
                if (window.location.search.indexOf('embed=true') !== -1) {
                  document.documentElement.setAttribute('data-embed', 'true');
                }
              })();
            `,
          }}
        />
      </head>
      <body>
        <QueryProvider>
          <Suspense fallback={null}>
            <ProjectProvider>
              <ToastProvider>
                <AppLayout>{children}</AppLayout>
              </ToastProvider>
            </ProjectProvider>
          </Suspense>
        </QueryProvider>
      </body>
    </html>
  )
}
