import Link from "next/link";
import { Button } from "@/components/ui/button";
import { 
  Shield, 
  Code, 
  Lock, 
  ArrowRight, 
  Brain, 
  Network, 
  Search, 
  Package, 
  Bot,
  Globe
} from "lucide-react";

export default function Home() {
  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-zinc-900">
      {/* Header */}
      <header className="border-b border-zinc-200 dark:border-zinc-800">
        <div className="container mx-auto flex h-16 items-center justify-between px-6">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-teal-600" />
            <span className="text-xl font-bold text-zinc-900 dark:text-white">DevSecShield</span>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/login">
              <Button variant="ghost" className="text-zinc-600 dark:text-zinc-400">
                Sign In
              </Button>
            </Link>
            <Link href="/register">
              <Button className="bg-teal-600 hover:bg-teal-700 text-white">
                Get Started
              </Button>
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="flex-1">
        <section className="container mx-auto px-6 py-24">
          <div className="mx-auto max-w-4xl text-center">
            <h1 className="mb-6 text-5xl font-bold tracking-tight text-zinc-900 dark:text-white sm:text-6xl">
              Secure Your Code
              <span className="block text-teal-600">Before It Ships</span>
            </h1>
            <p className="mb-8 text-xl text-zinc-600 dark:text-zinc-400 sm:text-2xl">
              Comprehensive security scanning for your applications. SAST, DAST, IAC, and more.
            </p>
            <div className="flex flex-col items-center justify-center gap-4 sm:flex-row">
              <Link href="/register">
                <Button size="lg" className="bg-teal-600 hover:bg-teal-700 text-white text-lg px-8">
                  Start Scanning
                  <ArrowRight className="ml-2 h-5 w-5" />
                </Button>
              </Link>
              <Link href="/login">
                <Button size="lg" variant="outline" className="text-lg px-8">
                  Sign In
                </Button>
              </Link>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section className="border-t border-zinc-200 bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-950 py-24">
          <div className="container mx-auto px-6">
            <div className="mx-auto max-w-7xl">
              <h2 className="mb-12 text-center text-3xl font-bold text-zinc-900 dark:text-white">
                Comprehensive Security Testing
              </h2>
              <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
                <div className="rounded-lg border border-zinc-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-teal-100 dark:bg-teal-900/30">
                    <Code className="h-6 w-6 text-teal-600" />
                  </div>
                  <h3 className="mb-2 text-xl font-semibold text-zinc-900 dark:text-white">
                    Static Analysis (SAST)
                  </h3>
                  <p className="text-sm text-zinc-600 dark:text-zinc-400">
                    Find vulnerabilities in your source code before deployment.
                  </p>
                </div>

                <div className="rounded-lg border border-zinc-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-teal-100 dark:bg-teal-900/30">
                    <Globe className="h-6 w-6 text-teal-600" />
                  </div>
                  <h3 className="mb-2 text-xl font-semibold text-zinc-900 dark:text-white">
                    Dynamic Analysis (DAST)
                  </h3>
                  <p className="text-sm text-zinc-600 dark:text-zinc-400">
                    Test running applications for security vulnerabilities.
                  </p>
                </div>

                <div className="rounded-lg border border-zinc-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-teal-100 dark:bg-teal-900/30">
                    <Lock className="h-6 w-6 text-teal-600" />
                  </div>
                  <h3 className="mb-2 text-xl font-semibold text-zinc-900 dark:text-white">
                    Infrastructure as Code (IAC)
                  </h3>
                  <p className="text-sm text-zinc-600 dark:text-zinc-400">
                    Scan your infrastructure configurations for misconfigurations.
                  </p>
                </div>

                <div className="rounded-lg border border-zinc-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-teal-100 dark:bg-teal-900/30">
                    <Brain className="h-6 w-6 text-teal-600" />
                  </div>
                  <h3 className="mb-2 text-xl font-semibold text-zinc-900 dark:text-white">
                    LLM Benchmarking
                  </h3>
                  <p className="text-sm text-zinc-600 dark:text-zinc-400">
                    Evaluate and benchmark Large Language Models for security vulnerabilities.
                  </p>
                </div>

                <div className="rounded-lg border border-zinc-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-teal-100 dark:bg-teal-900/30">
                    <Network className="h-6 w-6 text-teal-600" />
                  </div>
                  <h3 className="mb-2 text-xl font-semibold text-zinc-900 dark:text-white">
                    MCP Scanning
                  </h3>
                  <p className="text-sm text-zinc-600 dark:text-zinc-400">
                    Scan Model Context Protocol servers for security issues.
                  </p>
                </div>

                <div className="rounded-lg border border-zinc-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-teal-100 dark:bg-teal-900/30">
                    <Search className="h-6 w-6 text-teal-600" />
                  </div>
                  <h3 className="mb-2 text-xl font-semibold text-zinc-900 dark:text-white">
                    Data Leakage Detection
                  </h3>
                  <p className="text-sm text-zinc-600 dark:text-zinc-400">
                    Detect secrets, credentials, and sensitive data in your repositories.
                  </p>
                </div>

                <div className="rounded-lg border border-zinc-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-teal-100 dark:bg-teal-900/30">
                    <Package className="h-6 w-6 text-teal-600" />
                  </div>
                  <h3 className="mb-2 text-xl font-semibold text-zinc-900 dark:text-white">
                    SBOM & SCA
                  </h3>
                  <p className="text-sm text-zinc-600 dark:text-zinc-400">
                    Generate Software Bill of Materials and scan for vulnerable dependencies.
                  </p>
                </div>

                <div className="rounded-lg border border-zinc-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-teal-100 dark:bg-teal-900/30">
                    <Bot className="h-6 w-6 text-teal-600" />
                  </div>
                  <h3 className="mb-2 text-xl font-semibold text-zinc-900 dark:text-white">
                    Agent Discovery
                  </h3>
                  <p className="text-sm text-zinc-600 dark:text-zinc-400">
                    Discover and analyze AI agents and their security configurations.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-200 dark:border-zinc-800 py-8">
        <div className="container mx-auto px-6 text-center text-sm text-zinc-600 dark:text-zinc-400">
          <p>© 2024 DevSecShield. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
}
