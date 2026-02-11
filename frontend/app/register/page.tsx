"use client"

import { Suspense } from "react"
import LoginForm from "@/components/auth/LoginForm"

export default function RegisterPage() {
  return (
    <Suspense fallback={<div className="flex items-center justify-center min-h-screen bg-background" />}>
      <LoginForm method="signup" />
    </Suspense>
  )
}