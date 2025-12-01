// app/login/page.tsx
"use client"

import { useRouter } from "next/navigation"
import LoginForm from "@/components/auth/LoginForm"


export default function LoginPage() {

  return (
    <LoginForm method="signup" />
  )
}