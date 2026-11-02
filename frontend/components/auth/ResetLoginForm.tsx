// app/login/page.tsx
"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Mail, Lock, Shield, ArrowRightFromLineIcon, ArrowUpRight } from "lucide-react" // Ensure Shield is imported here

// Import official-looking icons from react-icons
import { FcGoogle } from "react-icons/fc"
import { FaApple } from "react-icons/fa"
import { FaXTwitter } from "react-icons/fa6" // Keeping this. If this still fails, confirm react-icons version/install.
import { toast } from "sonner"
import router from "next/navigation"
import api from "@/utils/interceptors"
import { useRouter } from "next/navigation"
import { handleApiError, showErrorToast } from "@/utils/error-handler"
import { newPasswordProblem, NEW_PASSWORD_HINT } from "@/utils/password_rules"



type UserData = {
    email: string
    password: string,
    verification_code: string,
    re_password: string
}
const delay = 30
const emptyResetUserData: UserData = {email: "", password: "", verification_code: "", re_password: ""}


export default function ResetLoginForm() {
  const [ userData, setUserData ] = useState<UserData>(emptyResetUserData)
  
  //timer to send verification code
  const [timer, setTimer] = useState(delay*1000)
  const [ timerId , setTimerId ] = useState<NodeJS.Timeout | null>(null)
  const [timerStarted, setTimerStarted] = useState(false)
  const [sendingCode, setSendingCode] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if(timer===0){
      clearInterval(timerId!)
      setTimerStarted(false)
      setTimer(delay*1000)
    }
    return () => {
      if (timerId) clearInterval(timerId)
    }
  }, [timer, timerId])

  const handleSendVerificationCode = async () => {
    const toastId = toast.loading("Sending verification code...")
    try{
        if(userData?.email.trim() === ""){
            toast.error("Please enter your email address")
            return
        }
        setSendingCode(true)
        setTimerStarted(true)
        setTimerId(setInterval(() => {
          setTimer(prev=>prev - 1000)
        }, 1000))
        const response = await api.post("/send_code",{email: userData?.email.trim()})
        if(response.status === 200){
            toast.success("Verification code sent successfully")
            
        }else{
            toast.error("Error while sending verification code",{description: response.data.detail})
        }
    }
    catch(error:any){
        showErrorToast(error, "Error while sending verification code")
    }
    finally{
        setSendingCode(false)
        toast.dismiss(toastId)
    }
  }
  
  
  const router = useRouter()
  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault()
    const problem = newPasswordProblem(userData?.password || "")
    if (problem) {
        toast.error(problem)
        return
    }
    if(userData?.password !== userData?.re_password){
        toast.error("Password and Re-Password do not match")
        return
    }
    const toastId = toast.loading("Resetting password...")
    setSubmitting(true)
    try{
        const response = await api.post("/reset_password",{
            email: userData?.email,
            password: userData?.password,
            verification_code: userData?.verification_code,
        })
        if(response.status === 200){
            // the reset signed out every session of this account (earlier tokens are revoked)
            localStorage.removeItem("access_token")
            localStorage.removeItem("refresh_token")
            toast.success("Password reset successfully. Please log in with your new password.")
            router.push("/login")
        }else{
            toast.error("Error while resetting password",{description: response.data.detail})
        }
    }
    catch(error:any){
        showErrorToast(error, "Error while resetting password")
    }
    finally{
        setSubmitting(false)
        toast.dismiss(toastId)
    }
  }
  

  return (
    <div className="flex items-center justify-center min-h-screen bg-background">
      <Card className="mx-auto max-w-sm w-full">
        <CardHeader className="space-y-1 text-center">
          {/* === START: UPDATED LOGO/TITLE SECTION (Matches Sidebar) === */}
          <div className="flex flex-col items-center justify-center space-y-2 mb-2">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center text-white text-xl font-bold">
              <Shield className="h-6 w-6" /> {/* Shield icon */}
            </div>
            <CardTitle className="text-2xl font-bold">DevSec Shield</CardTitle>
          </div>
          {/* === END: UPDATED LOGO/TITLE SECTION === */}
          <CardDescription>
           Don't have an account yet?
            <Link href="/register" className="ml-2 text-primary hover:underline">
              Sign Up
            </Link>
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <form onSubmit={handleResetPassword} className="space-y-4">

            {/* email section */}
            <div className="space-y-2">
              <Label htmlFor="email">Email address</Label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  id="email"
                  type="email"
                  autoComplete="username"
                  placeholder="email address"
                  className="pl-9"
                  value={userData?.email}
                  onChange={(e) => setUserData({...userData, email: e.target.value})}
                  required
                />
              </div>
            </div>
            {/* password section */}
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  id="password"
                  type="password"
                  autoComplete="new-password"
                  aria-describedby="password-rules"
                  placeholder="Password"
                  className="pl-9"
                  value={userData?.password}
                  onChange={(e) => setUserData({...userData, password: e.target.value})}
                  required
                />
              </div>
              <p id="password-rules" className="text-xs text-muted-foreground">{NEW_PASSWORD_HINT}</p>
            </div>

            {/* re-password section */}
            <div className="space-y-2">
              <Label htmlFor="re_password">Re-Password</Label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                    id="re_password"
                    type="password"
                    autoComplete="new-password"
                    placeholder="Re-Password"
                    className="pl-9"
                    value={userData?.re_password}
                    onChange={(e) => setUserData({...userData, re_password: e.target.value})}
                    required
                />
              </div>
            </div>

            
            
            {/* verification code section */}
              <div className="flex flex-col gap-2 w-full">
                <div className="space-y-2">
                  <Label htmlFor="verification_code">Verification Code</Label>
                  <Input
                    id="verification_code"
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    placeholder="Verification Code"
                    className="pl-2"
                    value={userData?.verification_code}
                    onChange={(e) => setUserData({...userData, verification_code: e.target.value})}
                    required
                  />
                </div>
                <div className="flex items-center w-full ">
                  <button 
                    type="button"
                    disabled={timerStarted || sendingCode}
                    className="w-fit cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed text-sm items-center ml-auto flex flex-row gap-2 hover:text-blue-300 hover:underline" onClick={handleSendVerificationCode}>
                    {sendingCode ? "Sending code..." : timerStarted ? `Resend in ${timer/1000}s` : "Send Verification Code"} <ArrowUpRight size={18}/>
                  </button>
                </div>
              </div>
  
            
            {/* submit button */}
            <Button type="submit" className="w-full cursor-pointer" disabled={submitting}>
              {submitting ? "Resetting password..." : "Reset Password"}
            </Button>

          </form>
          
        </CardContent>
      </Card>
    </div>
  )
}

