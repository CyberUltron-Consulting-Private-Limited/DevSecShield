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
import router, { useSearchParams } from "next/navigation"
import api, { retryAfterSeconds } from "@//utils/interceptors"
import { resendLabel, useResendCountdown, waitAfterFailedSend } from "@/utils/resend_countdown"
import { useRouter } from "next/navigation"
import { handleApiError, showErrorToast } from "@/utils/error-handler"
import { text_input_validation } from "@/utils/input_validation"
import { loginPasswordProblem, newPasswordProblem, NEW_PASSWORD_HINT } from "@/utils/password_rules"



type UserData = {
    email: string
    password: string,
    verification_code: string,
    first_name?: string
    last_name?: string
}
const delay = 30
const emptyRegisterUserData: UserData = {email: "", password: "", verification_code: "", first_name: "", last_name: ""}
const emptyLoginUserData: UserData = {email: "", password: "", verification_code: ""}
export default function LoginPage({
    method,
}:{
    method: "login" | "signup"
}) {
  const [ userData, setUserData ] = useState<UserData>(method === "login" ? emptyLoginUserData : emptyRegisterUserData)

  // wait before "Send Verification Code" can be pressed again
  const countdown = useResendCountdown(delay)
  const [sendingCode, setSendingCode] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  // get query params for redirect url after auth ( and redirect to that url after auth if this query param is present)
  const searchParams = useSearchParams()
  const redirectUrlString = searchParams.get("redirect_url")
  // Validate redirect URL to prevent open redirect attacks - only allow relative paths
  const rawRedirect = redirectUrlString?.split("-").join("/") || ""
  const redirectUrl = rawRedirect.startsWith("/") && !rawRedirect.startsWith("//") ? rawRedirect : ""



  const handleCancel = () => {
    alert("going back")
    // Push a dummy state to the history stack
    window.history.pushState(null, "", window.location.pathname);
  };


  const handleSendVerificationCode = async () => {
    const toastId = toast.loading("Sending verification code...")
    try{
        if(userData?.email.trim() === ""){
            toast.error("Please enter your email address")
            return
        }
        setSendingCode(true)
        countdown.start()
        const response = await api.post("/send_code",{email: userData?.email.trim()})
        if(response.status === 200){
            toast.success("Verification code sent successfully")

        }else{
            countdown.stop()
            toast.error("Error while sending verification code",{description: response.data.detail})
        }
    }
    catch(error:any){
        // nothing was sent: no wait before the next try (only the server's Retry-After for a 429)
        const apiError = showErrorToast(error, "Error while sending verification code");
        countdown.start(waitAfterFailedSend(apiError.status, retryAfterSeconds(error)))
    }
    finally{
        setSendingCode(false)
        toast.dismiss(toastId)
    }
  }
  
  
  const router = useRouter()
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    const problem = newPasswordProblem(userData?.password || "")
    if (problem) {
      toast.error(problem)
      return
    }
    const toastId = toast.loading("Creating your account...")
    setSubmitting(true)


    try{

      text_input_validation(userData?.verification_code)
      text_input_validation(userData?.first_name || "")
      text_input_validation(userData?.last_name || "")

        const response = await api.post("/signup",{
            email: userData?.email,
            password: userData?.password,
            verification_code: userData?.verification_code,
            first_name: userData?.first_name,
            last_name: userData?.last_name
        })
        if(response.status === 200){
            localStorage.setItem("access_token", response.data.access_token)
            localStorage.setItem("refresh_token", response.data.refresh_token)
            router.push(redirectUrl || "/home")
        }else{
            toast.error("Error while registering",{description: response.data.detail})
        }
    }
    catch(error:any){
      // setUserData(emptyLoginUserData)
      const apiError = handleApiError(error);
      showErrorToast(error, "Error while registering");
    }
    finally{
        setSubmitting(false)
        toast.dismiss(toastId)
    }
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    const problem = loginPasswordProblem(userData?.password || "")
    if (problem) {
      toast.error(problem)
      return
    }
    const toastId = toast.loading("Logging in...")
    setSubmitting(true)
    try{
      text_input_validation(userData?.verification_code)

        const data = {
            email: userData?.email,
            password: userData?.password,
            verification_code: userData?.verification_code
        }
        const response = await api.post("/login",data)
        if(response.status === 200){
            toast.success("Logged in successfully")
            localStorage.setItem("access_token", response.data.access_token)
            localStorage.setItem("refresh_token", response.data.refresh_token)
            router.push(redirectUrl || "/home")
        }else{
            toast.error("Error while logging in",{description: response.data.detail})
        }
    }
    catch(error:any){
      // Keep the address. The code is spent by any attempt that reached the password check, so ask for a new one
      // (before, the whole form was emptied and a retry with the same code said "Invalid verification code").
      setUserData({ ...emptyLoginUserData, email: userData?.email ?? "" })
      const apiError = showErrorToast(error, "Error while logging in");
      if (apiError.status === 400) {
        countdown.stop()
        toast.info("Each verification code works once: request a new code, then sign in again.")
      }
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
            <CardTitle className="text-2xl font-bold">DevSec Shield </CardTitle>
          </div>
          {/* === END: UPDATED LOGO/TITLE SECTION === */}
          <CardDescription>
            {method === "login" ? "Don't have an account yet?" : "Already have an account?"}{" "}
            {method=="login" && <Link href="/register" className="text-primary hover:underline">
              Sign up
            </Link>}
            {method=="signup" && <Link href="/login" className="text-primary hover:underline">
              Login
            </Link>}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <form onSubmit={method === "login" ? handleLogin : handleRegister} className="space-y-4">

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
                  autoComplete={method === "login" ? "current-password" : "new-password"}
                  aria-describedby={method === "signup" ? "password-rules" : undefined}
                  placeholder="Password"
                  className="pl-9"
                  value={userData?.password}
                  onChange={(e) => setUserData({...userData, password: e.target.value})}
                  required
                />
              </div>
              {method === "signup" && (
                <p id="password-rules" className="text-xs text-muted-foreground">{NEW_PASSWORD_HINT}</p>
              )}
            </div>

            {/* first name section*/}
            {method === "signup" && (
              <div className="space-y-2">
                <Label htmlFor="first_name">First Name</Label>
                <Input
                  id="first_name"
                  type="text"
                  autoComplete="given-name"
                  placeholder="First Name"
                  className="pl-2"
                  value={userData?.first_name}
                  onChange={(e) => setUserData({...userData, first_name: e.target.value})}
                  required
                />
              </div>
            )}
            {/* last name section */}
            {method === "signup" && (
              <div className="space-y-2">
                <Label htmlFor="last_name">Last Name</Label>
                <Input
                  id="last_name"
                  type="text"
                  autoComplete="family-name"
                  placeholder="Last Name"
                  className="pl-2"
                  value={userData?.last_name}
                  onChange={(e) => setUserData({...userData, last_name: e.target.value})}
                  required
                />
              </div>
            )}
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
                    disabled={countdown.running || sendingCode}
                    className="w-fit cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed text-sm items-center ml-auto flex flex-row gap-2 hover:text-blue-300 hover:underline" onClick={handleSendVerificationCode}>
                    {resendLabel(sendingCode, countdown.left)} <ArrowUpRight size={18}/>
                  </button>
                </div>
              </div>
  
            
            {/* submit button */}
            <Button type="submit" className="w-full cursor-pointer" disabled={submitting}>
              {submitting
                ? (method === "login" ? "Logging in..." : "Creating account...")
                : (method === "login" ? "Login" : "Register")}
            </Button>

            {/* forgot password section */}
            <div className="flex items-center w-full justify-center text-sm">
              {method === "login" && <Link href="/password_reset" className="text-primary hover:underline">
                Forgot Password?
              </Link>}
            </div>
          </form>
          
        </CardContent>
      </Card>
    </div>
  )
}

