
import api, { retryAfterSeconds } from "@/utils/interceptors";
import { AxiosError } from "axios";
import { toast } from "sonner";

export interface ApiError {
  message: string;
  status?: number;
  details?: string;
}


let isLoggingOut = false;

export const handleLogout = async () => {
  if (isLoggingOut) return;
  isLoggingOut = true;
  try{
    const response = await api.get("/logout")
    if(response.status === 200){
      toast.success("Logged out user and session deactivated")
      localStorage.clear()
      window.location.href = "/login";
    }else{
      throw new Error(response.data.detail)
    }
  }catch(error:any){
    // On logout failure, just clear and redirect
    localStorage.clear()
    window.location.href = "/login";
  } finally {
    isLoggingOut = false;
  }
}

/** "Value error, Password must be 8 to 128 characters long" -> "Password must be 8 to 128 characters long". */
function validationMessage(detail: unknown): string | null {
  if (typeof detail === "string" && detail.trim()) return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0] as { msg?: unknown; loc?: unknown };
    if (typeof first?.msg === "string" && first.msg.trim()) {
      const msg = first.msg.replace(/^(Value error|Assertion failed), /, "");
      const loc = Array.isArray(first.loc) ? first.loc.filter((p) => p !== "body" && p !== "query" && p !== "path") : [];
      const field = loc.length ? String(loc[loc.length - 1]) : "";
      // pydantic's own messages ("String should have at most 128 characters") need the field name
      return field && !/password|email|code/i.test(msg) ? `${field.replace(/_/g, " ")}: ${msg}` : msg;
    }
  }
  return null;
}

function waitText(seconds: number): string {
  if (seconds < 60) return `${Math.max(1, Math.round(seconds))} second${Math.round(seconds) === 1 ? "" : "s"}`;
  const minutes = Math.ceil(seconds / 60);
  return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}

export const handleApiError = (error: unknown): ApiError => {
  if (error instanceof AxiosError) {
    console.log(error);
    const status = error.response?.status;
    const message = error.response?.data?.message || error.response?.data?.detail || error.message;

    if (status === 422) {
      return {
        message: validationMessage(error.response?.data?.detail) || 'Validation error. Please check your input.',
        status: 422
      };
    }
    // Handle specific status codes
    if (status === 429) {
      const wait = retryAfterSeconds(error);
      const detail = error.response?.data?.detail;
      const reason = typeof detail === "string" && detail && detail !== "Too Many Requests"
        ? detail.replace(/\s*Try again later\.?$/i, "")
        : "Too many requests.";
      return {
        message: wait != null ? `${reason} Please try again in ${waitText(wait)}.` : `${reason} Please try again later.`,
        status: 429
      };
    } else if (status === 401) {
      localStorage.clear()
      window.location.href = "/login";
      return {
        message: 'Unauthorized access. Please log in again.',
        status: 401
      };
    } else if (status === 403) {
      handleLogout();
      return {
        message: 'Access forbidden. You do not have permission to perform this action.',
        status: 403
      };
    } else if (status === 404) {
      return {
        message: 'Resource not found.',
        status: 404
      };
    } else if (status === 500) {
      return {
        message: 'Internal server error. Please try again later.',
        status: 500
      };
    } else if (status && status >= 400) {
      return {
        message: message || 'An error occurred while processing your request.',
        status
      };
    } else {
      return {
        message: message || 'Network error. Please check your connection.',
        status
      };
    }
  } else if (error instanceof Error) {
    return {
      message: error.message,
    };
  } else {
    return {
      message: 'An unexpected error occurred',
    };
  }
};

export const showErrorToast = (error: unknown, fallbackMessage?: string) => {
  const apiError = handleApiError(error);
  toast.error(apiError.message || fallbackMessage || 'An error occurred');
  return apiError;
};


export const handleApiCall = async <T>(
  apiCall: () => Promise<T>,
  options?: {
    showErrorToast?: boolean;
    fallbackMessage?: string;
    onError?: (error: ApiError) => void;
  }
): Promise<{ data?: T; error?: ApiError }> => {
  try {
    const data = await apiCall();
    return { data };
  } catch (error) {
    const apiError = handleApiError(error);
    
    if (options?.showErrorToast !== false) {
      toast.error(apiError.message || options?.fallbackMessage || 'An error occurred');
    }
    
    if (options?.onError) {
      options.onError(apiError);
    }
    
    return { error: apiError };
  }
};

