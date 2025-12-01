
import api from "@/utils/interceptors";
import { AxiosError } from "axios";
import { toast } from "sonner";

export interface ApiError {
  message: string;
  status?: number;
  details?: string;
}


export const handleLogout = async () => {
  try{
    const response = await api.get("/logout")
    if(response.status === 200){
      toast.success("Logged out user and session deactivated")
      localStorage.clear()
      window.location.assign("/login")
    }else{
      throw new Error(response.data.detail)
    }
  }catch(error:any){
    const apiError = handleApiError(error);
    showErrorToast(apiError, "Error while logging out");
  }
}

export const handleApiError = (error: unknown): ApiError => {
  if (error instanceof AxiosError) {
    const status = error.response?.status;
    const message = error.response?.data?.message || error.response?.data?.detail || error.message;
    
    // Handle specific status codes
    if (status === 429) {
      return {
        message: 'Too many requests, please try again later',
        status: 429
      };
    } else if (status === 401) {
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

