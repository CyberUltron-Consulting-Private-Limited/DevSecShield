import axios from "axios";
// Base URL can be configured via env; falls back to local FastAPI server
// let backendURL = "http://127.0.0.1:8081"; // for local deveslopment
const backendURL = "https://devsecshieldapi.zeroshield.ai";



export const apiBaseURL = backendURL;
console.log("api base url : ", apiBaseURL);


const api = axios.create({
  baseURL: apiBaseURL,
});

export function getAccessToken() {
  try {
    return typeof window !== "undefined" ? localStorage.getItem("access_token") : null;
  } catch {
    return null;
  }
}

export function getRefreshToken() {
  try {
    return typeof window !== "undefined" ? localStorage.getItem("refresh_token") : null;
  } catch {
    return null;
  }
}

function setAccessToken(token) {
  try {
    if (typeof window !== "undefined" && token) {
      localStorage.setItem("access_token", token);
    }
  } catch {
    // ignore storage errors
  }
}

    

// Request interceptor: attach Authorization header as expected by backend
api.interceptors.request.use(
  (config) => {
    const accessToken = getAccessToken();
    if (accessToken) {
    config.headers["Authorization"] = `Bearer ${accessToken}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: on 401, attempt one-time refresh then retry original request
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Only handle unauthorized responses
    const status = error?.response?.status;

    if ((status === 401) && !originalRequest._retry) {
      originalRequest._retry = true

      try {
        const refreshToken = getRefreshToken();
        if (!refreshToken) {
          window.location.href = "/login";
          localStorage.removeItem("access_token");
          localStorage.removeItem("refresh_token");
          return Promise.reject(error);
        }

        // Request new access token
        const refreshResp = await api.post("/refresh", { refresh_token: refreshToken });
        const newAccessToken = refreshResp?.data?.access_token;

        if (!newAccessToken) {
          window.location.href = "/login";
          localStorage.removeItem("access_token");
          localStorage.removeItem("refresh_token");
          return Promise.reject(error);
        }

        setAccessToken(newAccessToken);

        // Update Authorization header and retry original request
        originalRequest.headers = originalRequest.headers || {};
        originalRequest.headers["Authorization"] = `Bearer ${newAccessToken}`;

        return api(originalRequest);
      } catch (refreshErr) {
        window.location.href = "/login";
        localStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
        return Promise.reject(refreshErr);
      }
    }

    return Promise.reject(error);
  }
);

export default api;


