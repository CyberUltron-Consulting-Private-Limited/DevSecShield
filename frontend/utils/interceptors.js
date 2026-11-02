import axios from "axios";
// Base URL: set NEXT_PUBLIC_BACKEND_URL at build time (prod) or use local default
const backendURL =
  process.env.NEXT_PUBLIC_BACKEND_URL ||
  (process.env.NODE_ENV === "production"
    ? "https://devsecshieldapi.zeroshield.ai"
    : "http://127.0.0.1:8081");



export const apiBaseURL = backendURL;
console.log("api base url : ", apiBaseURL);


const api = axios.create({
  baseURL: apiBaseURL,
});

// The refresh call goes through its own instance: it must never re-enter the 401 handler below.
const refreshClient = axios.create({
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

function sendToLogin() {
  try {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
  } catch {
    // ignore storage errors
  }
  window.location.href = "/login";
}

/** Seconds from a 429's Retry-After header (delta-seconds or HTTP date), or null. */
export function retryAfterSeconds(error) {
  const raw = error?.response?.headers?.["retry-after"];
  if (raw == null || raw === "") return null;
  const seconds = Number(raw);
  if (Number.isFinite(seconds)) return Math.max(0, seconds);
  const at = Date.parse(raw);
  return Number.isNaN(at) ? null : Math.max(0, Math.ceil((at - Date.now()) / 1000));
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const REFRESH_429_ATTEMPTS = 5;
const REFRESH_429_MAX_WAIT_S = 60;

class RefreshRejected extends Error {}

// One refresh at a time: every request that gets a 401 while a refresh is running waits for the same one.
let refreshInFlight = null;

async function requestNewAccessToken(refreshToken) {
  for (let attempt = 1; ; attempt += 1) {
    try {
      const response = await refreshClient.post("/refresh", { refresh_token: refreshToken });
      const token = response?.data?.access_token;
      if (!token) throw new RefreshRejected("no access token in the refresh response");
      return token;
    } catch (error) {
      if (error instanceof RefreshRejected) throw error;
      const status = error?.response?.status;
      if (status === 429 && attempt < REFRESH_429_ATTEMPTS) {
        // Rate limited: the refresh token is still good, so wait as told and try again (never log out here).
        const wait = Math.min(retryAfterSeconds(error) ?? 2 ** attempt, REFRESH_429_MAX_WAIT_S);
        await sleep(Math.max(1, wait) * 1000);
        continue;
      }
      if (status === 401 || status === 403) throw new RefreshRejected("the refresh token was refused");
      throw error; // 429 that never cleared, 5xx, network: keep the session, fail this request only
    }
  }
}

function refreshAccessToken(refreshToken) {
  if (!refreshInFlight) {
    refreshInFlight = requestNewAccessToken(refreshToken).finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
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

// Response interceptor: on 401, refresh once (shared by all parallel 401s) and retry the request.
// A 429 is passed through: react-query retries queries after Retry-After (utils/query_client.ts) and
// utils/error-handler.ts tells the user how long to wait.
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const status = error?.response?.status;

    if (status === 401 && originalRequest && !originalRequest._retry) {
      originalRequest._retry = true;
      const refreshToken = getRefreshToken();
      if (!refreshToken) {
        sendToLogin();
        return Promise.reject(error);
      }
      try {
        const newAccessToken = await refreshAccessToken(refreshToken);
        setAccessToken(newAccessToken);
        originalRequest.headers = originalRequest.headers || {};
        originalRequest.headers["Authorization"] = `Bearer ${newAccessToken}`;
        return api(originalRequest);
      } catch (refreshErr) {
        if (refreshErr instanceof RefreshRejected) {
          sendToLogin();
        }
        return Promise.reject(refreshErr instanceof RefreshRejected ? error : refreshErr);
      }
    }

    return Promise.reject(error);
  }
);

export default api;
