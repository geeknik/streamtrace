import type { ApiErrorBody } from "./types";

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/v1";
const TOKEN_KEY = "streamtrace_token";

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function buildHeaders(): HeadersInit {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };
  const token = getToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let code = "unknown";
    let message = `HTTP ${response.status}`;
    try {
      const body = (await response.json()) as { error?: ApiErrorBody };
      if (body.error) {
        code = body.error.code;
        message = body.error.message;
      }
    } catch {
      // response body was not JSON, keep defaults
    }
    throw new ApiError(response.status, code, message);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json() as Promise<T>;
}

function buildQueryString(params?: Record<string, string>): string {
  if (!params) return "";
  const filtered = Object.entries(params).filter(
    ([, v]) => v !== "" && v !== undefined && v !== null,
  );
  if (filtered.length === 0) return "";
  const qs = new URLSearchParams(filtered);
  return `?${qs.toString()}`;
}

export interface ApiClient {
  get<T>(path: string, params?: Record<string, string>): Promise<T>;
  post<T>(path: string, body: unknown): Promise<T>;
  patch<T>(path: string, body: unknown): Promise<T>;
  del(path: string): Promise<void>;
}

export const api: ApiClient = {
  async get<T>(path: string, params?: Record<string, string>): Promise<T> {
    const url = `${BASE_URL}${path}${buildQueryString(params)}`;
    const response = await fetch(url, {
      method: "GET",
      headers: buildHeaders(),
    });
    return handleResponse<T>(response);
  },

  async post<T>(path: string, body: unknown): Promise<T> {
    const url = `${BASE_URL}${path}`;
    const response = await fetch(url, {
      method: "POST",
      headers: buildHeaders(),
      body: JSON.stringify(body),
    });
    return handleResponse<T>(response);
  },

  async patch<T>(path: string, body: unknown): Promise<T> {
    const url = `${BASE_URL}${path}`;
    const response = await fetch(url, {
      method: "PATCH",
      headers: buildHeaders(),
      body: JSON.stringify(body),
    });
    return handleResponse<T>(response);
  },

  async del(path: string): Promise<void> {
    const url = `${BASE_URL}${path}`;
    const response = await fetch(url, {
      method: "DELETE",
      headers: buildHeaders(),
    });
    await handleResponse<void>(response);
  },
};
