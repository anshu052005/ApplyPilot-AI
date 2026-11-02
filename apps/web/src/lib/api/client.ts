import { env } from "@/lib/env";
import { getSupabase } from "@/lib/supabase/client";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export type ApiResponse<T> = { status: number; data: T | undefined };

/**
 * Calls the FastAPI backend with the current Supabase access token and returns the HTTP status with the body.
 * Throws ApiError for any non-2xx response. Throws a TypeError when the network request itself fails.
 * Use this when the status code carries meaning (for example 202 vs 204), as account deletion does.
 */
export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<ApiResponse<T>> {
  const { data } = await getSupabase().auth.getSession();
  const token = data.session?.access_token;
  if (!token) {
    throw new ApiError(401, "Not signed in");
  }

  const response = await fetch(`${env.apiUrl}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init.headers,
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new ApiError(response.status, typeof body.detail === "string" ? body.detail : `Request failed (${response.status})`);
  }
  if (response.status === 204) {
    return { status: 204, data: undefined };
  }
  const body = (await response.json().catch(() => undefined)) as T | undefined;
  return { status: response.status, data: body };
}

/** Calls the FastAPI backend and returns the parsed body. Throws ApiError on failure. */
export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const { data } = await apiRequest<T>(path, init);
  return data as T;
}
