import { vi } from "vitest";

/** Shared test doubles. Only the browser boundaries are replaced: Supabase auth, the router and fetch. */
export const supabase = {
  getSession: vi.fn(),
  signOut: vi.fn(),
};

export const router = {
  replace: vi.fn(),
};

export const API_URL = "http://api.test";

export function signedIn() {
  supabase.getSession.mockResolvedValue({ data: { session: { access_token: "test-token" } } });
}

export function signedOut() {
  supabase.getSession.mockResolvedValue({ data: { session: null } });
}

export function json(status: number, body?: unknown): Response {
  if (status === 204) return new Response(null, { status });
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const ME = { id: "11111111-2222-3333-4444-555555555555", email: "ada@example.com", display_name: null };
