import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LOCKED_MESSAGE, NETWORK_MESSAGE, PENDING_MESSAGE, requestAccountDeletion } from "@/lib/account/deletion";
import { API_URL, json, signedIn, signedOut, supabase } from "./support";

vi.mock("@/lib/env", async () => {
  const support = await import("./support");
  return { env: { supabaseUrl: "http://127.0.0.1:54321", supabaseAnonKey: "anon", apiUrl: support.API_URL } };
});
vi.mock("@/lib/supabase/client", () => ({ getSupabase: () => ({ auth: supabase }) }));

const fetchMock = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  signedIn();
});

afterEach(() => {
  fetchMock.mockReset();
  vi.unstubAllGlobals();
});

describe("requestAccountDeletion", () => {
  it("reports deleted only for HTTP 204", async () => {
    fetchMock.mockResolvedValue(json(204));

    await expect(requestAccountDeletion()).resolves.toEqual({ kind: "deleted" });
    expect(fetchMock).toHaveBeenCalledWith(
      `${API_URL}/api/v1/auth/account`,
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("reports pending for HTTP 202, never deleted", async () => {
    fetchMock.mockResolvedValue(json(202, { status: "pending", detail: "retry" }));

    await expect(requestAccountDeletion()).resolves.toEqual({ kind: "pending", message: PENDING_MESSAGE });
  });

  it("reports locked for HTTP 423", async () => {
    fetchMock.mockResolvedValue(json(423, { detail: "locked" }));

    await expect(requestAccountDeletion()).resolves.toEqual({ kind: "locked", message: LOCKED_MESSAGE });
  });

  it("reports unauthenticated for HTTP 401", async () => {
    fetchMock.mockResolvedValue(json(401, { detail: "Not authenticated" }));

    await expect(requestAccountDeletion()).resolves.toEqual({ kind: "unauthenticated" });
  });

  it("reports an error with the server message for other failures, never deleted", async () => {
    fetchMock.mockResolvedValue(json(500, { detail: "Database unavailable" }));

    const result = await requestAccountDeletion();

    expect(result.kind).toBe("error");
    expect(result.kind === "error" && result.message).toContain("Database unavailable");
    expect(result.kind === "error" && result.message).toContain("Nothing has been reported as deleted");
  });

  it("treats an unexpected 2xx as an error, not success (fail closed)", async () => {
    fetchMock.mockResolvedValue(json(200, { ok: true }));

    const result = await requestAccountDeletion();

    expect(result.kind).toBe("error");
  });

  it("never reports deleted when the network request fails", async () => {
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));

    await expect(requestAccountDeletion()).resolves.toEqual({ kind: "error", message: NETWORK_MESSAGE });
  });

  it("reports unauthenticated without calling the API when there is no session", async () => {
    signedOut();

    await expect(requestAccountDeletion()).resolves.toEqual({ kind: "unauthenticated" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
