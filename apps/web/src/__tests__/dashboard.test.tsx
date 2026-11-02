import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import DashboardPage from "@/app/dashboard/page";
import { LOCKED_MESSAGE, NETWORK_MESSAGE, PENDING_MESSAGE } from "@/lib/account/deletion";
import { ME, json, router, signedIn, supabase } from "./support";

vi.mock("@/lib/env", async () => {
  const support = await import("./support");
  return { env: { supabaseUrl: "http://127.0.0.1:54321", supabaseAnonKey: "anon", apiUrl: support.API_URL } };
});
vi.mock("@/lib/supabase/client", () => ({ getSupabase: () => ({ auth: supabase }) }));
vi.mock("next/navigation", () => ({ useRouter: () => router }));

const fetchMock = vi.fn();

/** Routes GET /auth/me and DELETE /auth/account to the given responses, then mounts the dashboard. Each DELETE takes the next queued response. */
function serve(me: () => Response, deletes: Array<() => Response | Promise<Response>> = []) {
  mount();
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    if (init?.method === "DELETE") {
      const next = deletes.shift();
      if (!next) throw new Error("unexpected extra DELETE");
      return next();
    }
    if (String(url).endsWith("/api/v1/auth/me")) return me();
    throw new Error(`unexpected request ${String(url)}`);
  });
}

function mount() {
  return render(<DashboardPage />);
}

const deleteCalls = () => fetchMock.mock.calls.filter(([, init]) => init?.method === "DELETE").length;

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  vi.spyOn(window, "confirm").mockReturnValue(true);
  signedIn();
  supabase.signOut.mockResolvedValue({ error: null });
  router.replace.mockReset();
  supabase.signOut.mockClear();
});

afterEach(() => {
  cleanup();
  fetchMock.mockReset();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("dashboard account view", () => {
  it("shows account data when the account is ready", async () => {
    serve(() => json(200, ME));

    expect(await screen.findByText(ME.email)).toBeTruthy();
    expect(screen.getByText(ME.id)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Delete my account" })).toBeTruthy();
  });

  it("signs out and redirects when the session is rejected", async () => {
    serve(() => json(401, { detail: "Not authenticated" }));

    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login"));
    expect(supabase.signOut).toHaveBeenCalled();
  });

  it("shows the account as locked and hides its data when the account is locked (HTTP 423)", async () => {
    serve(() => json(423, { detail: "locked" }));

    expect(await screen.findByText(LOCKED_MESSAGE)).toBeTruthy();
    expect(screen.queryByText(ME.email)).toBeNull();
    expect(screen.queryByText(ME.id)).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete my account" })).toBeNull();
    expect(screen.getByRole("button", { name: "Retry deletion" })).toBeTruthy();
  });

  it("offers a try-again action when loading fails, without showing account data", async () => {
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));
    mount();

    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByText(ME.email)).toBeNull();
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
  });
});

describe("dashboard account deletion", () => {
  it("does nothing when the user cancels the confirmation", async () => {
    serve(() => json(200, ME), [() => json(204)]);
    vi.spyOn(window, "confirm").mockReturnValue(false);
    await screen.findByText(ME.email);

    fireEvent.click(screen.getByRole("button", { name: "Delete my account" }));

    expect(deleteCalls()).toBe(0);
    expect(supabase.signOut).not.toHaveBeenCalled();
  });

  it("HTTP 204: confirms deletion and signs out", async () => {
    serve(() => json(200, ME), [() => json(204)]);
    await screen.findByText(ME.email);

    fireEvent.click(screen.getByRole("button", { name: "Delete my account" }));

    expect(await screen.findByText("Your account has been deleted")).toBeTruthy();
    expect(supabase.signOut).toHaveBeenCalled();
    expect(screen.queryByText(ME.email)).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("HTTP 202: reports pending, does not sign out, does not report success, and offers retry", async () => {
    serve(() => json(200, ME), [() => json(202, { status: "pending", detail: "retry" })]);
    await screen.findByText(ME.email);

    fireEvent.click(screen.getByRole("button", { name: "Delete my account" }));

    expect(await screen.findByText(PENDING_MESSAGE)).toBeTruthy();
    expect(supabase.signOut).not.toHaveBeenCalled();
    expect(router.replace).not.toHaveBeenCalledWith("/login");
    expect(screen.queryByText("Your account has been deleted")).toBeNull();
    expect(screen.queryByText(ME.email)).toBeNull();
    expect(screen.getByRole("button", { name: "Retry deletion" })).toBeTruthy();
  });

  it("HTTP 202 then 204 on retry: completes deletion and signs out", async () => {
    serve(
      () => json(200, ME),
      [() => json(202, { status: "pending", detail: "retry" }), () => json(204)],
    );
    await screen.findByText(ME.email);
    fireEvent.click(screen.getByRole("button", { name: "Delete my account" }));
    await screen.findByRole("button", { name: "Retry deletion" });

    fireEvent.click(screen.getByRole("button", { name: "Retry deletion" }));

    expect(await screen.findByText("Your account has been deleted")).toBeTruthy();
    expect(supabase.signOut).toHaveBeenCalledTimes(1);
    expect(deleteCalls()).toBe(2);
  });

  it("HTTP 423 during deletion: shows the locked state with no account data", async () => {
    serve(() => json(200, ME), [() => json(423, { detail: "locked" })]);
    await screen.findByText(ME.email);

    fireEvent.click(screen.getByRole("button", { name: "Delete my account" }));

    expect(await screen.findByText(LOCKED_MESSAGE)).toBeTruthy();
    expect(screen.queryByText(ME.email)).toBeNull();
    expect(supabase.signOut).not.toHaveBeenCalled();
  });

  it("network error: never reports success, keeps the user signed in, and re-enables the button", async () => {
    serve(() => json(200, ME), [() => Promise.reject(new TypeError("Failed to fetch"))]);
    await screen.findByText(ME.email);

    fireEvent.click(screen.getByRole("button", { name: "Delete my account" }));

    expect(await screen.findByText(NETWORK_MESSAGE)).toBeTruthy();
    expect(screen.queryByText("Your account has been deleted")).toBeNull();
    expect(supabase.signOut).not.toHaveBeenCalled();
    expect(screen.getByText(ME.email)).toBeTruthy();
    await waitFor(() =>
      expect((screen.getByRole("button", { name: "Delete my account" }) as HTMLButtonElement).disabled).toBe(false),
    );
  });

  it("server error: shows the failure, keeps the account visible, and does not sign out", async () => {
    serve(() => json(200, ME), [() => json(500, { detail: "Storage unavailable" })]);
    await screen.findByText(ME.email);

    fireEvent.click(screen.getByRole("button", { name: "Delete my account" }));

    expect(await screen.findByText(/Storage unavailable/)).toBeTruthy();
    expect(supabase.signOut).not.toHaveBeenCalled();
    expect(screen.getByText(ME.email)).toBeTruthy();
  });

  it("HTTP 401 during deletion: signs out and redirects to login", async () => {
    serve(() => json(200, ME), [() => json(401, { detail: "Not authenticated" })]);
    await screen.findByText(ME.email);

    fireEvent.click(screen.getByRole("button", { name: "Delete my account" }));

    await waitFor(() => expect(router.replace).toHaveBeenCalledWith("/login"));
    expect(supabase.signOut).toHaveBeenCalled();
  });

  it("retry that fails with a network error stays locked and does not report success", async () => {
    serve(
      () => json(423, { detail: "locked" }),
      [() => Promise.reject(new TypeError("Failed to fetch"))],
    );
    await screen.findByRole("button", { name: "Retry deletion" });

    fireEvent.click(screen.getByRole("button", { name: "Retry deletion" }));

    expect(await screen.findByText(NETWORK_MESSAGE)).toBeTruthy();
    expect(screen.queryByText("Your account has been deleted")).toBeNull();
    expect(supabase.signOut).not.toHaveBeenCalled();
    expect(screen.queryByText(ME.email)).toBeNull();
  });
});
