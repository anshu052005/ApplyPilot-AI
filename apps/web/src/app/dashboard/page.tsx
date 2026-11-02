"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { LOCKED_MESSAGE, requestAccountDeletion, type DeletionResult } from "@/lib/account/deletion";
import { ApiError, apiFetch } from "@/lib/api/client";
import { getSupabase } from "@/lib/supabase/client";

type Me = { id: string; email: string | null; display_name: string | null };

/**
 * "ready": account data is shown. "locked": deletion is pending or in progress, so no account data is rendered
 * and only the retry and sign-out actions remain. "deleted": the account was removed and the user is signed out.
 */
type View = "loading" | "ready" | "locked" | "deleted" | "load-error";

export default function DashboardPage() {
  const router = useRouter();
  const [view, setView] = useState<View>("loading");
  const [me, setMe] = useState<Me | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loadAccount = useCallback(async () => {
    setView("loading");
    setLoadError(null);
    const { data } = await getSupabase().auth.getSession();
    if (!data.session) {
      router.replace("/login");
      return;
    }
    try {
      const profile = await apiFetch<Me>("/api/v1/auth/me");
      setMe(profile);
      setView("ready");
    } catch (err) {
      setMe(null);
      if (err instanceof ApiError && err.status === 401) {
        await getSupabase().auth.signOut();
        router.replace("/login");
        return;
      }
      if (err instanceof ApiError && err.status === 423) {
        setNotice(LOCKED_MESSAGE);
        setView("locked");
        return;
      }
      setLoadError(err instanceof Error ? err.message : "Could not load your account.");
      setView("load-error");
    }
  }, [router]);

  useEffect(() => {
    void loadAccount();
  }, [loadAccount]);

  function applyDeletion(result: DeletionResult) {
    switch (result.kind) {
      case "deleted":
        setMe(null);
        setNotice(null);
        setView("deleted");
        void getSupabase().auth.signOut();
        return;
      case "pending":
      case "locked":
        setMe(null);
        setNotice(result.message);
        setView("locked");
        return;
      case "unauthenticated":
        void getSupabase().auth.signOut().then(() => router.replace("/login"));
        return;
      case "error":
        // Keep the current view. The account is still there, so nothing is hidden or signed out.
        setNotice(result.message);
        return;
    }
  }

  async function runDeletion() {
    setBusy(true);
    setNotice(null);
    const result = await requestAccountDeletion();
    setBusy(false);
    applyDeletion(result);
  }

  function confirmAndDelete() {
    const confirmed = window.confirm(
      "Delete your ApplyPilot account and all of your data? This cannot be undone.",
    );
    if (!confirmed) return;
    void runDeletion();
  }

  async function signOut() {
    await getSupabase().auth.signOut();
    router.replace("/login");
  }

  return (
    <main className="mx-auto max-w-3xl px-4 py-10">
      <header className="mb-8 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">ApplyPilot AI</h1>
        {view !== "deleted" && (
          <button onClick={signOut} className="rounded-md border border-slate-300 px-3 py-1.5 text-sm">
            Sign out
          </button>
        )}
      </header>

      {view === "deleted" && (
        <section role="status" aria-label="Account deleted" className="rounded-lg border border-slate-200 bg-white p-6">
          <h2 className="mb-2 text-lg font-medium">Your account has been deleted</h2>
          <p className="mb-4 text-sm text-slate-600">
            Your sign-in and all ApplyPilot data associated with it were removed. You have been signed out.
          </p>
          <button onClick={() => router.replace("/register")} className="rounded-md border border-slate-300 px-3 py-1.5 text-sm">
            Create a new account
          </button>
        </section>
      )}

      {view === "loading" && <p className="text-sm text-slate-500">Loading your account…</p>}

      {view === "load-error" && (
        <div className="mb-4 flex items-center gap-4">
          <p role="alert" className="text-sm text-red-700">
            {loadError}
          </p>
          <button onClick={() => void loadAccount()} className="rounded-md border border-slate-300 px-3 py-1.5 text-sm">
            Try again
          </button>
        </div>
      )}

      {notice && (
        <p role="alert" className="mb-4 text-sm text-red-700">
          {notice}
        </p>
      )}

      {view === "ready" && me && (
        <section aria-label="Account" className="rounded-lg border border-slate-200 bg-white p-6">
          <h2 className="mb-3 text-lg font-medium">Account</h2>
          <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm">
            <dt className="text-slate-500">Email</dt>
            <dd>{me.email ?? "—"}</dd>
            <dt className="text-slate-500">User ID</dt>
            <dd className="font-mono text-xs">{me.id}</dd>
          </dl>
        </section>
      )}

      {(view === "ready" || view === "locked") && (
        <section aria-label="Danger zone" className="mt-6 rounded-lg border border-red-200 bg-white p-6">
          {view === "ready" ? (
            <>
              <h2 className="mb-2 text-lg font-medium">Delete account</h2>
              <p className="mb-4 text-sm text-slate-600">
                Removes your sign-in and all ApplyPilot data associated with it.
              </p>
              <button
                onClick={confirmAndDelete}
                disabled={busy}
                className="rounded-md bg-red-700 px-4 py-2 text-sm text-white disabled:opacity-60"
              >
                {busy ? "Deleting…" : "Delete my account"}
              </button>
            </>
          ) : (
            <>
              <h2 className="mb-2 text-lg font-medium">Deletion in progress</h2>
              <p className="mb-4 text-sm text-slate-600">
                You already asked to delete this account, so retrying does not ask again. The account stays locked until
                the deletion completes.
              </p>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => void runDeletion()}
                  disabled={busy}
                  className="rounded-md bg-red-700 px-4 py-2 text-sm text-white disabled:opacity-60"
                >
                  {busy ? "Retrying…" : "Retry deletion"}
                </button>
              </div>
            </>
          )}
        </section>
      )}
    </main>
  );
}
