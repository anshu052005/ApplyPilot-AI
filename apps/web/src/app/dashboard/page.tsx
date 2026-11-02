"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ApiError, apiFetch } from "@/lib/api/client";
import { getSupabase } from "@/lib/supabase/client";

type Me = { id: string; email: string | null; display_name: string | null };

export default function DashboardPage() {
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const { data } = await getSupabase().auth.getSession();
      if (!data.session) {
        router.replace("/login");
        return;
      }
      try {
        const profile = await apiFetch<Me>("/api/v1/auth/me");
        if (!cancelled) setMe(profile);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          await getSupabase().auth.signOut();
          router.replace("/login");
          return;
        }
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not load your profile.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [router]);

  async function signOut() {
    await getSupabase().auth.signOut();
    router.replace("/login");
  }

  async function deleteAccount() {
    const confirmed = window.confirm(
      "Delete your ApplyPilot account and all of your data? This cannot be undone.",
    );
    if (!confirmed) return;
    setBusy(true);
    setError(null);
    try {
      await apiFetch<void>("/api/v1/auth/account", { method: "DELETE" });
      await getSupabase().auth.signOut();
      router.replace("/register");
    } catch (err) {
      setBusy(false);
      setError(err instanceof Error ? err.message : "Account deletion failed.");
    }
  }

  return (
    <main className="mx-auto max-w-3xl px-4 py-10">
      <header className="mb-8 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">ApplyPilot AI</h1>
        <button onClick={signOut} className="rounded-md border border-slate-300 px-3 py-1.5 text-sm">
          Sign out
        </button>
      </header>

      {error && (
        <p role="alert" className="mb-4 text-sm text-red-700">
          {error}
        </p>
      )}

      <section aria-label="Account" className="rounded-lg border border-slate-200 bg-white p-6">
        <h2 className="mb-3 text-lg font-medium">Account</h2>
        {me ? (
          <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm">
            <dt className="text-slate-500">Email</dt>
            <dd>{me.email ?? "—"}</dd>
            <dt className="text-slate-500">User ID</dt>
            <dd className="font-mono text-xs">{me.id}</dd>
          </dl>
        ) : (
          <p className="text-sm text-slate-500">Loading your account…</p>
        )}
      </section>

      <section aria-label="Danger zone" className="mt-6 rounded-lg border border-red-200 bg-white p-6">
        <h2 className="mb-2 text-lg font-medium">Delete account</h2>
        <p className="mb-4 text-sm text-slate-600">
          Removes your sign-in and all ApplyPilot data associated with it.
        </p>
        <button
          onClick={deleteAccount}
          disabled={busy || !me}
          className="rounded-md bg-red-700 px-4 py-2 text-sm text-white disabled:opacity-60"
        >
          {busy ? "Deleting…" : "Delete my account"}
        </button>
      </section>
    </main>
  );
}
