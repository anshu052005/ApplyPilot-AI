import { ApiError, apiRequest } from "@/lib/api/client";

/**
 * Outcome of one account-deletion request. Only "deleted" means the account is gone.
 * Every other outcome leaves the user signed in and must not be shown as success.
 */
export type DeletionResult =
  | { kind: "deleted" }
  | { kind: "pending"; message: string }
  | { kind: "locked"; message: string }
  | { kind: "unauthenticated" }
  | { kind: "error"; message: string };

export const PENDING_MESSAGE =
  "Deletion has started but has not finished. Your data stays locked until it completes. Retry to continue.";
export const LOCKED_MESSAGE =
  "Your account is locked while its deletion is being processed. Your data is not available until it completes.";
export const NETWORK_MESSAGE =
  "We could not reach the server, so we cannot confirm the deletion. Nothing has been reported as deleted. Retry when you are connected.";

/** Maps DELETE /api/v1/auth/account to one outcome per response. Fails closed on anything unexpected. */
export async function requestAccountDeletion(): Promise<DeletionResult> {
  try {
    const { status } = await apiRequest("/api/v1/auth/account", { method: "DELETE" });
    if (status === 204) return { kind: "deleted" };
    if (status === 202) return { kind: "pending", message: PENDING_MESSAGE };
    return { kind: "error", message: `Unexpected response from the server (${status}). Nothing has been reported as deleted.` };
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.status === 423) return { kind: "locked", message: LOCKED_MESSAGE };
      if (err.status === 401) return { kind: "unauthenticated" };
      return { kind: "error", message: `${err.message}. Nothing has been reported as deleted.` };
    }
    return { kind: "error", message: NETWORK_MESSAGE };
  }
}
