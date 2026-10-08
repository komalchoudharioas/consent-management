// Thin typed fetch wrapper over the Consent Manager REST API.
// Every path is rooted at /consent/v1 (the backend router prefix). Admin calls
// carry the Keycloak bearer token; the subject/consent-request flow reuses the
// authenticated subject's token.
import { getConfig, getToken, refreshToken } from "../auth";
import type {
  Artefact,
  AweTask,
  ConsentRequest,
  DecisionLog,
  PagedTasks,
  Paginated,
  Partner,
  PartnerCreate,
  PartnerPolicy,
  PartnerUpdate,
  PolicyUpsert,
  RevokeResponse,
} from "./types";

export class ApiError extends Error {
  status: number;
  reason?: string;
  constructor(status: number, message: string, reason?: string) {
    super(message);
    this.status = status;
    this.reason = reason;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  await refreshToken();
  const base = getConfig().apiBaseUrl.replace(/\/$/, "");
  const res = await fetch(`${base}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${getToken()}`,
      ...(init.headers ?? {}),
    },
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const body = text ? JSON.parse(text) : undefined;
  if (!res.ok) {
    const detail = body?.detail ?? body?.error ?? body?.message ?? res.statusText;
    const reason = body?.reason_code ?? body?.reason;
    throw new ApiError(res.status, typeof detail === "string" ? detail : JSON.stringify(detail), reason);
  }
  return body as T;
}

const V1 = "/consent/v1";

export const api = {
  // ── Partners (admin) ───────────────────────────────────────────────
  listPartners: () => request<Partner[]>(`${V1}/partners`),
  getPartner: (id: string) => request<Partner>(`${V1}/partners/${id}`),
  createPartner: (data: PartnerCreate) =>
    request<Partner>(`${V1}/partners`, { method: "POST", body: JSON.stringify(data) }),
  updatePartner: (id: string, data: PartnerUpdate) =>
    request<Partner>(`${V1}/partners/${id}`, { method: "PATCH", body: JSON.stringify(data) }),

  // Policy (versioned). putPolicy returns the new version — `pending` if it
  // widened access and AWE approval is enabled, else `active`.
  getPolicy: (id: string) => request<PartnerPolicy>(`${V1}/partners/${id}/policy`),
  listPolicies: (id: string) => request<PartnerPolicy[]>(`${V1}/partners/${id}/policies`),
  putPolicy: (id: string, data: PolicyUpsert) =>
    request<PartnerPolicy>(`${V1}/partners/${id}/policy`, { method: "PUT", body: JSON.stringify(data) }),

  // ── Decisions (admin status/audit view) ────────────────────────────
  listDecisions: (params: { partner_id?: string; decision?: string; limit?: number } = {}) => {
    const q = new URLSearchParams();
    if (params.partner_id) q.set("partner_id", params.partner_id);
    if (params.decision) q.set("decision", params.decision);
    q.set("limit", String(params.limit ?? 50));
    return request<DecisionLog[]>(`${V1}/decisions?${q.toString()}`);
  },

  // ── AWE approvals (approver inbox — proxied to AWE with the approver JWT) ──
  listMyTasks: (params: { status?: string; page?: number; page_size?: number } = {}) => {
    const q = new URLSearchParams();
    q.set("status", params.status ?? "open");
    q.set("page", String(params.page ?? 1));
    q.set("page_size", String(params.page_size ?? 25));
    return request<PagedTasks>(`${V1}/awe/tasks?${q.toString()}`);
  },
  submitTaskDecision: (taskId: string, action: "approve" | "reject" | "abstain", comment?: string) =>
    request<unknown>(`${V1}/awe/tasks/${taskId}/decision`, {
      method: "POST",
      body: JSON.stringify({ action, comment: comment ?? null }),
    }),
  claimTask: (taskId: string) =>
    request<AweTask>(`${V1}/awe/tasks/${taskId}/claim`, { method: "POST" }),
  getAweRequest: (requestId: string) => request<unknown>(`${V1}/awe/requests/${requestId}`),

  // ── Subject rights (transparency dashboard) ────────────────────────
  myConsents: (status?: string) =>
    request<Paginated<Artefact>>(
      `${V1}/my/consents${status ? `?status=${encodeURIComponent(status)}` : ""}`
    ).then((p) => p.items),
  myConsent: (id: string) => request<Artefact>(`${V1}/my/consents/${id}`),
  revokeMyConsent: (id: string) =>
    request<RevokeResponse>(`${V1}/my/consents/${id}/revoke`, {
      method: "POST",
      body: JSON.stringify({ originated_by: "subject" }),
    }),

  // ── Consent request (originate / redirect flow) ────────────────────
  getConsentRequest: (id: string) => request<ConsentRequest>(`${V1}/consent-requests/${id}`),

  // What is being ASKED of me, as opposed to /my/consents which is what I have
  // already agreed to. Scoped to the caller by the token, so it takes no
  // subject argument. Defaults to pending server-side.
  // "all" means every status; absent would mean pending, which is the route's
  // own default. These return the ENVELOPE, not just the items: a subject can
  // have hundreds of rows, so `total` is the only honest source for a count and
  // for saying how much of the history is on screen.
  myConsentRequestsPage: (status = "pending", size = 100) =>
    request<Paginated<ConsentRequest>>(
      `${V1}/my/consent-requests?status=${encodeURIComponent(status || "all")}&size=${size}`
    ),

  // view "consents" drops the access records each partner fetch writes under
  // a decision; "all" is every row.
  myConsentsPage: (status?: string, size = 100, view: "all" | "consents" = "all") =>
    request<Paginated<Artefact>>(
      `${V1}/my/consents?size=${size}&view=${view}${
        status ? `&status=${encodeURIComponent(status)}` : ""
      }`
    ),
  myConsentActivity: (id: string) => request<Artefact[]>(`${V1}/my/consents/${id}/activity`),
  // The subject authenticates by presenting their IdP id_token, then approves
  // with the scopes they agree to share.
  authenticateConsentRequest: (id: string, idToken: string) =>
    request<{ token_validated: boolean }>(`${V1}/consent-requests/${id}/authenticate`, {
      method: "POST",
      body: JSON.stringify({ id_token: idToken }),
    }),
  // …or, when the partner's policy requires it, by entering a one-time code.
  // Both paths end in the same AuthContext; approve refuses without one.
  issueConsentOtp: (id: string) =>
    request<{ otp_channel: string | null; otp_expires_at: string | null }>(
      `${V1}/consent-requests/${id}/otp`,
      { method: "POST" },
    ),
  verifyConsentOtp: (id: string, otp: string) =>
    request<{ auth_method: string | null }>(`${V1}/consent-requests/${id}/verify-otp`, {
      method: "POST",
      body: JSON.stringify({ otp }),
    }),
  approveConsentRequest: (id: string, grantedScopes: string[]) =>
    request<Artefact>(`${V1}/consent-requests/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ granted_scopes: grantedScopes }),
    }),
  denyConsentRequest: (id: string, reason?: string) =>
    request<ConsentRequest>(`${V1}/consent-requests/${id}/deny`, {
      method: "POST",
      body: JSON.stringify({ reason: reason ?? null }),
    }),
};
