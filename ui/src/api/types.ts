// Types mirroring the Consent Manager backend schemas (/consent/v1/*).
// Kept intentionally close to the Pydantic models so the client stays honest.

export type PartnerStatus = "active" | "suspended";

// A "partner" in CM is a POLICY BINDING: it binds a Partner-Management partner
// (partner_mgmt_id) to a controller + data-share policy. Identity/keys live in
// PM; `name` here is just a display label.
export interface Partner {
  id: string;
  name?: string | null;
  audience: string;
  controller_id: string;
  partner_mgmt_id?: string | null;
  status: PartnerStatus;
  created_at?: string;
}

export interface PartnerCreate {
  partner_mgmt_id?: string | null;
  audience: string;
  controller_id: string;
  name?: string | null;
}

export interface PartnerUpdate {
  name?: string;
  status?: PartnerStatus;
  partner_mgmt_id?: string | null;
}

export type FetchType = "oneshot" | "periodic";

// A versioned data-share policy's lifecycle: `pending` awaits AWE approval;
// `active` is in force; `superseded`/`rejected` are historical.
export type PolicyStatus = "pending" | "active" | "superseded" | "rejected";

// Durations are ISO-8601 duration strings (e.g. "P1Y", "P30D", "PT12H"),
// matching the backend. max_fetch_frequency is likewise a string (e.g. "P1D").
export interface PolicyUpsert {
  allowed_data_scopes: string[];
  allowed_purposes: string[];
  allowed_subject_id_types: string[];
  allowed_signing_algs: string[];
  max_validity_duration?: string | null;
  fetch_type: FetchType;
  max_fetch_frequency?: string | null;
  data_life?: string | null;
  // How this partner's subjects must prove who they are on the consent
  // screen. "otp" demands a one-time code before approval; null means an
  // id_token is enough.
  required_auth_method?: AuthMethod;
  // WHY this partner may hold the data — a different question from how the
  // subject proves who they are. "consent" needs a subject grant;
  // "legitimate_interest" seeks none, and the policy's allowed_data_scopes
  // becomes the ceiling in the grant's place. For an INTERNAL partner only.
  lawful_basis?: LawfulBasis;
}

export type LawfulBasis = "consent" | "legitimate_interest";

// The backend rejects anything else rather than storing it — an unrecognised
// value would read as "no authentication required" and quietly drop a factor.
export type AuthMethod = "otp" | null;

export interface PartnerPolicy extends PolicyUpsert {
  id: string;
  partner_id: string;
  version: number;
  status: PolicyStatus;
  awe_request_id?: string | null;
  effective_from?: string | null;
}

// ── AWE approval tasks (approver inbox — proxied to AWE) ──────────────────
export interface AweTask {
  id: string;
  request_id: string;
  stage_order: number;
  assignee: string;
  status: string; // open | claimed | completed | ...
  artifact_type?: string | null;
  artifact_id?: string | null;
  policy_key?: string | null;
  context?: Record<string, unknown> | null;
  created_at: string;
  due_at?: string | null;
}

export interface PagedTasks {
  items: AweTask[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

// ── Decision log (admin status/audit view) ───────────────────────────────
export interface DecisionLog {
  id: string;
  partner_id?: string | null;
  consent_id?: string | null;
  object_jti?: string | null;
  decision: "permit" | "deny";
  reason_code: string;
  detail?: string | null;
  policy_version?: number | null;
  created_at: string;
}

// ── Subject rights (transparency dashboard) ──────────────────────────────
// Backed by ArtefactResponse. `purpose` is a structured object; the registry
// decides its shape, so we render defensively.
export type ConsentStatus = "active" | "revoked" | "expired" | "pending";

export interface Purpose {
  code?: string;
  name?: string;
  description?: string;
  [k: string]: unknown;
}

export interface Artefact {
  id: string;
  consent_id?: string | null;
  subject_id_type: string;
  subject_id_value: string;
  partner_id: string;
  purpose: Purpose;
  effective_data_scopes: string[];
  status: ConsentStatus;
  source: string;
  valid_from: string;
  valid_until: string;
  created_at: string;
  revoked_at?: string | null;
  // Subject routes only. `consent` is a decision; `access` records each time
  // data moved under one, and points at it.
  record_kind?: "consent" | "access" | null;
  derived_from?: string | null;
  activity_count?: number | null;
  partner_name?: string | null;
  controller_id?: string | null;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface RevokeResponse {
  consent_id: string;
  status: string;
  revoked_at: string;
}

// ── Consent-request (originate / redirect flow) ──────────────────────────
export interface ConsentRequest {
  id: string;
  subject_id_type: string;
  subject_id_value: string;
  partner_id: string;
  purpose: Purpose;
  requested_scopes: string[];
  status: string; // created | authenticated | approved | denied | expired
  valid_from?: string | null;
  valid_until?: string | null;
  created_at: string;
  // From the partner's policy: "otp" means this screen must collect a code
  // before it may approve. Null keeps the IdP-token path.
  required_auth_method?: string | null;
  otp_channel?: string | null;
  otp_expires_at?: string | null;
  otp_verified_at?: string | null;
}
