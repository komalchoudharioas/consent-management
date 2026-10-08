import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import type { Artefact, ConsentRequest, Purpose } from "../api/types";

export function purposeLabel(purpose: Purpose): string {
  return (
    (purpose?.name as string) ||
    (purpose?.description as string) ||
    (purpose?.code as string) ||
    "data sharing"
  );
}

// A decision the subject has made, or is being asked to make. The two live in
// DIFFERENT tables and that is not an accident: declining never mints a consent
// artefact, so a declined request exists only as a request. Listing "all my
// consents" therefore means merging two sources, and a page that reads only the
// artefacts can never show a decline however it is filtered.
type Row =
  | { kind: "request"; id: string; status: string; partner: string; purpose: Purpose;
      scopes: string[]; at: string; req: ConsentRequest }
  | { kind: "artefact"; id: string; status: string; partner: string; purpose: Purpose;
      scopes: string[]; at: string; validUntil?: string | null; art: Artefact };

// What a partner's fetches write under the subject's one decision. Shown as
// the consent's history by default; as their own rows when asked for.
const RECORD_LABEL: Record<string, string> = {
  access: "Data access",
};

type FilterKey = "all" | "pending" | "active" | "denied" | "revoked" | "expired";

type Source = "requests" | "artefacts";

const FILTERS: {
  key: FilterKey;
  label: string;
  hint: string;
  // Which table answers this option. `all` reads both; every other option reads
  // exactly one, because a status belongs to one or the other and never both.
  from: Source[];
}[] = [
  { key: "all", label: "All", hint: "Everything asked of you and everything you decided",
    from: ["requests", "artefacts"] },
  { key: "pending", label: "Awaiting your decision", hint: "Asked, not yet answered",
    from: ["requests"] },
  { key: "active", label: "Granted", hint: "Currently being shared",
    from: ["artefacts"] },
  { key: "denied", label: "Declined", hint: "You refused these — nothing was shared",
    from: ["requests"] },
  { key: "revoked", label: "Withdrawn", hint: "Granted, then taken back",
    from: ["artefacts"] },
  { key: "expired", label: "Expired", hint: "Ran past their validity",
    from: ["requests", "artefacts"] },
];

export default function MyConsentsPage() {
  const qc = useQueryClient();
  const [filter, setFilter] = useState<FilterKey>("all");
  // Every fetch a partner makes under a consent writes an access record. By
  // default those sit under the consent as its history; this puts them back
  // in the list as rows of their own.
  const [showSystem, setShowSystem] = useState(false);
  const view = showSystem ? "all" : "consents";

  const active = FILTERS.find((f) => f.key === filter) ?? FILTERS[0];
  const wants = (src: Source) => active.from.includes(src);

  const requests = useQuery({
    queryKey: ["my-consent-requests", filter],
    enabled: wants("requests"),
    queryFn: () => api.myConsentRequestsPage(filter === "all" ? "all" : filter),
  });
  const artefacts = useQuery({
    queryKey: ["my-consents", filter, view],
    enabled: wants("artefacts"),
    queryFn: () => api.myConsentsPage(filter === "all" ? undefined : filter, 100, view),
  });

  // Counts for the menu. One cheap size=1 call per option reads `total`, which
  // is the only number that reflects the whole history rather than the page.
  const counts = useQuery({
    queryKey: ["my-consent-counts", view],
    queryFn: async () => {
      const out: Record<string, number> = {};
      for (const f of FILTERS) {
        let n = 0;
        if (f.from.includes("requests")) {
          n += (await api.myConsentRequestsPage(f.key === "all" ? "all" : f.key, 1)).total;
        }
        if (f.from.includes("artefacts")) {
          n += (await api.myConsentsPage(f.key === "all" ? undefined : f.key, 1, view)).total;
        }
        // An approved request and the artefact it minted are one decision, so
        // "all" would otherwise count every granted consent twice.
        if (f.key === "all") {
          n -= (await api.myConsentRequestsPage("approved", 1)).total;
        }
        out[f.key] = n;
      }
      return out;
    },
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeMyConsent(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["my-consents"] });
      qc.invalidateQueries({ queryKey: ["my-consent-counts"] });
      qc.invalidateQueries({ queryKey: ["my-consent-activity"] });
    },
  });

  const rows: Row[] = [
    // An approved request is the same decision as the artefact it minted, so
    // showing both would double every granted consent. The artefact wins: it
    // carries the effective scopes and the withdrawal.
    ...(wants("requests") ? requests.data?.items ?? [] : [])
      .filter((r) => r.status !== "approved")
      .map<Row>((r) => ({
        kind: "request", id: r.id, status: r.status, partner: r.partner_id,
        purpose: r.purpose, scopes: r.requested_scopes,
        at: r.created_at ?? "", req: r,
      })),
    ...(wants("artefacts") ? artefacts.data?.items ?? [] : []).map<Row>((a: Artefact) => ({
      kind: "artefact", id: a.id, status: a.status, partner: a.partner_id,
      purpose: a.purpose, scopes: a.effective_data_scopes,
      at: a.created_at ?? "", validUntil: a.valid_until, art: a,
    })),
  ].sort((x, y) => (y.at || "").localeCompare(x.at || ""));

  const total = counts.data?.[filter] ?? rows.length;
  const count = (k: FilterKey) => counts.data?.[k] ?? 0;
  const shown = rows;

  const loading =
    (wants("requests") && requests.isLoading) || (wants("artefacts") && artefacts.isLoading);
  const failed =
    (wants("requests") && requests.error) || (wants("artefacts") && artefacts.error);

  return (
    <div>
      <div className="spread" style={{ alignItems: "flex-start" }}>
        <div>
          <h1 style={{ marginBottom: 4 }}>My consents</h1>
          <p className="muted" style={{ marginTop: 0, marginBottom: 24 }}>
            Everything organisations have asked of you, and what you decided. You can withdraw a
            granted consent at any time — sharing stops immediately and all parties are notified.
          </p>
        </div>
        <FilterMenu value={filter} onChange={setFilter} count={count} />
      </div>

      <label className="system-toggle">
        <input
          type="checkbox"
          checked={showSystem}
          onChange={(e) => setShowSystem(e.target.checked)}
        />
        Show system records
        <span className="muted">
          — the data-access records behind each consent, as separate rows
        </span>
      </label>

      {loading && <div className="loading">Loading…</div>}
      {failed && <div className="notice notice-error">Could not load your consents.</div>}

      {!loading && !failed && shown.length === 0 && (
        <div className="card">
          {filter === "all"
            ? "Nobody has asked to use your data yet."
            : `Nothing here — you have no ${active.label.toLowerCase()} consents.`}
        </div>
      )}

      {!loading && !failed && shown.length > 0 && total > shown.length && (
        <p className="muted" style={{ fontSize: 13 }}>
          Showing the {shown.length} most recent of {total}.
        </p>
      )}

      {shown.map((row) =>
        row.kind === "request" ? (
          <RequestCard key={row.id} row={row} />
        ) : (
          <ArtefactCard
            key={row.id}
            row={row}
            onRevoke={() => revoke.mutate(row.id)}
            revoking={revoke.isPending}
          />
        )
      )}
    </div>
  );
}

/** Filter icon + menu. Built rather than using a <select> because the options
 *  carry a count and a line of explanation, which a native select cannot show. */
function FilterMenu({
  value,
  onChange,
  count,
}: {
  value: FilterKey;
  onChange: (k: FilterKey) => void;
  count: (k: FilterKey) => number;
}) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);

  // A menu that can only be closed by choosing something is a trap, so an
  // outside click and Escape both dismiss it.
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("keydown", esc);
    };
  }, [open]);

  const active = FILTERS.find((f) => f.key === value) ?? FILTERS[0];

  return (
    <div className="filter-menu" ref={box}>
      <button
        className="btn-secondary filter-trigger"
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        <svg width="15" height="15" viewBox="0 0 16 16" aria-hidden="true">
          <path
            d="M1.5 3h13M4 8h8m-5.5 5h3"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinecap="round"
            fill="none"
          />
        </svg>
        {active.label}
        <span className="filter-count">{count(value)}</span>
      </button>

      {open && (
        <div className="filter-list" role="menu">
          {FILTERS.map((f) => (
            <button
              key={f.key}
              role="menuitemradio"
              aria-checked={f.key === value}
              className={`filter-option${f.key === value ? " selected" : ""}`}
              onClick={() => {
                onChange(f.key);
                setOpen(false);
              }}
            >
              <div className="filter-option-main">
                <span>{f.label}</span>
                <span className="filter-count">{count(f.key)}</span>
              </div>
              <div className="filter-option-hint">{f.hint}</div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/** A request the subject has not granted — pending, declined or expired.
 *
 * Deliberately NOT a second place to grant. `/consent/:requestId` already owns
 * that decision: the OTP, the ID-token fallback, the partner's policy and the
 * wording shown to the subject. A copy here would be a second thing to keep in
 * step with the policy rules, which is exactly where a consent screen must not
 * drift.
 */
function RequestCard({ row }: { row: Extract<Row, { kind: "request" }> }) {
  const pending = row.status === "pending";
  return (
    <div className="card">
      <div className="spread" style={{ marginBottom: 12 }}>
        <div>
          <h3 style={{ margin: 0 }}>{row.partner}</h3>
          <div className="muted">{purposeLabel(row.purpose)}</div>
        </div>
        <span className={`badge badge-${row.status}`}>
          {row.status === "denied" ? "declined" : row.status}
        </span>
      </div>

      <div className="field" style={{ margin: 0 }}>
        <label style={{ fontSize: 13 }}>
          {pending ? "Data being requested" : "Data that was requested"}
        </label>
        <div className="chips">
          {row.scopes.map((s) => (
            <span key={s} className={`chip${pending ? " selected" : ""}`}>
              {s}
            </span>
          ))}
        </div>
      </div>

      <div className="row" style={{ marginTop: 16, justifyContent: "space-between" }}>
        <span className="muted" style={{ fontSize: 13 }}>
          {pending
            ? row.req.required_auth_method === "otp"
              ? "You will be asked for a one-time code."
              : "Nothing is shared until you grant it."
            : row.status === "denied"
            ? "You declined this. Nothing was shared."
            : "This request expired without a decision."}
        </span>
        {pending && (
          <Link className="btn-primary" to={`/consent/${row.id}`} state={{ from: "my-consents" }}>
            Review and decide
          </Link>
        )}
      </div>
    </div>
  );
}

function ArtefactCard({
  row,
  onRevoke,
  revoking,
}: {
  row: Extract<Row, { kind: "artefact" }>;
  onRevoke: () => void;
  revoking: boolean;
}) {
  const [openHistory, setOpenHistory] = useState(false);
  const record = row.art.record_kind ? RECORD_LABEL[row.art.record_kind] : undefined;
  const history = row.art.activity_count ?? 0;
  return (
    <div className="card">
      <div className="spread" style={{ marginBottom: 12 }}>
        <div>
          <h3 style={{ margin: 0 }}>{row.partner}</h3>
          <div className="muted">
            {record ? `${record} · ${row.art.partner_name ?? row.partner}` : purposeLabel(row.purpose)}
          </div>
        </div>
        <div className="row" style={{ gap: 8 }}>
          {record && <span className="record-tag">{record}</span>}
          <span className={`badge badge-${row.status}`}>
            {row.status === "revoked" ? "withdrawn" : row.status}
          </span>
        </div>
      </div>

      <div className="field" style={{ margin: 0 }}>
        <label style={{ fontSize: 13 }}>
          {row.status === "active" ? "Data shared" : "Data that was shared"}
        </label>
        <div className="chips">
          {row.scopes.map((s) => (
            <span key={s} className={`chip${row.status === "active" ? " selected" : ""}`}>
              {s}
            </span>
          ))}
        </div>
      </div>

      <div className="row" style={{ marginTop: 16, justifyContent: "space-between" }}>
        <span className="muted" style={{ fontSize: 13 }}>
          {row.status === "revoked"
            ? "Withdrawn — sharing has stopped."
            : row.validUntil
            ? `Valid until ${formatDate(row.validUntil)}`
            : "No expiry set"}
        </span>
        <div className="row" style={{ gap: 8 }}>
          {history > 0 && (
            <button
              className="btn-secondary"
              onClick={() => setOpenHistory((o) => !o)}
              aria-expanded={openHistory}
            >
              {openHistory ? "Hide" : "Show"} access history ({history})
            </button>
          )}
          {row.status === "active" && (
            <button className="btn-danger" onClick={onRevoke} disabled={revoking}>
              Withdraw consent
            </button>
          )}
        </div>
      </div>

      {openHistory && <ConsentActivity consentId={row.id} />}
    </div>
  );
}

/** What was done under one consent: every time data actually moved. Read-only - the consent above is what the
 *  subject acts on, and withdrawing it is what stops all of this. */
function ConsentActivity({ consentId }: { consentId: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["my-consent-activity", consentId],
    queryFn: () => api.myConsentActivity(consentId),
  });
  if (isLoading) return <div className="loading">Loading history…</div>;
  if (error) return <div className="notice notice-error">Could not load the history.</div>;
  return (
    <table className="data activity-table">
      <thead>
        <tr>
          <th>When</th>
          <th>Record</th>
          <th>Partner</th>
          <th>Data</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {(data ?? []).map((a) => (
          <tr key={a.id}>
            <td>{formatDateTime(a.created_at)}</td>
            <td>{(a.record_kind && RECORD_LABEL[a.record_kind]) || a.source}</td>
            <td>{a.partner_name ?? a.controller_id ?? a.partner_id}</td>
            <td>{a.effective_data_scopes.join(", ")}</td>
            <td>
              <span className={`badge badge-${a.status}`}>
                {a.status === "revoked" ? "withdrawn" : a.status}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
