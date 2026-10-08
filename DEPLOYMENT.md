# Consent Manager — Deployment & Setup (DevOps)

How to deploy the Consent Manager (CM) so that **everything works**: the core
consent/PDP API, the subject consent screen (with its optional OTP step) and
the AWE approval workflow.

This is the operator's guide. For local hacking see `RUN-LOCAL.md`.

---

## 1. What CM depends on

CM is **not standalone**. Before it is useful, these must be running and
reachable *from the CM container*:

| Dependency | Why CM needs it | If missing |
|---|---|---|
| **PostgreSQL** | CM's own database | won't start (migrate fails) |
| **Partner Management (PM)** | source of partner public keys (`/keys/{ref}`) | signature verification fails **closed** → every partner fetch denied |
| **Keycloak** (realm `staff`) | staff/approver login + AWE service tokens | admin & approver endpoints 401; AWE auth fails |
| **AWE** (Approval Workflow Engine) | approves *widening* policy changes | Approvals screen & `/awe/tasks` 500 |

> **Networking rule that bites everyone:** the addresses in `backend/.env` are
> **docker-network service names** (`db`, `keycloak`, `awe`,
> `commons-services-pm-partner-api`). They only
> resolve because the CM backend joins the shared external network
> `openg2p-developer_default` (see `docker-compose.yml`). **All the services
> above must be on that same network/host**, or CM cannot reach them. On
> Kubernetes, use the in-cluster service DNS instead.

---

## 2. How configuration works (read this before editing anything)

- **`backend/.env` is the single source of truth.** `docker-compose.yml` loads
  it into the `backend` service via `env_file: [backend/.env]`. Edit a value
  there and `docker compose up -d` to apply it.
- **One value is NOT in `.env`: the signing-key PEM.** A PEM needs real
  newlines, which an `env_file` cannot carry, so
  `CONSENT_MANAGER_CM_SIGNING_PRIVATE_KEY_PEM` stays inline in
  `docker-compose.yml` (YAML block scalar). Replace it for production.
- **Precedence gotcha:** values in a compose `environment:` block **override**
  `env_file`. Do **not** re-add config keys to `environment:` — they would
  silently shadow `backend/.env`. (This is exactly why editing `.env` used to
  "do nothing" — the old compose hard-coded everything inline.)
- `backend/.env.example` documents every variable. Copy it to `backend/.env`
  and fill in the environment-specific values (marked `CHANGE ME`).

---

## 3. Feature flags — turn these ON for a full deployment

All default to a *safe/minimal* value. For a deployment where approvals must
work, set:

```bash
# AWE: gate widening policy changes behind approval
CONSENT_MANAGER_AWE_ENABLED=true
CONSENT_MANAGER_AWE_BASE_URL=http://awe:8000    # reachable AWE, no trailing slash
CONSENT_MANAGER_AWE_TOKEN_URL=<keycloak>/realms/staff/protocol/openid-connect/token
CONSENT_MANAGER_AWE_CLIENT_SECRET=<dev client secret>
CONSENT_MANAGER_AWE_CALLBACK_URL=http://consent-manager-api:8000/consent/v1/awe/webhooks/decision
CONSENT_MANAGER_AWE_CALLBACK_SECRET_ID=<registered in AWE>
CONSENT_MANAGER_AWE_CALLBACK_HMAC_SECRET=<matches AWE>

# Real auth (required for the Approvals screen — the approver's RS256 token is
# forwarded to AWE; an unsigned dev token is rejected)
CONSENT_MANAGER_AUTH_ENABLED=true
CONSENT_MANAGER_AUTH_ISSUER=<keycloak>/realms/staff
CONSENT_MANAGER_AUTH_JWKS_URL=<keycloak>/realms/staff/protocol/openid-connect/certs
```

> **AWE issuer gotcha:** AWE validates the token `iss`. If tokens are minted via
> `keycloak:8080` but AWE expects `localhost:8080` (or vice-versa), it rejects
> them with *Invalid issuer*. In compose, `extra_hosts: localhost:host-gateway`
> lets `localhost:8080` inside the container reach Keycloak on the host so the
> issuer matches — keep `AUTH_ISSUER`/`AWE_TOKEN_URL` consistent with what AWE
> expects. On K8s, make both use the same in-cluster Keycloak URL.

---

## 4. Deploy with Docker Compose

```bash
# 0. Prereqs: Docker; the openg2p-developer stack (Postgres peers, Keycloak, PM,
#    AWE) already up, creating the network openg2p-developer_default.

# 1. Configure
cp backend/.env.example backend/.env
#   edit backend/.env: set the flags in §3, secrets, and the real
#   Keycloak/AWE/PM addresses for THIS environment.

# 2. (prod) replace the signing key in docker-compose.yml
#   CONSENT_MANAGER_CM_SIGNING_PRIVATE_KEY_PEM: your own Ed25519/EC/RSA PEM.

# 3. Build & start (build arg pins the framework ref; see Dockerfile)
docker compose build
docker compose up -d

# 4. Confirm the config actually resolved (should print AWE_ENABLED: "true")
docker compose config | grep -E 'AWE_ENABLED'
```

Services & ports (from `docker-compose.yml`):

| Service | Container | Host port |
|---|---|---|
| backend (API) | `consent-manager-backend-1` | `8000` |
| frontend (UI) | `consent-manager-frontend-1` | `${CM_UI_PORT:-3002}` |
| db | `consent-manager-db-1` | `5434` → 5432 |

The UI reads Keycloak settings at runtime from `ui/public/config.json` (mounted,
no rebuild) — point it at this environment's Keycloak or the login/approvals
flow won't work.

---

## 5. Verify

```bash
# API up
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8000/ping                       # 200

# Core PDP route
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8000/consent/v1/partners        # 200

# AWE approvals reachable (needs AWE up + a real approver token)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8000/consent/v1/awe/tasks        # 200 (not 500)

# DB schema created
docker exec consent-manager-db-1 psql -U postgres -d consent_manager_db \
  -tAc "SELECT count(*) FROM pg_tables WHERE schemaname='public'"                          # > 0
```

---

## 6. Troubleshooting — the failures we actually hit

| Symptom | Cause | Fix |
|---|---|---|
| `/consent/v1/awe/tasks` → **500** `awe_base_url is not configured` | `AWE_BASE_URL` empty at runtime | set `AWE_BASE_URL` (and `AWE_ENABLED=true`), restart |
| Edited `backend/.env` but nothing changed | a compose `environment:` block is shadowing `env_file` | remove the key from `environment:` (keep only the PEM) |
| Partner fetch always denied / `signature_invalid` | `PARTNER_MGMT_API_URL` empty/unreachable, or the partner's key not registered in PM | wire PM; register the partner's key |
| AWE rejects token: *Invalid issuer* / *alg not allowed* | issuer mismatch, or UI issuing unsigned `alg:none` dev token | align `AUTH_ISSUER`/`AWE_TOKEN_URL`; point the UI `config.json` at real Keycloak |
| Container can't resolve `awe`/`keycloak`/registry names | CM not on `openg2p-developer_default`, or those services not running | ensure the shared external network + dependencies are up |
| Widening policy saved but stays `pending` forever | AWE decision webhook never reaches CM | set `AWE_CALLBACK_URL` to a CM address AWE can reach; secrets must match |

---

## 7. Kubernetes (Helm)

A chart ships under `deployment/charts/openg2p-consent-manager`. The same
config keys apply (as chart values / env). Use in-cluster service DNS for every
address, supply the signing key via a Secret (`signingKey.mode`), and set the
same feature flags from §3.
