"""Turn the one-time code on or off for a partner, and show where it stands.

The OTP is a property of the partner, not of the flow: ``required_auth_method``
on the partner's active policy decides whether the subject must enter a
one-time code on the consent screen before ``approve`` will accept their grant.

    python set-partner-otp.py                    # show every partner
    python set-partner-otp.py <audience> on
    python set-partner-otp.py <audience> off

Point it at another Consent Manager with G2P_CM (default http://localhost:8000).

Turning it OFF is a widening — the partner reaches the same data with less proof
from the subject — so with AWE enabled the new version lands ``pending`` and the
old one stays in force until it is approved. This script approves it for you and
says so. Turning it ON takes effect at once.
"""
import os
import sys
import time

import httpx

CM = os.environ.get("G2P_CM", "http://localhost:8000")
KEYCLOAK = os.environ.get(
    "G2P_KEYCLOAK", "http://localhost:8080") + "/realms/staff/protocol/openid-connect/token"


def hdr():
    r = httpx.post(KEYCLOAK, timeout=20, data={
        "grant_type": "password", "client_id": "consent-manager-ui",
        "username": "staff", "password": "staff", "scope": "openid"})
    r.raise_for_status()
    return {"Authorization": "Bearer " + r.json()["access_token"],
            "Content-Type": "application/json"}


def partners(H):
    rows = httpx.get(CM + "/consent/v1/partners", headers=H, timeout=30).json()
    return rows if isinstance(rows, list) else rows.get("items", rows.get("data", []))


def active_policy(H, pid):
    rows = httpx.get(CM + "/consent/v1/partners/%s/policies" % pid,
                     headers=H, timeout=30).json()
    rows = rows if isinstance(rows, list) else rows.get("items", rows.get("data", []))
    return next((p for p in rows if p.get("status") == "active"), None)


def approve_pending(H):
    tasks = httpx.get(CM + "/consent/v1/awe/tasks", headers=H, timeout=30).json()
    rows = tasks if isinstance(tasks, list) else tasks.get("items", tasks.get("data", []))
    for t in rows:
        tid = t.get("task_id") or t.get("id")
        httpx.post(CM + "/consent/v1/awe/tasks/%s/claim" % tid, headers=H, timeout=30)
        httpx.post(CM + "/consent/v1/awe/tasks/%s/decision" % tid, headers=H, timeout=30,
                   json={"action": "approve", "comment": "required_auth_method change"})
    return len(rows)


def main():
    H = hdr()
    rows = partners(H)

    if len(sys.argv) < 3:
        print("\n  %-22s %-38s %-8s %s"
              % ("AUDIENCE", "PARTNER ID", "OTP", "LAWFUL BASIS"))
        print("  " + "-" * 88)
        for p in sorted(rows, key=lambda r: r.get("audience") or ""):
            pol = active_policy(H, p["id"])
            if pol is None:
                # Distinct from OFF: no policy at all means /validate treats
                # the partner as having no permissions whatsoever.
                state = "no active policy"
            else:
                state = "on" if pol.get("required_auth_method") == "otp" else "OFF"
            basis = (pol or {}).get("lawful_basis") or "consent"
            # Worth seeing beside the OTP column: a partner on legitimate_interest
            # asks nobody anything, so its OTP setting is moot by construction.
            print("  %-22s %-38s %-8s %s"
                  % (p.get("audience"), p["id"], state,
                     "consent" if basis == "consent"
                     else "LEGITIMATE INTEREST - no consent sought"))
        print("\n  set one with:  set-partner-otp.py <audience> on|off\n")
        return 0

    audience, want = sys.argv[1], sys.argv[2].lower()
    if want not in ("on", "off"):
        sys.exit("second argument must be 'on' or 'off'")
    match = [p for p in rows if p.get("audience") == audience]
    if not match:
        sys.exit("no partner with audience '%s'. Run with no arguments to list them."
                 % audience)
    pid = match[0]["id"]

    pol = active_policy(H, pid)
    if pol is None:
        sys.exit("partner %s has no active policy; create one first"
                 % audience)
    now = pol.get("required_auth_method")
    if (now == "otp") == (want == "on"):
        print("  %s: OTP already %s — nothing to do" % (audience, want))
        return 0

    # A policy version replaces the whole document, so carry the current one
    # forward and change only the one field. Sending a partial body would
    # silently drop this partner's scopes.
    body = {k: pol.get(k) for k in (
        "allowed_data_scopes", "allowed_purposes", "allowed_subject_id_types",
        "allowed_signing_algs", "max_validity_duration", "fetch_type",
        "max_fetch_frequency", "data_life")}
    body["required_auth_method"] = "otp" if want == "on" else None

    r = httpx.put(CM + "/consent/v1/partners/%s/policy" % pid,
                  headers=H, timeout=30, json=body)
    if r.status_code >= 400:
        sys.exit("policy update failed: HTTP %s %s" % (r.status_code, r.text[:300]))
    new = r.json()
    print("  %s: OTP %s -> %s  (policy v%s, %s)"
          % (audience, "on" if now == "otp" else "OFF", want,
             new.get("version"), new.get("status")))

    if new.get("status") == "pending":
        n = approve_pending(H)
        print("  removing a factor needs AWE approval; approved %d task(s)" % n)

    # AWE decides through an asynchronous webhook, so reading the active policy
    # straight after the decision races it and reports the old version. Poll.
    want_method = "otp" if want == "on" else None
    for _ in range(20):
        pol = active_policy(H, pid)
        if (pol or {}).get("required_auth_method") == want_method:
            break
        time.sleep(1)
    live = (pol or {}).get("required_auth_method")
    print("  active policy v%s now requires: %s"
          % ((pol or {}).get("version"), live or "no authentication method"))
    if (live == "otp") != (want == "on"):
        sys.exit("  the change did NOT take effect — the old version is still active")
    return 0


if __name__ == "__main__":
    sys.exit(main())
