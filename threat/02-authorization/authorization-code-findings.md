# lab-auth — Authorization: Code Findings & Recommendations

**Threat model 02 — Authorization (access control).** The code audit, for the "How to Secure Your Apps" series
(Episode 5). Unlike a pure audit, the two **do-now** findings here were **implemented, tested, and committed**
(the series' code→threat→detection→fix arc). Companion to
[authorization-detection-mitigation.md](authorization-detection-mitigation.md) (the SecureNow runbook).

Scope: `src/app.js` on `tutorial/securenow`, SecureNow SDK **8.12.2**, app `lab-auth`
(`df7ab010-37ac-4732-88ac-a8ac23afe1a4`). Reviewed & fixed 2026-10-19 (commit `609640f`).

---

## Executive summary

| Threats modeled | Covered 🟢 | Partial 🟡 | Gap 🔴 | N/A for this app | Findings | Fixes shipped |
|---|---|---|---|---|---|---|
| 71 | 10 | 2 | 0 | 58 | 3 | 2 (AZ-1, AZ-2) |

**The headline:** lab-auth is **correctly authorized** — every privileged route is role-gated, registration
cannot set its own role, the role PATCH cannot be mass-assigned, it requires a fresh password (step-up), and a
role change invalidates every session. The one real gap was **blindness, not a hole**: authorization decisions
lived only in the app's own database, so a probe of the access-control boundary never reached SecureNow. That is
now fixed (**AZ-1**), plus a race in the admin-quorum guard (**AZ-2**). Both shipped with tests.

**Do we detect sudden privilege escalation? Yes — two ways:**
1. **When a role is granted up** (member → admin): the `role_changed`/`direction=elevate` event feeds
   **R-AZ-03** and the live 01-auth rule — the elevation is caught.
2. **When a boundary just opens with no role-change event** (a mid-session grant, a replayed higher-privilege
   session, or a gate regression): **R-AZ-BOUNDARY** catches the `403 → 200` on the same restricted route from
   **traces alone, zero app code** — validated live (`/api/admin/users`, `403 → 200`).

**Why 58 of 71 are N/A:** lab-auth has no user-owned business objects (the dashboard is static, `:365-379`), no
multi-tenancy, and no LLM-agent / MCP / tool-calling surface — so the object-level (BOLA), tenancy, and agentic
groups have nothing to attack here. They are carried as forward-looking (§4).

---

## 1. The authorization model (as built)

**Roles:** `member` (1) < `analyst` (2) < `admin` (3) — the `roles` set + `rank` map (`src/app.js`, used `:406`/`:417`).
Role lives on the `users` row, read fresh each request on session rehydrate (`:121-133`).

**Gates:** `requireUser` (`:167`) — any session · `requireRole(...allowed)` (`:171`) — role membership; on failure
writes `authorization.denied` locally **and now exports `authz.denied` to SecureNow** (AZ-1, `:174-181`).

| Method + route | Gate | Object scope |
|---|---|---|
| `GET /api/dashboard` (`:371`) | `requireUser` | none — **static** demo data (no BOLA surface) |
| `GET /api/security` (`:386`) | `requireRole('analyst','admin')` | all events; **own** sessions (`:394` `WHERE sess->>'userId'=$1`) 🟢 |
| `GET /api/admin/users` (`:401`) | `requireRole('admin')` | all users |
| `PATCH /api/admin/users/:id[/role]` (`:405`) | `requireRole('admin')` | any user — see guards |

**Role-change guards:** UUID + `role ∈ roles` (`:406`) · self-demotion blocked (`:407`) · **step-up (F5)** within
5 min else `403 STEP_UP_REQUIRED` (now also exports `authz.denied reason=step_up_required`, `:409-414`) ·
**admin-quorum + race safety (AZ-2)** (`:417-446`) · session invalidation via `session_version` bump (`:131`) ·
audit `admin.role_changed` + `auth.security.change{direction,target_ref}` (`:452-455`).

**Write-path safety:** registration inserts only `id,email,name,password_hash` — **no `role`** (`:231-234`); the
role PATCH reads only validated `role` + `:id`, body never spread. No mass-assignment.

---

## 2. The 71-threat catalog → lab-auth coverage

🟢 covered · 🟡 partial · 🔴 gap · ⚪ N/A. Groups A–M are the classic catalog; **group N (61–71) is the agentic /
MCP / tool-calling surface**.

| Group | Threats | lab-auth | Why |
|---|---|---|---|
| A. Object-level (BOLA/IDOR) | 1–8 | ⚪ N/A | no owned business objects; only owned object is *sessions*, scoped (`:394`) 🟢 |
| B. Function-level (BFLA) | 9–15 | 🟢 | every privileged route gated; probing now **exported** (AZ-1) → R-AZ-01 |
| C. Property-level / mass-assignment | 16–22 | 🟢 | no body-spread; register has no role column |
| D. Vertical escalation | 23–28 | 🟢 | role server-side each request; **403→200 boundary detectable** (R-AZ-BOUNDARY) |
| E. Horizontal escalation | 29–33 | 🟢 / ⚪ | own-session scope enforced; no cross-user objects |
| F. Forced browsing / method & case | 34–38 | 🟢 | F6 strict + case-sensitive routing |
| G. Privileged-function abuse | 39–43 | 🟢 | step-up (F5) + session-version bump; step-up bypass detectable (R-AZ-02) |
| H. Admin / self-service escalation | 44–48 | 🟢 | self-demotion blocked + **admin-quorum race closed (AZ-2)** |
| I. Multi-tenancy | 49–52 | ⚪ N/A | single-tenant lab |
| J. Confused deputy / SSRF-authz | 53–55 | ⚪ N/A | no server-side fetch of user-controlled refs |
| K. TOCTOU / race | 56–57 | 🟢 | concurrent role PATCH serialized by `FOR UPDATE` (AZ-2) |
| L. Token / scope | 58–59 | 🟢 | session cookie + server-side version check |
| M. Observable abuse | 60 | 🟢 | denials + elevation now exported (AZ-1) → R-AZ-01/02/03/BOUNDARY |
| N. AI agents / MCP / tool-calling | 61–71 | ⚪ N/A | no agent/MCP/tool surface — see §4 |

**Covered 🟢 (10):** BFLA gating, own-session scope, no mass-assignment, register role-pinning, vertical-escalation
+ boundary detection, forced-browsing/case (F6), step-up (F5), session invalidation, token/version, TOCTOU (AZ-2).
**Partial 🟡 (2):** AZ-3 (denials lack `object_owner` for future owned objects), horizontal exposure on the global
security console (by design, single-tenant). **Gap 🔴 (0 live)** — AZ-1 closed the only detection-blocking gap.

---

## 3. Findings

### AZ-1 — Authorization decisions now exported to SecureNow · severity **medium** · 🟢 SHIPPED  {#az-1}

**Was:** `requireRole` (`:174`) and the step-up gate (`:409`) recorded denials only in the local `security_events`
table — SecureNow saw the `403` traces but not the authorization semantics (who, which role, which route,
role-denied vs step-up). Function-level probing (OWASP API5) was undetectable *as such*.

**Now (commit `609640f`, `src/app.js:174-181`, `:409-414`):** both denial points also
`emit('authz.denied', …)` with `decision`, `reason` (`role_denied` / `step_up_required`), `route`, `method`,
`have_role`, `need_role`, `target_ref`. `emit` is the lab's existing optional bridge (`src/securenow-bridge.js`).

```js
// src/app.js — requireRole denial
emit('authz.denied', req, { userId: req.user.id, attributes: {
  decision: 'deny', reason: 'role_denied', route, method: req.method,
  have_role: req.user.role, need_role: allowed.join('|'), target_ref: req.params?.id ?? null,
} });
```

**Backs detections:** [R-AZ-01](authorization-detection-mitigation.md#r-az-01) (validated: 3 routes, 18 denials)
and [R-AZ-02](authorization-detection-mitigation.md#r-az-02) (validated: 3 step-up blocks).

### AZ-2 — Admin-quorum invariant + concurrent-role-change race · severity **low** · 🟢 SHIPPED  {#az-2}

**Was:** self-demotion was blocked (`:407`), but two admins demoting each other concurrently were not serialized
(TOCTOU, threats 56–57 / 44–48). A single-statement subquery would **not** close it under READ COMMITTED — its
count takes no lock on the admin rows.

**Now (commit `609640f`, `src/app.js:417-446`):** the role change runs in one transaction that locks the admin
set `FOR UPDATE`, re-counts under the lock, and refuses any demotion that would leave zero admins
(`409 LAST_ADMIN`, also exported as `authz.denied reason=last_admin`). A new integration test fires two concurrent
cross-demotions and asserts exactly one `200` + one `409` and that one admin always remains (14 tests green).

**Backs detection:** [R-AZ-03](authorization-detection-mitigation.md#r-az-03) — containment for the fan-out shape.

### AZ-3 — Denial events carry no object owner (forward-looking) · severity **low** · 🟡

The authz events carry `target_ref` (the requested id) but not `object_owner` — fine today (no owned objects),
but the day a `GET /api/x/:id` lands, true IDOR (`caller ≠ object_owner` on an *allow*) is detectable only if the
event carries both. Add `object_owner` + emit on *grants* of sensitive resources then.

---

### AZ-5 — IDOR on `GET /api/notes/:id` (owned object, predictable key) · severity **high** · 🟢 SHIPPED (found → detected → fixed)  {#az-5}

**Where.** `GET /api/notes/:id` (`src/app.js`). The `notes` resource uses a **predictable integer key**
(`db/001_initial.sql`), and the handler originally fetched the row by id **only** — never scoped to the caller:
`SELECT … FROM notes WHERE id=$1`. Any signed-in user could read any note.

**Why it matters.** This is OWASP **API1 / BOLA** — the most common and most exploited access-control bug. A single
IDOR request returns a normal `200` and emits no error; it is invisible per-request. It is caught **statistically**,
from the shape of the traffic (see detection report §11): a scanner shows a high **miss ratio** (`404`-heavy), a
dumper shows many distinct **`200`** reads, a walker a dense consecutive id range, and the definitive breach is a
`200` the app granted on an object the caller doesn't own.

**Detected, live.** With the IDOR present, a scan/walk/dump run against the lab fired all four rules and was quiet on
a legitimate baseline — scan `203.0.113.61` (90% `404`), dump `203.0.113.62` (100% `200`, 30 cross-owner reads).

**Fix (shipped, commit `5ba2e37`).** Scope the read to the owner so a not-owned note is indistinguishable from a
missing one:
```js
// not-owned => no row => 404, no existence leak
const { rows } = await pool.query(
  'SELECT id,owner_id,title,body,created_at FROM notes WHERE id=$1 AND owner_id=$2', [id, req.user.id]);
```
Plus `authz.granted` with `owner_id` on the read, so the cross-owner detection has its signal. A new integration
test proves a note is readable only by its owner (owner `200`, another user `404`).

**Backs detections:** the four statistical rules in
[authorization-detection-mitigation.md §11](authorization-detection-mitigation.md). Teaching point: the behavioural
rules (scan/walk/dump) warn you someone is *hunting*; the cross-owner event tells you whether they *succeeded*.

## 4. Forward-looking: authorization in the age of AI, MCP & APIs

Not applicable to lab-auth yet (no agent/MCP/tool surface) — the map for when it, or your real app, grows one
(catalog group N): re-authorize at the **tool boundary** per end user (confused-deputy, 61); carry the user's
authz down (OBO, 62); bound tokens to an audience/resource (RFC 8707, 67); gate high-impact tool actions behind a
human (69 — the agentic analog of step-up); scope retrieval to the caller (RAG, 68); treat `agent.action`
(background runs) as its own privileged surface (70). Emit `track('tool.call', { on_behalf_of, decision, tool,
target_ref, object_owner })`; the detection side is in the sibling report §10.

---

## 5. What's already right (keep it)

Role gates on every privileged route · server-side role each request · registration can't self-escalate · role
PATCH can't be mass-assigned · step-up before role change (F5) · session invalidation on role change · own-session
scope on the security console · strict case-sensitive routing (F6).

---

## 6. Fix list — state

| ID | Fix | Status | File:line | Test | Detection |
|---|---|---|---|---|---|
| AZ-1 | Export authz decisions (`track('authz.denied')`) at both denial points | ✅ shipped `609640f` | `src/app.js:174-181`, `:409-414` | covered live (R-AZ-01/02 fired) | R-AZ-01, R-AZ-02 |
| AZ-2 | Admin-quorum invariant + `FOR UPDATE` race safety; `409 LAST_ADMIN` | ✅ shipped `609640f` | `src/app.js:417-446` | new concurrent-demotion test (14 green) | R-AZ-03 |
| AZ-3 | Add `object_owner` + emit on sensitive grants (for future owned objects) | DO-SOON | `src/app.js:174` | n/a until an owned-object route exists | future IDOR rule |

Next: [authorization-detection-mitigation.md](authorization-detection-mitigation.md) — the SecureNow runbook.
