# Phase 16 Forensic QA Scorecard — screenshot-to-code

**Project**: Multi-tenant SaaS screenshot-to-code application  
**Phase**: 16 (System Completeness Audit)  
**Date**: 2026-09-11  
**Status**: Phase 20 complete, auth implementation in place

---

## Executive Summary

CI pipeline **PASSED**. Frontend builds successfully (1.4MB minified). Backend auth layer implemented with WebSocket middleware. **CRITICAL BLOCKER FIXED**: validate_auth_header function added to resolve ws_auth.py import error.

**VERDICT**: NOT READY FOR PRODUCTION (multiple P1 issues blocking function)

---

## Scorecard — 31 QA Areas

| § | Area | Status | Severity | Finding | Fixed |
|---|---|---|---|---|---|
| 1 | **UI Controls Exist** | PARTIAL | P1 | WebSocket doesn't pass auth token to backend. Frontend has no auth UI. | NO |
| 2 | **UI Handler Wiring** | PARTIAL | P1 | Settings dialog exists but no API key management UI. | NO |
| 3 | **API Endpoint Coverage** | PARTIAL | P1 | Missing health check endpoint at /health for DigitalOcean. | NO |
| 4 | **Database Schema** | VERIFIED | P1 | Schema defined; User.email @unique violates multi-tenant model (allows same email across orgs). | NO |
| 5 | **Foreign Key Integrity** | VERIFIED | OK | ForeignKey relations properly defined (Organization → User, Project, Render; Project → Render). | YES |
| 6 | **Database Indexes** | VERIFIED | P2 | Indexes on orgId, projectId, userId, status. Missing compound index on (orgId, userId). | NO |
| 7 | **Multi-tenancy Isolation** | VERIFIED | P1 | All queries filter by orgId; however, ws_auth uses in-memory VALID_KEYS not scoped to org. | NO |
| 8 | **Auth Integration** | VERIFIED | P1 | Bearer token + X-API-Key + query param support; but frontend never sends token. | NO |
| 9 | **WebSocket Middleware** | VERIFIED | P1 | get_ws_auth_context closes ws on failure; auth_context attached to scope; no heartbeat. | NO |
| 10 | **API Key Validation** | VERIFIED | P1 | validate_auth_header implemented; VALID_KEYS in-memory not database-backed. API key expiration not enforced. | NO |
| 11 | **Role-Based Access** | PARTIAL | P1 | require_role decorator exists; no route actually uses it yet. | NO |
| 12 | **Database CRUD — Create** | VERIFIED | P1 | create_render, create_project work; missing create UI and error handling for FK violations. | NO |
| 13 | **Database CRUD — Read** | VERIFIED | OK | get_project, get_render, list_renders all org-scoped. | YES |
| 14 | **Database CRUD — Update** | PARTIAL | P1 | update_render exists; no route exposes it; no optimistic locking. | NO |
| 15 | **Database CRUD — Delete** | NOT TESTED | P1 | No delete operations implemented. Soft delete pattern missing. | NO |
| 16 | **Form Client Validation** | NOT TESTED | P3 | Frontend has no form for create/edit. Settings dialog is a mock. | NO |
| 17 | **Form Server Validation** | NOT TESTED | P1 | No Pydantic models for request validation on any endpoint. | NO |
| 18 | **Search/Filter/Sort** | NOT TESTED | P1 | list_renders has no query parameters for filtering. | NO |
| 19 | **Pagination** | NOT TESTED | P1 | list_renders returns all results; no pagination. | NO |
| 20 | **Error States** | PARTIAL | P1 | WebSocket closes on auth failure; no error response message. | NO |
| 21 | **Loading States** | PARTIAL | P1 | Frontend shows "Generating..." but no loading skeleton for lists. | NO |
| 22 | **Empty States** | NOT TESTED | P2 | No empty state UI when user has 0 projects or renders. | NO |
| 23 | **Responsive Design** | NOT TESTED | P2 | Desktop design; no mobile breakpoints tested. | NO |
| 24 | **Accessibility** | NOT TESTED | P3 | No aria-labels, heading hierarchy, or keyboard navigation tested. | NO |
| 25 | **Forced Failures — DB Down** | NOT TESTED | P1 | No error handling for Prisma connection failures in db.py. | NO |
| 26 | **Forced Failures — API Down** | NOT TESTED | P1 | No timeout handling on LLM calls. | NO |
| 27 | **Forced Failures — Network Loss** | NOT TESTED | P1 | WebSocket disconnect handling incomplete (no reconnect). | NO |
| 28 | **Security — IDOR** | VERIFIED | P1 | Path traversal impossible (GUIDs); but project membership not verified in generate_code. | NO |
| 29 | **Security — SQLi/XSS** | VERIFIED | OK | Prisma handles SQLi; frontend escapes HTML. | YES |
| 30 | **Performance — LCP/CLS** | NOT TESTED | P2 | Frontend build 1.4MB minified (warning: single chunk). INP/CLS untested. | NO |
| 31 | **Deployment Verification** | PARTIAL | P1 | app.yaml + CI config exists; DigitalOcean secrets not configured. Not actually deployed yet. | NO |

---

## Detailed P1 Findings (Block Deployment)

### F1: Frontend Auth Token Not Sent to WebSocket [SEVERITY: P1 — CRITICAL]

**Finding**: generateCode.ts creates WebSocket to `/generate-code` without Authorization header or token query parameter. Backend now requires valid auth (via get_ws_auth_context) but frontend provides none.

**Impact**: WebSocket handshake succeeds, but backend immediately closes connection with code 1008 (policy violation). No code generation possible.

**Failure Scenario**: User uploads screenshot → frontend opens ws://localhost:7001/generate-code → backend calls get_ws_auth_context → closes WS because no auth header → user sees blank screen or error "WebSocket connection closed".

**Evidence**: `frontend/src/generateCode.ts:58` creates WebSocket without auth; `backend/ws_auth.py:35` closes if no valid auth found.

**Fix Required**:
1. Add auth token to localStorage on Settings save
2. Modify generateCode.ts to append ?token=<key> to URL or send Authorization header (WebSocket headers via constructor don't work; query param required)
3. Backend already handles query param in ws_auth.py line 28

---

### F2: Missing API Key Management UI [SEVERITY: P1 — BLOCKS FEATURE]

**Finding**: Settings dialog exists (Settings.tsx) but has no fields to input, generate, or copy API key. User has no way to get auth token.

**Impact**: Users cannot authenticate; cannot use the app.

**Failure Scenario**: User opens Settings → no "API Key" section → tries to generate key → nothing happens.

**Evidence**: `frontend/src/components/Settings.tsx` is a skeleton; no apiKey input field.

**Fix Required**: Add input field + "Generate" button + "Copy to Clipboard" to Settings.

---

### F3: No Health Check Endpoint [SEVERITY: P1 — DEPLOYMENT BLOCKER]

**Finding**: app.yaml declares health check at `/health` (line in app.yaml) but backend has no /health route.

**Impact**: DigitalOcean health checks will fail; deployment will mark the service as unhealthy and attempt rolling restart loop.

**Failure Scenario**: Deploy to DO → health check probe fails → deployment rolls back.

**Fix Required**: Add simple GET /health endpoint returning `{"status": "ok"}`.

---

### F4: User.email @unique Violates Multi-Tenancy [SEVERITY: P1 — DATA MODEL]

**Finding**: Prisma schema `User.email String @unique` prevents same email across organizations. Multi-tenant apps require `@@unique([email, orgId])`.

**Impact**: Cannot invite user jane@example.com to both org A and org B; second org creation fails.

**Failure Scenario**: Org A invites jane@example.com → creates user → Org B tries to invite jane@example.com → Prisma unique constraint violation.

**Evidence**: `prisma/schema.prisma:24`

**Fix Required**: Change to `@@unique([email, orgId])` and re-run migrations.

---

### F5: API Key Scoping Not Enforced [SEVERITY: P1 — SECURITY]

**Finding**: auth.py VALID_KEYS is in-memory hardcoded dictionary. No database lookup. Keys are not tied to users; any key works for any org (hardcoded org-2).

**Impact**: Shared keys across all orgs; org isolation breakable if key leaked.

**Failure Scenario**: User A (org-1) leaks API key "demo-key-123" → attacker uses it and gets access to org-1 data; but key also grants access to org-2 in the hardcoded dict.

**Evidence**: `backend/auth.py:12-15` defines VALID_KEYS; `get_auth_context` returns hardcoded org_id.

**Fix Required**: 
1. Replace VALID_KEYS with database query: `api_key = await db.api_key.find_unique(where={"key": key})`
2. Return AuthContext with api_key.org_id, not hardcoded
3. Add API key generation endpoint
4. Enforce expiration check

---

### F6: WebSocket Closing Without Response Message [SEVERITY: P1 — UX]

**Finding**: get_ws_auth_context closes WebSocket with `code=status.WS_1008_POLICY_VIOLATION` but sends no JSON error message. Frontend cannot distinguish auth failure from network error.

**Impact**: User sees "connection closed" with no context; poor debugging experience.

**Failure Scenario**: User opens app with invalid key → WS closes silently → no error message shown.

**Fix Required**: Before closing, send error frame: `await websocket.send_json({"type": "error", "code": "UNAUTHORIZED", "message": "Invalid API key"})`

---

### F7: No Project Membership Verification in Code Generation [SEVERITY: P1 — IDOR]

**Finding**: stream_code handler receives auth_context but never verifies that the project specified in the request belongs to the authenticated user's org.

**Impact**: User from org-1 could send project_id from org-2 and generate code for org-2 assets.

**Failure Scenario**: 
1. User A (org-1) logs in
2. User A guesses project ID from org-2 (cuid format: 6–12 chars, low entropy)
3. User A sends request to generate code for org-2 project
4. Backend accepts it (no ownership check)
5. User A gets org-2 screenshot and code

**Evidence**: `backend/routes/generate_code.py:895` sets auth_context but line ~901 (ParameterExtractionMiddleware) doesn't validate project ownership.

**Fix Required**: In ParameterExtractionMiddleware, verify `project = await get_project(project_id, auth_context)` and fail if None.

---

### F8: No Render Error Persistence [SEVERITY: P1 — OBSERVABILITY]

**Finding**: Render model has `error String?` field but code generator never populates it. Failed generations never record why they failed.

**Impact**: No audit trail; users can't debug failures.

**Failure Scenario**: Generation fails → user sees "error" status → no error message in database → can't diagnose root cause.

**Fix Required**: Wrap code generation in try/catch; on exception, call `update_render(render_id, error=str(exception))`.

---

## Detailed P2 Findings (Should Fix Before Launch)

| P2 Code | Issue | Impact |
|---|---|---|
| P2-1 | Missing compound index on (orgId, userId) | N+1 queries on "my renders" operations |
| P2-2 | No pagination on list_renders | Slow query for users with 10k renders |
| P2-3 | No filter/sort parameters on list endpoints | UX: can't find render by date or status |
| P2-4 | Chunk size warning on frontend build | Potential 2MB+ slow load on low-bandwidth |
| P2-5 | No soft-delete; deletes are hard | Cannot restore accidentally deleted projects |
| P2-6 | No rate limiting on WebSocket | Abuse: spam generate requests |
| P2-7 | No connection heartbeat on WebSocket | Silent disconnects after 60s proxy timeout |

---

## Phase-by-Phase Implementation Map

| Phase | Owner | Blocker | P0-Ready |
|---|---|---|---|
| 20 | Auth Middleware | ✓ FIXED | YES |
| 21 | Frontend Auth UI | F1, F2 | NO |
| 22 | Health Endpoint | F3 | NO |
| 23 | Schema Migration | F4 | NO |
| 24 | API Key DB Store | F5 | NO |
| 25 | Project Ownership Verify | F7 | NO |
| 26 | Error Persistence | F8 | NO |
| 27 | Error Messages | F6 | NO |
| 28 | Pagination + Filters | P2-2, P2-3 | NO |

**Next Phase**: 21 (Frontend Auth UI) — unblock F1/F2 so app is usable.

---

## Final Readiness Verdict

**PRODUCTION READY**: NO  
**READY WITH CRITICAL RISKS**: NO  
**READY WITH MINOR RISKS**: NO  
**NOT READY**: YES

**Reason**: 8 P1 blockers prevent user code generation. App is structured correctly (auth, multi-tenancy, CRUD) but wired incompletely.

**Estimated Effort to P1 Clear**: 2–3 days (Frontend UI + Backend fixes + Testing)

---

## Test Matrix

- [ ] WebSocket connects with valid API key
- [ ] WebSocket closes with invalid API key
- [ ] Code generation streams to authenticated user
- [ ] Project A user cannot access Project B
- [ ] Failed generation records error message
- [ ] Health check returns 200 OK
- [ ] User can create project and render
- [ ] Pagination works with 100+ renders
- [ ] Settings dialog saves API key
- [ ] Concurrent requests from two users don't leak data

---

Generated by Phase 16 Forensic QA Protocol (automatic, Scott 2026-09-10)
