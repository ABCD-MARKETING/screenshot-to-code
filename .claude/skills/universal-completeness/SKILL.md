---
name: universal-completeness
description: GLOBAL HARD RULE (2026-09-05) — Universal Product Completeness & System Integration Protocol. Apply on EVERY development request in EVERY repo — any feature, page, button, field, DB column, API, automation, AI prompt, sales script, report, permission, config, integration, refactor, rename, or "fix". Never treat a request as isolated to the file/screen named. UNDERSTAND → LOCATE → SCAN → MAP → DESIGN → IMPLEMENT → CONNECT → VERIFY → SEARCH AGAIN → AUDIT → REPORT. Feature is not done until the user can actually operate the complete workflow end to end. Canonical text: essman929/AI-MEMORY memory/UNIVERSAL-COMPLETENESS-PROTOCOL.md.
---

# Universal Completeness Protocol (compact operating version)

**Source of truth:** `essman929/AI-MEMORY` → `memory/UNIVERSAL-COMPLETENESS-PROTOCOL.md` (43 sections, verbatim). This file is the vendored operating copy. Do not edit here; edit the canonical file and re-vendor.

**Core principle:** the user identified *one part* of a larger system. Understand the whole workflow, find what the change affects, connect every dependency, and make sure the user can actually accomplish the goal. Never think "change this one thing."

## Four levels — never stop at Level 1

1. **USER** — what is the human actually trying to accomplish?
2. **WORKFLOW** — every step from beginning to end.
3. **SYSTEM** — pages, components, DB records, APIs, automations, permissions, AI, notifications, reports, integrations that support it.
4. **ARCHITECTURE** — frontend, backend, DB, APIs, external services, automation, AI, auth, security, analytics, infra impact.

## Required sequence on every development request

| Step | Do |
|---|---|
| 1 UNDERSTAND | Real objective, not the literal wording. |
| 2 LOCATE | Where the functionality lives now (all of it, not just the named file). |
| 3 SCAN | Grep/inspect the whole repo: references, imports, schema, queries, endpoints, consumers, webhooks, jobs, prompts, agents, config, env vars, permissions, analytics, notifications, email/SMS flows, docs, tests, feature flags. Inspect DB schema (Neon MCP) and API contracts when available. |
| 4 MAP | Change Impact Map across: Frontend · Backend · Database · APIs · Automations · AI · Business logic · Analytics · Security · Testing. |
| 5 DESIGN | Complete user workflow + required functionality. Classify gaps **P0** (workflow breaks without it) / **P1** (clear, low-risk improvement) / **P2** (defer). |
| 6 IMPLEMENT | Requested change + all P0 + appropriate P1. No speculative P2. |
| 7 CONNECT | UI → API → backend → DB → result → UI. Automations, AI prompts/agents, permissions, analytics, external services as applicable. |
| 8 VERIFY | Test the real user workflow end to end, not just the function. Run the repo's own checks (typecheck, build, tests). |
| 9 SEARCH AGAIN | Stale references, obsolete fields, duplicate logic, broken imports, stale prompts, outdated API calls, dead config, old terminology, missing consumers/tests. |
| 10 AUDIT | Final system-wide audit (below). |
| 11 REPORT | Changed · Connected · Dependencies found · Extra improvements · Intentionally not done · Risks · P2 recs · Workflow verified? |

## Completeness checks (apply the ones that fit the entity — don't overbuild)

- **Entity/CRUD:** Create → Read → Update → Delete; then Archive/Restore/Duplicate/Activate/Deactivate/Assign/Bulk/History/Audit only where they logically belong.
- **Tables/grids:** search, sort, filter, pagination, counts, row + bulk actions, export/import, empty/loading/error states — sized to the data.
- **Forms:** required/optional, labels + help, validation + error messages, defaults, correct controls, Save/Cancel/Reset, draft + unsaved-change protection, confirm destructive.
- **States:** loading, loaded, empty (with a useful CTA), error (what failed, can they retry, was data saved?), success, disabled, read-only, unauthorized, pending/processing/failed/cancelled/archived/expired.
- **Workflow:** Discover → Select → Configure → Submit → Process → Confirm → Track → Complete. No button that starts a flow whose next step doesn't exist. No record the user can't find later. No status without a path in and out. No config option without a behavior it changes.
- **Cross-module:** Lead → Contact → Opportunity → Quote → Sale → Customer → Policy → Renewal. Trace shared IDs, FKs, events, webhooks, queues, notifications.
- **Roles/permissions:** who can see/create/edit/delete/approve/configure/export/bulk/administer, per role (owner, admin, manager, employee, agent, customer, vendor, partner, affiliate, read-only, system/API). Enforce on the backend, not just the UI.
- **Single source of truth:** same value in frontend + backend + prompt + DB + hardcode = duplication. Centralize; consumers read the source.
- **Sales scripts / prompts (aibots etc.):** editor, admin config, voice agent, text agent, system prompts, flow, rebuttals, qualification, routing, CRM, transcripts, disposition, follow-up automation, SMS/email, analytics, training data, dashboards, APIs, webhooks, version history, audit log, tests. Changing the source does not update consumers unless the architecture guarantees it.
- **Automations:** Trigger → Conditions → Action → Result → Error handling → Retry → Logging. Idempotent? Audit trail? User informed?
- **AI features:** prompts, agent config, tools + permissions, knowledge/retrieval, memory, model routing, guardrails, output parsing, downstream consumers (CRM, automations, analytics), logging, eval, tests. A response existing ≠ done.
- **API integrations:** auth, credentials, env config, request/response, validation, errors, retry, timeout, rate limits, logging, webhooks, status sync, mapping, dedupe, sandbox/prod, tests.
- **DB changes:** inspect schema → consumers → relationships → migration → back-compat → queries → APIs → frontend → validation → seed/test data → reports → automations → docs → test workflows.
- **API contract changes:** consumers, producers, frontend, external deps, webhooks, auth, request/response diffs, compatibility, update all consumers, test the whole flow.
- **Rename/remove anything:** search the entire system first. A name is never assumed unused.
- **Mobile/responsive + accessibility:** usable, not just smaller; keyboard, focus, labels, contrast, semantics, no color-only signals.
- **Security:** authn, authz, tenant isolation, exposure, input validation, uploads, privilege escalation, sensitive data, audit logging, destructive actions. Never frontend-only.
- **Architectural problems exposed by the change:** name them and propose the fix. Don't stack complexity on a known structural flaw.

## Definition of Done (all 25 or explicitly N/A)

Requested functionality exists · user can operate it · UI controls · CRUD · states · validation · permissions · frontend↔backend connected · backend↔correct data source · APIs work · external integrations · automations · AI dependencies updated · related modules connected · existing dependencies identified · no obsolete references · error handling · loading + empty states · mobile/responsive · accessibility considered · security considered · analytics/audit considered · real workflows tested · regression risk evaluated · system-wide impact reviewed.

## Final audit questions

USER · UX · WORKFLOW · DATA · INTEGRATION · API · AUTOMATION · AI · PERMISSIONS · SECURITY · ERRORS · REGRESSION · MAINTAINABILITY · COMPLETENESS — evaluate every one before declaring done. Visual completeness is not functional completeness.

## Ambiguity

Infer from existing architecture, UX patterns, terminology, schema, permissions, integrations. Obvious + low-risk → proceed. Materially different product decisions → ask only that. Never make irreversible assumptions about business rules.

## Coexistence with other ABCD rules

Mentor Mode's 1–2 lines come first, then this protocol governs the build. Fix Protocol's Diagnose = steps 2–4 here; its Verify = steps 8–10. Repo CLAUDE.md wins on conventions (branch, deploy, DB access); this protocol wins on completeness. Compliance gates remain hard stops. Caveman Ultra compresses the *report*, never the scan or audit.
