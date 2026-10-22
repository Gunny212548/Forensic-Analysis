# IAI-14 - Roles and permissions: Admin, Manager, Analyst

Status: **Approved 2026-10-21 - Q56-Q60 as proposed** (Admin: accounts + read only; Manager alone closes; a Users page; every role sees every customer; existing accounts as listed). The user: "สร้าง role สำหรับ User ที่จะเข้ามาใช้งาน จะมี
Admin, Manager, analyze" (analyze = Analyst). Jira IAI-14: "Define roles (e.g. analyst, lead,
admin) and what each can do: assign, close, review, generate reports, manage customers, manage API
keys" (API keys were cut - every datum comes from an upload).

## Today

- `role` on an account is a label (`auth.py`); `authz.can()` allows everything (ADR-003). Every
  writing route but three already asks it (`cases.py`: verify, question, provenance, reprocess,
  merge, lifecycle, review); **upload, POST /companies and analyze do not ask yet**.
- Accounts are made with `tools/create_user.py` (no page). 8091: `admin.bisfish@gmail.com`
  (admin), `tester@fa-test.local` (analyst); dev: `parity@dev.local` (analyst).

## Standard (read 2026-10-21: NIST SP 800-53 Rev. 5.2.0, OSCAL catalog)

- **AC-2** Account Management: define account types, "group and role membership", "access
  authorizations (i.e., privileges)" per account; create / modify / disable / remove accounts by a
  defined process; AC-2(7): "monitor changes to roles or attributes".
- **AC-3** Access Enforcement: "enforce approved authorizations ... in accordance with applicable
  access control policies" - in the server, not the page.
- **AC-5** Separation of Duties: "dividing mission or business functions and support functions
  among different individuals or roles", and those "who administer access control functions do
  not also administer audit functions".
- **AC-6** Least Privilege: only "accesses ... necessary to accomplish assigned organizational
  tasks"; AC-6(2): privileged users use non-privileged accounts for non-security functions;
  AC-6(9): "log the execution of privileged functions".

## Proposed permission matrix

| action (authz name) | Analyst | Manager | Admin |
|---|---|---|---|
| Read: customers, cases, findings, timeline, graph, reports; exports (STIX, VERIS, ATT&CK layer) | yes | yes | **Q56** |
| Upload evidence into an existing customer / project (`case:upload`) | yes | yes | no |
| Create a customer or a project (`customer:manage`) - Upload's "+ Add new ..." | no | yes | no |
| Investigation question (`investigation:question`) | no | yes | no |
| Provenance, verify evidence, re-process (`evidence:provenance`, `evidence:verify`, `case:reprocess`) | yes | yes | no |
| Merge cases (`case:merge`) | no | yes | no |
| Review a finding - accept / modify / reject (`finding:review`) | yes | yes | no |
| Assign a finding (`finding:assign`) | only to themself, when unassigned | anyone | no |
| Investigate / contain (`finding:work`) | findings assigned to them | any | no |
| Resolve - close with a classification (`finding:close`) | **Q57** | yes | no |
| Reopen a resolved finding (`finding:reopen`) | no | yes | no |
| AI analysis - generate the narrative (`case:analyze`) | yes | yes | no |
| Accounts: add, change role, reset password, disable, remove (`account:manage`) | no | no | yes |

- **Deny by default**: an account whose role is none of the three may read nothing (AC-6). The
  role names are `admin`, `manager`, `analyst`.
- **Enforced in the server** (`authz.can` + the routes; AC-3); the page only reflects it: a
  control an account may not use is shown disabled with the role it needs - never hidden, so
  nothing on the page changes without a reason (the keep-UX-simple rule).
- **Every account change is logged**, hash-chained, with who did it (AC-2(7), AC-6(9)) - beside the
  sign-in audit log in `AUTH_DIR`, never with customer data.
- The MCP server stays read-only; its `--actor` must be an account whose role may read.

## Questions

- **Q56 - Admin and case data.** (A) Admin manages accounts only and sees no customer data
  (AC-5 / AC-6(2): whoever administers accounts also investigating needs a second, Manager
  account); (B) Admin manages accounts and may **read** everything, but takes no case action -
  proposed; (C) Admin may do everything.
- **Q57 - Who closes a finding.** Proposed: Manager only - the analyst works it to Contained (or
  to a reviewed false / benign positive) and the manager resolves it, so a closure has a second
  pair of eyes (AC-5). Or: an analyst may resolve findings assigned to them.
- **Q58 - Per-customer access.** Proposed: not now - every role sees every customer (an analyst
  limited to their customers is its own story). `can()` already receives the customer.
- **Q59 - Managing accounts.** Proposed: a **Users** page for Admin (Settings, today a
  placeholder): add with a temporary password, change role, reset password, disable, remove;
  `tools/create_user.py` stays for the first admin. Or: the command-line tool only.
- **Q60 - The existing accounts.** Proposed: `admin.bisfish@gmail.com` -> admin,
  `tester@fa-test.local` -> analyst, dev `parity@dev.local` -> **manager** (the parity check
  creates its "Parity check" customer, which an analyst may not).

## Tests (planned)

`tests/check_authz.py` grows into the matrix: every action x every role against the table above,
deny by default, an unknown role, the analyst's own-finding rules; the routes answer 403 (upload,
companies and analyze included); an account change writes a chained audit line;
`check_workflow` / `check_ingest` / `check_mcp` run with accounts of the roles they need.
