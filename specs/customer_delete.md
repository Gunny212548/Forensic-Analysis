# Deleting a customer - design

Status: **Approved 2026-10-28** (the user's answers below), built on branch `customer-delete`.
Requirement (the user, 2026-10-28): "ทำให้ลบ Customer ได้" - a customer can be deleted.

## Today

- A customer is its own store, `customers/<company_id>/` (gotcha #40): `customer.json`,
  `projects/`, every case's files (`cases/ db/ raw/ analysis/ review/ custody/ jobs/`), the
  hash-chained FD-id registry `findings/ids.jsonl` and the hash-chained record of the cases
  deleted from it, `deleted/log.jsonl` (specs/case_delete.md).
- A case can be deleted (admin, manager); its deletion is recorded in that customer's
  `deleted/log.jsonl`. Deleting the customer would take that record with it.

## Decided (the user, 2026-10-28)

- **D1 - a customer is deleted with every case it holds**, its projects and its evidence, in
  one action. The confirmation says what goes (cases, suggestions, analyst decisions, FD ids)
  and needs the customer's name typed back. Refused while any of its cases is queued,
  processing or has an AI narrative running - the same rule as a case (case_delete.BUSY).
  The background AI review of suggestions does not block it: it stops itself when its case is
  gone (triage `should_continue`), as for a case.
- **D2 - the record goes to a shared log**, `DATA_DIR/deleted/customers.jsonl`, hash-chained
  (hashchain.py), outside every customer store: who, when, the customer (id, name, created),
  its projects, each case (id, file name, project, upload time, the evidence's SHA-256 at
  acquisition, size, rows, flagged rows, the FD ids it held) and the customer's earlier case
  deletions carried over from its own log. Metadata only - no event, no log line, no evidence.
  The whole customer store is removed.
- **D3 - admin and manager** may delete a customer (`customer:delete`, authz.py), as for a case.
- **D4 - the button is on every row of the Customers page** (the page was read-only since
  2026-10-05; this is its one action). Not on the "No customer" row: those cases belong to no
  store to delete.

## How

1. `GET /api/companies/{id}/deletion` - what deleting it would remove (D1's confirmation),
   and which cases block it now.
2. `DELETE /api/companies/{id}` - refused 409 while a case is busy, 404 for no such customer.
   The store is first **renamed** out of the customers directory (`.deleting-<id>-<token>`,
   one atomic rename), so from that instant no page, list, upload or MCP call sees it - an
   upload naming the id is refused as for an unknown customer - then removed; the record is
   appended after. If the removal fails part-way the record names what was left behind.
3. Every case's id is dropped from the case -> customer cache (`storage.forget_case`).
4. FD ids are per customer; a customer added later under the same name is a new customer
   with a new id and its own registry, so no id is handed out twice within a customer.
