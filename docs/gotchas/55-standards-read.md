# Gotcha #55

**55. A standard is cited only from a document actually read (2026-10-20, the user:
"ต้องได้ตัวเอกสารมาก่อน").** `docs/standards/SOURCES.md` (branch `sprint/4` onwards) lists
each document read - version, SHA-256 of the copy, the page of every sentence relied on -
and the ones not obtained. Clause-level citation only for documents marked read.

- **Read:** NIST CSWP 29 (CSF 2.0), SP 800-86, SP 800-61r3, AI 600-1, AI 100-1, SP 800-55v1,
  SWGDE 18-Q-001 2.1, FIRST CSIRT Services Framework 2.1, Sigma 2.1.0 (rules, taxonomy,
  correlation), OCSF 1.9.0 Incident Finding, MITRE Attack Flow 4.0.
- **Not obtained:** every ISO document (27037, 27041, 27042, 27043, 9241-110, 27001 Annex A).
  iso.org answers 403 to automated access and the documents are sold; they are cited as
  "aligned with" only, and a read free document is cited first.
- **Checked against the read copies, and corrected:** every CSF 2.0 subcategory id cited from
  memory was right; Attack Flow is 4.0, not 3; SP 800-61r3 defines no TP / FP classes;
  SP 800-86 says it is not a guide for criminal investigations; SP 800-55v1 names mean time
  to detect / recovery, not to contain.
- **How to read a PDF here:** the web fetcher saves the PDF but returns its compressed
  streams as text; run `pdftotext -layout` (in Git Bash's mingw64) on the saved file and
  find the page by splitting on form feeds. The PDFs are kept in `docs/standards/files/`,
  not in git (`*.pdf` is ignored).
- **Downloads** need the sandbox lifted (`dangerouslyDisableSandbox`, the user's approval);
  `curl` fails on Schannel's revocation check (`CRYPT_E_REVOCATION_OFFLINE`), Python's
  `urllib` works.
