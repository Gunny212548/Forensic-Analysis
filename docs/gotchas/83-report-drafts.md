# Gotcha #83

**83. Report drafts: a Word skeleton can fetch other people's pictures, out-of-order XML hangs Word, and the AI's summary is checked, not trusted**

`specs/forensic_report.md`, IAI-72 / IAI-73, 2026-11-03 (the user: the system writes an editable
draft, the analyst finishes it in Word; the provider's template, never in git).

The traps:

1. **A template's pictures may be links.** The provider's Word template drew its heading bars inside
   `INCLUDEPICTURE` fields pointing at another organisation's website. The skeleton asks Word to
   update fields on open (for the contents page), and Word then downloaded those pictures and showed
   another company's logos in place of the bars - the user saw it in the first preview. Every
   `INCLUDEPICTURE` / `INCLUDETEXT` / `LINK` / `DDE` field and every non-hyperlink external
   relationship is refused on upload (`report_skeleton.check`), naming the part. A website hyperlink
   loads nothing and is allowed. Look at the *pictures* of a supplied template too: its cover footer
   carried a third customer's logo, and a people table kept two names in a second cell.
2. **Word stops on a hidden dialog for an element out of schema order.** `w:b` written before
   `w:rFonts`, `w:highlight` after `w:cs`, `w:outlineLvl` after `w:rPr` (62 places in the first
   skeleton): Word opened through COM sat on its "repair" dialog, invisible, holding the file - and the
   process could not be killed from this session; the user had to (`taskkill //PID n //F` in Git
   Bash, `//` because MSYS turns `/PID` into a path). Insert run and paragraph properties at their
   ECMA-376 rank, never append. A draft rendered for a look should also drop `w:updateFields`, whose
   prompt is another dialog.
3. **The summary's check is what keeps the model honest** (`report_summary.ground`). Measured on the
   bruteforce-pivot project: the model turned a SigmaHQ rule's Persistence tag into a motive ("to keep
   access") - tactics are not handed over; it wrote `adm.hu` for `adm.hd` - dotted accounts are
   checked; `10.20.0.40` was read as the times 10:20 and 00:40 - addresses are removed before times
   are checked; a true opening paragraph was refused for its end time because it cited only F1 - the
   whole span is a fact `S` whose ends are always accepted, a minute either side. An inference no check
   can see ("which confirms full control") still gets through: the yellow highlight and the analyst
   cover it (gotcha #13: prompt wording does not).
4. **Only high / critical groups have FD ids** (gotcha #49), so the draft numbers the confirmed groups
   `F1..Fn` in time order, and the summary cites those.
5. **A project's `question` is a record** (question, window, leads - `investigation.py`), not a string:
   read `question["question"]` (`report.question_text`).
6. **`make_draft` looks the summariser up at call time** so a check can put a stand-in model in
   (`summarise=None`); binding `report_summary.draft` as a default argument froze it at import.
7. **A PNG header is not a PNG.** A broken body behind `\x89PNG` passed the magic check and crashed the
   render (500); the picture is parsed with python-docx's own reader first (400).
8. **One fact line per finding does not fit the model's window.** A 526-finding project (the blind
   Windows quarter, all confirmed) gave 153,085 characters of facts against a 16,384-token window:
   the model saw a cut prompt, listed refs until its 1,600 tokens ran out, and the draft said
   `JSONDecodeError: Unterminated string` (57 s). Over `FACT_BUDGET` (24,000 characters) the rules
   with most findings are summed up as one line `G<n>` each - count, span, busiest sources and
   accounts; a paragraph citing it may name any of them - and a paragraph cites at most 8.
   Measured after: 6,477 characters, 3,305 prompt tokens, 23.7 s, 3 paragraphs kept, 1 refused.
   Past `FACT_LIMIT` the model is not asked and the draft says why.
