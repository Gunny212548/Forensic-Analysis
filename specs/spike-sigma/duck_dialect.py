"""Spike (a): a DuckDB dialect of pySigma's SQLite backend - detection only.

pySigma parses the rule, applies the modifiers and builds the condition tree; this
class changes only the tokens that mean something else on DuckDB.
"""
import re

from sigma.backends.sqlite import sqliteBackend

_BARE = r"[A-Za-z_][A-Za-z0-9_]*"


class DuckDialect(sqliteBackend):
    # Sigma compares strings case-insensitively. DuckDB LIKE is case-sensitive; ILIKE is not.
    wildcard_match_expression = "{field} ILIKE '{value}' ESCAPE '\\'"
    contains_expression = "{field} ILIKE '%{value}%' ESCAPE '\\'"
    # DuckDB has no REGEXP operator; regexp_matches is a search (RE2), like re.search.
    re_expression = "regexp_matches({field}, '{regex}')"
    # DuckDB has a NOCASE collation; equality is always collated (see __init__).
    collation_expression = "{expr} COLLATE NOCASE"

    # Event fields are VARCHAR. A bare "f > 1000" is a binder error on DuckDB (and on a
    # SQLite TEXT column every non-numeric string compares greater than any number).
    # Compare numbers as numbers; a value that is not one is not a match.
    compare_op_expression = "TRY_CAST({field} AS DOUBLE) {operator} {value}"

    def convert_condition_field_eq_val_num(self, cond, state):
        return f"TRY_CAST({self.escape_and_quote_field(cond.field)} AS DOUBLE)={cond.value}"

    def __init__(self, *a, **kw):
        kw.setdefault("collate_nocase", True)
        super().__init__(*a, **kw)

    def escape_and_quote_field(self, field):
        # DuckDB quotes identifiers with double quotes; a backtick is a syntax error.
        if re.fullmatch(_BARE, field):
            return '"' + field + '"'
        return '"' + field.replace('"', '""') + '"'

    def convert_correlation_rule(self, *a, **kw):
        raise NotImplementedError("correlations: not part of this dialect (spike)")
