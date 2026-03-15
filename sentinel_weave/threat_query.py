"""
Threat Hunting Query Engine — SentinelWeave

Provides a lightweight, SQL-inspired query language for searching
:class:`~sentinel_weave.threat_detector.ThreatReport` collections.

Query syntax
------------
A query is a boolean expression made up of *predicates* joined by
``AND`` / ``OR`` (case-insensitive).  Parentheses can be used for
grouping.

Predicate forms::

    field  op  value
    field  ~   pattern       # ~ means "contains" (substring, case-insensitive)

Supported fields
~~~~~~~~~~~~~~~~
===================  ====================================================
``threat_level``     Categorical: BENIGN LOW MEDIUM HIGH CRITICAL
``source_ip``        Source IP string (wildcards: ``10.0.*``)
``event_type``       Event-type string (wildcards: ``SSH*``)
``anomaly_score``    Float 0.0–1.0
``signature``        Any matched signature; use ``~`` for substring search
``raw``              Raw log line; use ``~`` for substring search
``explanation``      Explanation token; use ``~`` for substring search
===================  ====================================================

Supported operators
~~~~~~~~~~~~~~~~~~~
``=``  ``!=``  ``>``  ``<``  ``>=``  ``<=``  ``~`` (case-insensitive contains)

Wildcards
~~~~~~~~~
``*`` is supported in string fields for ``=`` and ``!=`` comparisons.
``10.0.*`` matches any IP starting with ``10.0.``.

Examples::

    from sentinel_weave.threat_query import ThreatQueryEngine

    engine = ThreatQueryEngine(reports)

    # All HIGH or CRITICAL events from a /24 subnet
    results = engine.query(
        "(threat_level = HIGH OR threat_level = CRITICAL)"
        " AND source_ip = 192.168.1.*"
    )

    # Events with anomaly score above 0.7 that matched an SSH signature
    results = engine.query("anomaly_score > 0.7 AND signature ~ SSH")

    # Brute-force events regardless of case
    results = engine.query("raw ~ brute force")
"""

from __future__ import annotations

import fnmatch
import re
from typing import Sequence

from .threat_detector import ThreatReport


# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
    \(                        # left paren
    | \)                      # right paren
    | (?i:AND|OR)(?=\s|$|\()  # boolean keyword
    | >=|<=|!=|[><=~]         # operators (longest match first)
    | [^\s()>=<~!]+           # bare word / value
    """,
    re.VERBOSE,
)


def _tokenise(query: str) -> list[str]:
    return _TOKEN_RE.findall(query)


# ---------------------------------------------------------------------------
# Predicate evaluation
# ---------------------------------------------------------------------------

def _field_values(report: ThreatReport, field: str) -> list[str | float]:
    """
    Return the value(s) of *field* extracted from *report*.

    For list-valued fields (``signature``, ``explanation``) a list is
    returned so the caller can check *any element*.
    """
    f = field.lower()
    if f == "threat_level":
        return [report.threat_level.value]
    if f == "source_ip":
        return [report.event.source_ip or ""]
    if f == "event_type":
        return [report.event.event_type or ""]
    if f == "anomaly_score":
        return [report.anomaly_score]
    if f == "signature":
        return list(report.event.matched_sigs or [])
    if f == "raw":
        return [report.event.raw or ""]
    if f == "explanation":
        return list(report.explanation or [])
    raise ValueError(f"Unknown query field: {field!r}")


def _match_value(stored: str | float, op: str, rhs: str) -> bool:
    """Apply *op* comparison between *stored* and *rhs*."""
    if op == "~":
        # Substring / contains (case-insensitive string)
        return rhs.lower() in str(stored).lower()

    # Numeric comparison when stored is float and rhs is numeric
    try:
        rhs_num = float(rhs)
        num = float(stored)
        if op == "=":
            return num == rhs_num
        if op == "!=":
            return num != rhs_num
        if op == ">":
            return num > rhs_num
        if op == "<":
            return num < rhs_num
        if op == ">=":
            return num >= rhs_num
        if op == "<=":
            return num <= rhs_num
    except (ValueError, TypeError):
        pass

    # String comparison (with wildcard support for = and !=)
    s = str(stored)
    if op in ("=", "!="):
        if "*" in rhs or "?" in rhs:
            matched = fnmatch.fnmatch(s.lower(), rhs.lower())
        else:
            matched = s.lower() == rhs.lower()
        return matched if op == "=" else not matched

    # Lexicographic ordering for string fields
    if op == ">":
        return s.lower() > rhs.lower()
    if op == "<":
        return s.lower() < rhs.lower()
    if op == ">=":
        return s.lower() >= rhs.lower()
    if op == "<=":
        return s.lower() <= rhs.lower()

    raise ValueError(f"Unknown operator: {op!r}")


def _eval_predicate(report: ThreatReport, field: str, op: str, rhs: str) -> bool:
    """Evaluate a single predicate against *report*."""
    values = _field_values(report, field)
    # For list-valued fields: predicate is True if *any* element matches
    return any(_match_value(v, op, rhs) for v in values)


# ---------------------------------------------------------------------------
# Recursive-descent parser / evaluator
# ---------------------------------------------------------------------------

class _Parser:
    """
    Recursive-descent parser that evaluates a query expression directly
    against a :class:`~sentinel_weave.threat_detector.ThreatReport`.
    """

    _OPS = frozenset({">=", "<=", "!=", ">", "<", "=", "~"})

    def __init__(self, tokens: list[str]) -> None:
        self._tokens = tokens
        self._pos = 0

    # -- helpers -----------------------------------------------------------

    def _peek(self) -> str | None:
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return None

    def _consume(self) -> str:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _expect(self, value: str) -> None:
        tok = self._consume()
        if tok != value:
            raise ValueError(f"Expected {value!r}, got {tok!r}")

    # -- grammar -----------------------------------------------------------
    # expr  ::= and_expr (OR and_expr)*
    # and_expr ::= atom (AND atom)*
    # atom  ::= '(' expr ')' | predicate
    # predicate ::= field op value

    def parse_expr(self, report: ThreatReport) -> bool:
        result = self._parse_and(report)
        while self._peek() and self._peek().upper() == "OR":
            self._consume()
            right = self._parse_and(report)
            result = result or right
        return result

    def _parse_and(self, report: ThreatReport) -> bool:
        result = self._parse_atom(report)
        while self._peek() and self._peek().upper() == "AND":
            self._consume()
            right = self._parse_atom(report)
            result = result and right
        return result

    def _parse_atom(self, report: ThreatReport) -> bool:
        tok = self._peek()
        if tok is None:
            raise ValueError("Unexpected end of query")
        if tok == "(":
            self._consume()
            result = self.parse_expr(report)
            self._expect(")")
            return result
        # predicate: field op value
        field = self._consume()
        op_tok = self._peek()
        if op_tok not in self._OPS:
            raise ValueError(f"Expected operator after field {field!r}, got {op_tok!r}")
        op = self._consume()
        value = self._consume()
        return _eval_predicate(report, field, op, value)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class ThreatQueryEngine:
    """
    Search a collection of :class:`~sentinel_weave.threat_detector.ThreatReport`
    objects using a simple query language.

    Parameters
    ----------
    reports:
        The report collection to search.  The list is stored by reference;
        calling :meth:`add` mutates the same collection seen by subsequent
        :meth:`query` calls.

    Examples
    --------
    ::

        engine = ThreatQueryEngine(reports)
        high_ssh = engine.query(
            "threat_level = HIGH AND source_ip ~ 10.0.0."
        )
        brute_force = engine.query("signature ~ BRUTE")
    """

    def __init__(self, reports: list[ThreatReport] | None = None) -> None:
        self._reports: list[ThreatReport] = list(reports) if reports else []

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add(self, report: ThreatReport) -> None:
        """Append *report* to the internal collection."""
        self._reports.append(report)

    def add_bulk(self, reports: Sequence[ThreatReport]) -> None:
        """Append all *reports* to the internal collection."""
        self._reports.extend(reports)

    def clear(self) -> None:
        """Remove all reports from the internal collection."""
        self._reports.clear()

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def query(self, query_str: str) -> list[ThreatReport]:
        """
        Return all reports that match *query_str*.

        Parameters
        ----------
        query_str:
            Query expression — see module docstring for syntax.

        Returns
        -------
        list[ThreatReport]
            Filtered list in the same order as the internal collection.

        Raises
        ------
        ValueError
            If the query cannot be parsed or references an unknown field.
        """
        query_str = query_str.strip()
        if not query_str:
            return list(self._reports)

        tokens = _tokenise(query_str)
        if not tokens:
            return list(self._reports)

        results: list[ThreatReport] = []
        for report in self._reports:
            parser = _Parser(list(tokens))
            if parser.parse_expr(report):
                results.append(report)
        return results

    def query_one(self, query_str: str) -> ThreatReport | None:
        """Return the first matching report, or *None*."""
        results = self.query(query_str)
        return results[0] if results else None

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def count(self, query_str: str = "") -> int:
        """Return the number of reports matching *query_str* (all if empty)."""
        return len(self.query(query_str))

    def fields(self) -> list[str]:
        """Return the list of queryable field names."""
        return [
            "threat_level",
            "source_ip",
            "event_type",
            "anomaly_score",
            "signature",
            "raw",
            "explanation",
        ]

    def __len__(self) -> int:
        return len(self._reports)

    def __repr__(self) -> str:
        return f"ThreatQueryEngine({len(self._reports)} reports)"
