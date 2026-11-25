from __future__ import annotations

import re
from dataclasses import dataclass, field

from .sniff import CATEGORY_NAMES, ext_of, category_of

_TOKEN = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+|[^\W\d_]+", re.UNICODE)


def tokens(text: str) -> set[str]:
    """Split a path/name into lowercase word tokens (handles snake_case, camelCase, digits, Arabic)."""
    out = set()
    for part in re.split(r"[\\/ ._\-\[\]\(\)]+", text):
        for t in _TOKEN.findall(part):
            out.add(t.lower())
    return out


def _term_hit(term: str, toks: set[str], text_lower: str, substring: bool) -> bool:
    term = term.lower().strip()
    if not term:
        return False
    if substring or not term.isascii() or " " in term:
        return term in text_lower
    if term in toks or term + "s" in toks or term + "es" in toks:
        return True
    return term.endswith("s") and term[:-1] in toks


@dataclass
class Keyword:
    label: str
    terms: list[str]


def parse_keywords(spec: str | None) -> list[Keyword]:
    """'trees=tree|pine|palm,houses=house|cottage,rock' -> [Keyword...]  (label defaults to the first term)."""
    out = []
    for item in (spec or "").split(","):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            label, terms = item.split("=", 1)
        else:
            label, terms = item, item
        ts = [t.strip() for t in terms.split("|") if t.strip()]
        label = re.sub(r"[^\w\-]+", "_", label.strip(), flags=re.UNICODE) or ts[0]
        out.append(Keyword(label, ts))
    return out


@dataclass
class Filters:
    exts: set = field(default_factory=set)
    categories: set = field(default_factory=set)
    keywords: list = field(default_factory=list)
    exclude: list = field(default_factory=list)
    match_content: bool = True
    substring: bool = False

    @property
    def any_active(self) -> bool:
        return bool(self.exts or self.categories or self.keywords or self.exclude)

    @property
    def type_filter(self) -> bool:
        return bool(self.exts or self.categories)

    def type_ok(self, name: str) -> bool:
        if not self.type_filter:
            return True
        return ext_of(name) in self.exts or category_of(name) in self.categories

    def excluded(self, text: str) -> bool:
        if not self.exclude:
            return False
        low = text.lower(); tk = tokens(text)
        return any(_term_hit(t, tk, low, self.substring) for t in self.exclude)

    def keyword_label(self, *texts: str) -> str | None:
        """First keyword whose term appears in any of the texts (path and/or internal names)."""
        joined = " ".join(texts); low = joined.lower(); tk = tokens(joined)
        for kw in self.keywords:
            if any(_term_hit(t, tk, low, self.substring) for t in kw.terms):
                return kw.label
        return None


def parse_categories(spec: str | None) -> set:
    cats = set()
    for c in (spec or "").split(","):
        c = c.strip().lower()
        if not c:
            continue
        if c not in CATEGORY_NAMES:
            raise SystemExit(f"فئة غير معروفة: {c}. المتاح: {', '.join(CATEGORY_NAMES)}")
        cats.add(c)
    return cats


def parse_exts(spec: str | None) -> set:
    return {e.strip().lower().lstrip(".") for e in (spec or "").split(",") if e.strip()}
