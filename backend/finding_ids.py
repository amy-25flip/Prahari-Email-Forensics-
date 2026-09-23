"""Stable, deterministic finding/check identifiers, assigned once at each
result's finalization point (not scattered across every flag()/add() call
site across the codebase). Re-analyzing the SAME email content reproduces
the SAME id for the SAME underlying finding -- so a forensic report, a PDF/
JSON export, or a second independent reviewer can cite "finding a3f9c1d2"
and have that reference mean something stable across re-analysis, exports,
and time, rather than only a loose prose description.

Honest scope:
- The id is a hash of (category, title, detail). Many detail strings embed a
  specific evidence value (a URL, a domain, a header name, an address), but
  NOT all producers in this codebase do -- some emit intentionally generic
  text (e.g. a structural "Suspicious URL" reason shared by several distinct
  URLs in the same report). Two genuinely different findings that happen to
  render identical category+title+detail text would collide onto the same
  id if id assignment stopped there -- so assign() also folds in each
  entry's occurrence index among duplicates-so-far IN THE SAME LIST, which
  keeps same-content duplicates distinguishable (a real forensic citation
  concern) while staying fully deterministic given the same input, since
  every producer in this codebase builds its list in a fixed order for the
  same input content.
- This does NOT protect against a finding whose own text embeds a live
  external lookup result (e.g. a reputation classification) that could
  itself differ between two runs at different times -- that is the
  finding's content genuinely changing, not a flaw in id assignment; the id
  is only ever as stable as the text it is computed from.
- Ids are a reference/citation aid, not a new trust or scoring signal --
  they carry no security meaning of their own, and (being an unsalted hash
  truncated to 64 bits) are not a redaction or privacy-protection mechanism.
"""
import hashlib
from collections import defaultdict

ID_LENGTH = 16


def assign(entries, category_key):
    """Mutates each dict in `entries` in place, adding a stable 'id' field.
    category_key is whichever key that shape uses for its category ('group'
    for engine.py findings, 'kind' for ps_assessment/conversation/network_history-
    style checks). Returns `entries` for convenient chaining."""
    seen = defaultdict(int)
    for entry in entries:
        basis = '|'.join((str(entry.get(category_key, '')), str(entry.get('title', '')), str(entry.get('detail', ''))))
        occurrence = seen[basis]
        seen[basis] += 1
        # The occurrence index is folded in for every entry, not only
        # repeats: this keeps the FIRST occurrence's id identical to what a
        # smaller, duplicate-free list would have produced, so ids stay
        # stable if a caller's list composition changes elsewhere in ways
        # that don't affect this particular finding's own duplicate count.
        full_basis = f'{basis}|{occurrence}'
        entry['id'] = hashlib.sha256(full_basis.encode('utf-8', errors='replace')).hexdigest()[:ID_LENGTH]
    return entries
