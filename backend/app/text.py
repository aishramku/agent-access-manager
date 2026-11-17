"""Small text and time helpers shared by the router, checker and actions."""

from __future__ import annotations

import re

_TIME_RE = re.compile(r"\b(\d{1,2})(?::(\d{2}))?\s*(am|pm|a\.m\.|p\.m\.)?(?![\d:])|\b(noon|midday)\b")


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower().replace("’", "'").replace("‘", "'")).strip()


def has_word(text: str, keyword: str) -> bool:
    """True when `keyword` starts at a word boundary in `text` ("file" matches "files")."""
    return re.search(r"\b" + re.escape(keyword), text) is not None


def parse_times(text: str) -> list[int]:
    """Return times found in the text, as minutes after midnight."""
    out: list[int] = []
    for m in _TIME_RE.finditer(text):
        if m.group(4):
            out.append(12 * 60)
            continue
        hour, minute = int(m.group(1)), int(m.group(2) or 0)
        ampm = (m.group(3) or "").replace(".", "")
        if hour > 23 or minute > 59:
            continue
        if ampm == "pm" and hour < 12:
            hour += 12
        if ampm == "am" and hour == 12:
            hour = 0
        if not ampm and 1 <= hour <= 7:  # "move it to 4" means 4 PM during office hours
            hour += 12
        out.append(hour * 60 + minute)
    return out


def fmt_time(minutes: int | None) -> str:
    if minutes is None:
        return "?"
    h, m = divmod(minutes, 60)
    return f"{h % 12 or 12}:{m:02d} {'PM' if h >= 12 else 'AM'}"


def fmt_duration(seconds: float) -> str:
    if seconds <= 0:
        return "00:00"
    s = int(seconds + 0.999)
    return f"{s // 60:02d}:{s % 60:02d}"


def sentence(s: str) -> str:
    return s if s.endswith((".", "!", "?")) else s + "."
