"""Unit tests for timeutil (Beijing-time timestamps). No network / Node."""
from datetime import datetime, timedelta, timezone

from hcaptcha.timeutil import (
    BEIJING,
    beijing_now,
    beijing_now_iso,
    beijing_now_str,
)


def test_offset_is_utc_plus_8():
    assert BEIJING.utcoffset(None) == timedelta(hours=8)


def test_now_is_aware():
    now = beijing_now()
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(hours=8)


def test_iso_round_trips_and_has_offset():
    s = beijing_now_iso()
    assert s.endswith("+08:00")
    # millisecond precision => exactly 3 fractional digits
    assert "." in s
    frac = s.split(".")[1].split("+")[0]
    assert len(frac) == 3
    parsed = datetime.fromisoformat(s)
    assert parsed.utcoffset() == timedelta(hours=8)


def test_readable_format():
    s = beijing_now_str()
    assert s.endswith("(UTC+8)")
    # "YYYY-MM-DD HH:MM:SS (UTC+8)"
    assert len(s.split(" ")[0]) == 10


def test_iso_matches_utc_now():
    """Beijing time should be UTC+8 of the same instant (within a minute)."""
    bj = beijing_now()
    utc = datetime.now(timezone.utc)
    delta = abs((utc - bj).total_seconds())
    assert delta < 60
