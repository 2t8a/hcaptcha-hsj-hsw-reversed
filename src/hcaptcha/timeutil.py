"""Time helpers — Beijing time (UTC+8) timestamps for generated artefacts."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

# China Standard Time = UTC+8, no DST.
BEIJING = timezone(timedelta(hours=8), name="Asia/Shanghai")


def beijing_now() -> datetime:
    return datetime.now(BEIJING)


def beijing_now_iso() -> str:
    """Precise Beijing timestamp, millisecond precision + explicit offset.

    Example: ``2026-10-10T22:30:15.123+08:00``
    """
    return beijing_now().isoformat(timespec="milliseconds")


def beijing_now_str() -> str:
    """Human-readable Beijing timestamp, second precision.

    Example: ``2026-10-10 22:30:15 (UTC+8)``
    """
    return beijing_now().strftime("%Y-%m-%d %H:%M:%S") + " (UTC+8)"
