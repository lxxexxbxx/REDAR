"""처리 과정 로그. **메모리에만 둔다.**

파일로 남기면 용량이 계속 늘고 사용자 데이터 경로를 관리해야 한다. 목적은
'지금 무엇이 돌고 있는지' 를 보는 것이므로 스캔 중과 직후만 남으면 충분함

두 겹으로 제한
  - 개수: 최근 _MAX 줄만 유지 (오래된 것부터 밀려남)
  - 시간: _TTL_SEC 지난 줄은 조회 시점에 걸러냄

파이썬 logging 과 nuclei 출력을 같은 버퍼에 모아 시간순으로 보여준다
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

# 링 버퍼 크기. 한 줄 200자 기준 대략 400KB 상한
_MAX = 2000
# 보관 시간. '스캔 끝나고 한동안' 에 해당
_TTL_SEC = 600.0

_lock = threading.Lock()
_entries: deque[Entry] = deque(maxlen=_MAX)
_seq = 0
_installed = False


@dataclass(frozen=True, slots=True)
class Entry:
    seq: int
    at: float
    level: str
    source: str
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "at": self.at,
            "level": self.level,
            "source": self.source,
            "message": self.message,
        }


def append(source: str, message: str, level: str = "INFO") -> None:
    """버퍼에 한 줄 추가. 어디서 호출해도 예외를 내지 않아야 함"""
    global _seq
    text = (message or "").rstrip()
    if not text:
        return
    with _lock:
        _seq += 1
        _entries.append(Entry(
            seq=_seq, at=time.time(), level=level,
            source=source, message=text[:2000],
        ))


def entries(after: int = 0, limit: int = 500) -> list[dict[str, Any]]:
    """after 이후의 줄. 화면이 커서를 들고 폴링"""
    cutoff = time.time() - _TTL_SEC
    with _lock:
        rows = [e for e in _entries if e.seq > after and e.at >= cutoff]
    return [e.as_dict() for e in rows[-limit:]]


def latest_seq() -> int:
    with _lock:
        return _seq


def clear() -> None:
    global _seq
    with _lock:
        _entries.clear()
        _seq = 0


class RingHandler(logging.Handler):
    """logging -> 버퍼. 파일·표준출력으로는 보내지 않음"""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            append(record.name, self.format(record), record.levelname)
        except Exception:  # noqa: BLE001 - 로깅이 앱을 죽이면 안 됨
            pass


def install(level: int = logging.INFO) -> None:
    """루트 로거에 한 번만 부착. 재호출은 무시"""
    global _installed
    if _installed:
        return
    handler = RingHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.setLevel(level)
    root = logging.getLogger()
    root.addHandler(handler)
    if root.level > level:
        root.setLevel(level)
    _installed = True
