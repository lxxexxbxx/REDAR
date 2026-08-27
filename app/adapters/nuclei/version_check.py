"""nuclei 가용성 확인. 실행·파싱은 runner.py / parser.py."""
from __future__ import annotations

import re
import subprocess
from functools import lru_cache

from app.config import settings

_VERSION_RE = re.compile(r"v?(\d+\.\d+\.\d+)")


@lru_cache(maxsize=1)
def version() -> str | None:
    """`nuclei -version` 결과. 미설치·실행 실패 시 None. 프로세스 수명 동안 캐시."""
    exe = settings.nuclei_bin()
    if not exe:
        return None
    try:
        proc = subprocess.run(
            [exe, "-version"], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return None
    # 버전을 stderr 로 내는 릴리스 존재
    found = _VERSION_RE.search(proc.stdout + proc.stderr)
    return found.group(1) if found else None
