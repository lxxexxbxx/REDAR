"""ULID 기반 식별자.

docs/00 · db/schema.sql 이 'scn_' + ULID 형식을 지정.
외부 의존성 대신 26자 Crockford base32 로 직접 생성. 시간순 정렬 가능
"""
from __future__ import annotations

import secrets
import time

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32 (I,L,O,U 제외)
_LEN = 26


def ulid() -> str:
    """48비트 밀리초 타임스탬프 + 80비트 난수."""
    value = (int(time.time() * 1000) << 80) | secrets.randbits(80)
    chars = []
    for _ in range(_LEN):
        chars.append(_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def new_id(prefix: str) -> str:
    """'fnd' -> 'fnd_01K3...'."""
    return f"{prefix}_{ulid()}"
