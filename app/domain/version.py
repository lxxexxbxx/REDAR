"""버전 비교.

문자열 비교는 '4.10.1' < '4.9.0' 으로 오판. 패치 목표를 낮게 제시하면 조치 후에도 취약 상태 유지

sort_key() 출력 형식은 component_advisories.fixed_version_key 와 일치 필수.
해당 값은 tools/build_data_csv.py 의 vkey() 산출물이며 v_patch_plan 이 문자열 비교.
형식 불일치 시 오류 없이 패치 목표만 소실. tests/test_domain.py 가 951행 전체 대조
"""
from __future__ import annotations

_SEGMENTS = 4  # tools/build_data_csv.py 와 동일. 5번째 이후 세그먼트 폐기
_WIDTH = 5


def sort_key(version: str | None) -> str:
    """'4.10.1' -> '00004.00010.00001'. 사전순 비교 = 버전순 비교."""
    if not version:
        return ""
    return ".".join(
        f"{int(p):0{_WIDTH}d}" if p.isdigit() else p.rjust(_WIDTH, "0")
        for p in str(version).split(".")[:_SEGMENTS]
    )


def compare(a: str | None, b: str | None) -> int:
    """a<b -> -1, a==b -> 0, a>b -> 1.

    '4.2' 와 '4.2.0' 은 자리수 차이로 전자가 작게 판정. 의미상 동일하나
    패치 판정에서 '더 올려야 함' 쪽으로 기울어 안전
    """
    ka, kb = sort_key(a), sort_key(b)
    return (ka > kb) - (ka < kb)


def is_outdated(installed: str | None, fixed: str | None) -> bool:
    """설치 버전 < 패치 버전 여부. 한쪽이라도 불명이면 판정 보류."""
    if not installed or not fixed:
        return False
    return compare(installed, fixed) < 0


def max_version(versions: list[str | None]) -> str | None:
    """최고 버전. max() 에 문자열 직접 투입하는 실수 방지용 래퍼."""
    known = [v for v in versions if v]
    return max(known, key=sort_key) if known else None
