"""포트 범위 입력 검증.

nuclei 에는 포트 범위 옵션이 없어 REDAR 가 개별 대상으로 펼침.
표기는 두 층 - 요약은 입력 원문, 개별 탐지는 실제 포트 (docs/04 조치 대상 특정)
"""
from __future__ import annotations

import pytest

from app.domain import target_range as tr


# ─────────────────────────────── 전개

@pytest.mark.parametrize(
    "text,expected",
    [
        ("localhost:80-82", ["localhost:80", "localhost:81", "localhost:82"]),
        ("http://h:8080-8081", ["http://h:8080", "http://h:8081"]),
        # 스킴·경로 보존. 경로를 잃으면 다른 대상이 됨
        ("http://h:80-81/api", ["http://h:80/api", "http://h:81/api"]),
        ("localhost:7860", ["localhost:7860"]),        # 범위 아님
        ("localhost", ["localhost"]),
        ("localhost:80-80", ["localhost:80"]),         # 한 포트짜리 범위
    ],
)
def test_expand_one(text, expected):
    assert tr.expand_one(text) == expected


def test_expand_dedupes_preserving_order():
    """같은 대상을 두 번 스캔하지 않음"""
    result = tr.expand(["localhost:80", "localhost:79-81"])
    assert result.targets == [
        "localhost:80", "localhost:79", "localhost:81",
    ]
    assert result.raw == ["localhost:80", "localhost:79-81"]


def test_expanded_flag_only_when_range_used():
    assert tr.expand(["localhost:7860"]).expanded is False
    assert tr.expand(["localhost:80-90"]).expanded is True


@pytest.mark.parametrize("text", ["localhost:90-80", "localhost:0-10",
                                  "localhost:1-70000"])
def test_invalid_range_rejected(text):
    with pytest.raises(tr.RangeError):
        tr.expand_one(text)


def test_over_max_rejected():
    """대상이 곱으로 늘어 스캔 시간·대상 부하가 함께 커짐"""
    with pytest.raises(tr.RangeError, match="범위 축소"):
        tr.expand([f"localhost:1-{tr.MAX_PORTS + 1}"])


def test_max_boundary_allowed():
    assert len(tr.expand([f"localhost:1-{tr.MAX_PORTS}"]).targets) == tr.MAX_PORTS


# ─────────────────────────────── 허용 목록 판정

def test_hosts_strips_range():
    """판정은 호스트 기준. 전개 결과 전체를 검사하면 같은 호스트를 수천 번 봄"""
    assert tr.hosts(["localhost:33-4444"]) == ["localhost"]
    assert tr.hosts(["http://target.local:80-90/x"]) == ["target.local"]


def test_hosts_dedupes():
    assert tr.hosts(["localhost:80-90", "http://localhost:7860"]) == ["localhost"]


# ─────────────────────────────── 표기

def test_describe_reads_as_range():
    assert tr.describe("localhost:33-4444") == "localhost · 포트 33~4444"
    assert tr.describe("localhost:7860") is None
