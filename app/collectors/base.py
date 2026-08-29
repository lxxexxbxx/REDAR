"""수집기 프로토콜 · 레지스트리 · HTTP 프로브 (docs/01 §4.1).

절대 규칙 (IMPLEMENTATION_BRIEF M4)
  1. 읽기 전용. 대상 상태를 변경하는 요청을 보내지 않음 -> GET/HEAD 만 허용
  2. 수집기 실패는 예외를 전파하지 않음. collectors_failed 에 기록하고 계속
  3. 확신할 수 없으면 version=None + confidence=low. 추정값의 확정 표기 금지
  4. 타임아웃 필수
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
import socket
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from app import __version__
from app.domain.enums import Confidence

logger = logging.getLogger(__name__)

# 응답 본문 상한. 대상 부하와 메모리 모두 통제. 버전 표기는 앞부분에 있음
_MAX_BODY_BYTES = 256 * 1024
_ALLOWED_METHODS = frozenset({"GET", "HEAD"})

# 실행 순서. generic-http -> 애플리케이션 -> 미들웨어 (docs/01 §4.1)
ORDER_GENERIC = 10
ORDER_APPLICATION = 20
ORDER_MIDDLEWARE = 30


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]          # 키는 소문자로 정규화
    text: str
    url: str
    error: str | None = None            # 요청 자체 실패. 수집기는 이걸 보고 판단 보류

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 400

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


@dataclass
class StackFinding:
    product: str | None = None
    version: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    evidence: str | None = None


@dataclass
class ComponentFinding:
    type: str
    slug: str
    name: str | None = None
    version: str | None = None
    active: bool | None = None
    confidence: Confidence = Confidence.MEDIUM
    evidence: str | None = None


@dataclass
class ExposureFinding:
    key: str
    value: bool
    path: str | None = None
    evidence: str | None = None


@dataclass
class CollectResult:
    """수집기 1개의 산출물. 비어 있어도 실패가 아님"""

    web_server: StackFinding | None = None
    language: StackFinding | None = None
    application: StackFinding | None = None
    components: list[ComponentFinding] = field(default_factory=list)
    exposures: list[ExposureFinding] = field(default_factory=list)


@dataclass
class TargetContext:
    """수집 대상 1개. http 는 주입 가능 - 테스트가 실제 요청 없이 돌아야 한다"""

    scheme: str
    host: str
    port: int | None
    timeout_sec: int = 5
    http: Callable[..., Response] | None = None
    # 앞선 수집기 결과. applicable() 이 상위 판단을 참조 (docs/01 §4.1)
    collected: dict[str, CollectResult] = field(default_factory=dict)

    @property
    def origin(self) -> str:
        default = {"http": 80, "https": 443}.get(self.scheme)
        if self.port and self.port != default:
            return f"{self.scheme}://{self.host}:{self.port}"
        return f"{self.scheme}://{self.host}"

    @property
    def target_host(self) -> str:
        return f"{self.host}:{self.port}" if self.port else self.host

    def get(self, path: str, *, method: str = "GET") -> Response:
        fetch = self.http or fetch_url
        return fetch(f"{self.origin}{path}", method=method, timeout=self.timeout_sec)

    def component_slugs(self, *types: str) -> set[str]:
        """앞선 수집기가 찾은 구성요소 슬러그. 제한 플러그인 존재 판단 등에 사용"""
        wanted = set(types)
        return {
            c.slug
            for result in self.collected.values()
            for c in result.components
            if not wanted or c.type in wanted
        }


@runtime_checkable
class Collector(Protocol):
    key: str
    label: str
    version: str
    detects: tuple[str, ...]
    order: int

    def applicable(self, ctx: TargetContext) -> bool: ...

    def collect(self, ctx: TargetContext) -> CollectResult: ...


def fetch_url(url: str, *, method: str = "GET", timeout: int = 5) -> Response:
    """HTTP 요청 1건. 실패를 예외로 올리지 않고 Response.error 로 돌려줌

    GET/HEAD 만 허용. 대상 상태를 바꾸는 메서드는 코드 수준에서 차단 (M4 규칙 1)
    """
    if method not in _ALLOWED_METHODS:
        raise ValueError(f"읽기 전용 수집기에서 허용되지 않는 메서드: {method}")

    request = urllib.request.Request(
        url, method=method, headers={"User-Agent": f"REDAR/{__version__}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            body = resp.read(_MAX_BODY_BYTES) if method == "GET" else b""
            return Response(
                status=resp.status,
                headers={k.lower(): v for k, v in resp.headers.items()},
                text=body.decode("utf-8", errors="replace"),
                url=resp.url,
            )
    except urllib.error.HTTPError as exc:
        # 404·403 도 판단 근거. 오류가 아니라 응답으로 취급
        body = b""
        try:
            body = exc.read(_MAX_BODY_BYTES)
        except Exception:  # noqa: BLE001 - 본문 없는 오류 응답
            pass
        return Response(
            status=exc.code,
            headers={k.lower(): v for k, v in (exc.headers or {}).items()},
            text=body.decode("utf-8", errors="replace"),
            url=url,
        )
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
        return Response(status=0, headers={}, text="", url=url, error=str(exc))


def registry() -> list[Collector]:
    """collectors/ 안의 모듈에서 COLLECTOR 를 수집함

    파일 추가만으로 등록되어야 한다 (M4 완료 조건). 등록표를 따로 두면 누락이 생김
    """
    package = importlib.import_module(__package__)
    found: list[Collector] = []
    for info in pkgutil.iter_modules(package.__path__):
        if info.name.startswith("_") or info.name == "base":
            continue
        module = importlib.import_module(f"{__package__}.{info.name}")
        collector = getattr(module, "COLLECTOR", None)
        if collector is None:
            logger.warning("수집기 모듈에 COLLECTOR 없음: %s", info.name)
            continue
        found.append(collector)
    return sorted(found, key=lambda c: (c.order, c.key))


def describe() -> list[dict[str, object]]:
    """GET /collectors 응답 (docs/00 §4)."""
    return [
        {
            "key": c.key,
            "label": c.label,
            "version": c.version,
            "enabled": True,
            "detects": list(c.detects),
        }
        for c in registry()
    ]
