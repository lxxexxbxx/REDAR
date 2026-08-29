"""공통 HTTP 수집기. 웹서버·언어 런타임 식별 + 서버 무관 노출 3종.

exposure_key 3종의 정본은 docs/00 §1.2 (generic-http 담당분)
"""
from __future__ import annotations

import re
import socket
import ssl

from app.collectors.base import (
    ORDER_GENERIC,
    CollectResult,
    ComponentFinding,
    ExposureFinding,
    StackFinding,
    TargetContext,
)
from app.domain.enums import Confidence

# Server: Apache/2.4.52 (Ubuntu) -> 제품·버전 분리
_SERVER_RE = re.compile(r"^([A-Za-z][\w.+-]*)(?:/([\w.]+))?")
# X-Powered-By: PHP/7.4.33
_POWERED_RE = re.compile(r"^([A-Za-z][\w.+-]*)(?:/([\w.]+))?")

# 디렉터리 리스팅 후보. 대상마다 존재 여부가 달라 전부 확인하고 하나라도 걸리면 노출
_LISTING_PATHS = ("/wp-content/uploads/", "/uploads/", "/files/", "/images/")
_LISTING_MARKERS = ("index of /", "<title>index of", "directory listing for")

# 취약 프로토콜. TLS1.0/1.1 은 핸드셰이크가 성립하면 그 자체로 취약 설정
_WEAK_PROTOCOLS = (
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
)


class GenericHttpCollector:
    key = "generic-http"
    label = "공통 HTTP"
    version = "0.1.0"
    detects = ("server_header", "language_runtime", "tls", "directory_listing")
    order = ORDER_GENERIC

    def applicable(self, ctx: TargetContext) -> bool:
        return True                       # 모든 대상에 적용

    def collect(self, ctx: TargetContext) -> CollectResult:
        result = CollectResult()
        root = ctx.get("/")

        if root.ok or root.status:
            server = root.header("server")
            result.web_server = _parse_stack(server, "Server 헤더")
            result.exposures.append(_server_header_exposure(server))

            powered = root.header("x-powered-by")
            if powered:
                result.language = _parse_stack(powered, "X-Powered-By 헤더")

        result.exposures.append(_directory_listing(ctx))
        result.exposures.append(_tls_exposure(ctx))
        return result


def _parse_stack(raw: str, evidence: str) -> StackFinding:
    """제품·버전 분리. 버전 표기가 없으면 None + low (M4 규칙 3)"""
    if not raw:
        return StackFinding(confidence=Confidence.LOW, evidence=f"{evidence} 없음")
    match = _SERVER_RE.match(raw.strip())
    if not match:
        return StackFinding(confidence=Confidence.LOW, evidence=raw[:120])
    product, version = match.group(1), match.group(2)
    return StackFinding(
        product=product,
        version=version,
        # 헤더는 위조 가능하나 값이 있으면 high, 버전 미표기면 low
        confidence=Confidence.HIGH if version else Confidence.LOW,
        evidence=f"{evidence}: {raw[:120]}",
    )


def _server_header_exposure(raw: str) -> ExposureFinding:
    """제품명만 있으면 노출 아님. 버전까지 드러나면 노출 (WEB-16)"""
    has_version = bool(raw and _SERVER_RE.match(raw.strip()) and
                       _SERVER_RE.match(raw.strip()).group(2))
    return ExposureFinding(
        key="server_header_verbose",
        value=has_version,
        path="/",
        evidence=f"Server: {raw[:120]}" if raw else "Server 헤더 없음",
    )


def _directory_listing(ctx: TargetContext) -> ExposureFinding:
    checked = []
    for path in _LISTING_PATHS:
        resp = ctx.get(path)
        checked.append(f"{path} {resp.status or resp.error}")
        if resp.ok and any(m in resp.text.lower() for m in _LISTING_MARKERS):
            return ExposureFinding(
                key="directory_listing", value=True, path=path,
                evidence=f"{path} 응답에 인덱스 표기",
            )
    return ExposureFinding(
        key="directory_listing", value=False, path=_LISTING_PATHS[0],
        evidence="확인 경로에서 인덱스 표기 없음: " + ", ".join(checked),
    )


def _tls_exposure(ctx: TargetContext) -> ExposureFinding:
    """TLS 미제공 또는 TLS1.0/1.1 수락이면 취약 (WEB-20, WA-17)"""
    if ctx.scheme != "https":
        return ExposureFinding(
            key="tls_weak_config", value=True, path="/",
            evidence="대상이 평문 HTTP. TLS 미적용",
        )

    port = ctx.port or 443
    accepted = []
    for label, version in _WEAK_PROTOCOLS:
        if _handshake_ok(ctx.host, port, version, ctx.timeout_sec):
            accepted.append(label)
    if accepted:
        return ExposureFinding(
            key="tls_weak_config", value=True, path="/",
            evidence=f"취약 프로토콜 수락: {', '.join(accepted)}",
        )
    return ExposureFinding(
        key="tls_weak_config", value=False, path="/",
        evidence="TLS1.0/1.1 핸드셰이크 거부",
    )


def _handshake_ok(host: str, port: int, version, timeout: int) -> bool:
    """지정 프로토콜로만 핸드셰이크 시도. 성립하면 True"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # 취약 설정 확인이 목적이므로 인증서 검증은 하지 않음. 데이터를 주고받지 않음
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
    except ValueError:
        return False                       # 런타임 OpenSSL 이 해당 버전을 막아둔 경우
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return True
    except (ssl.SSLError, OSError):
        return False


COLLECTOR = GenericHttpCollector()
