"""Apache httpd 수집기. 버전 + 원격에서 보이는 모듈 흔적.

모듈 목록은 원격에서 완전히 알 수 없다. 흔적만 medium/low 로 남기고
확정 목록으로 표기하지 않음 (M4 규칙 3)
"""
from __future__ import annotations

import re

from app.collectors.base import (
    ORDER_MIDDLEWARE,
    CollectResult,
    ComponentFinding,
    StackFinding,
    TargetContext,
)
from app.domain.enums import Confidence

_SERVER_RE = re.compile(r"Apache(?:/([\d.]+))?", re.I)

# 원격 응답에 흔적이 남는 모듈. (헤더 또는 본문 표지, 모듈명)
_MODULE_HINTS = (
    ("x-powered-by", "php", "mod_php"),
    ("dav", "", "mod_dav"),
    ("content-encoding", "gzip", "mod_deflate"),
)


class ApacheCollector:
    key = "apache"
    label = "Apache httpd"
    version = "0.1.0"
    detects = ("version", "modules")
    order = ORDER_MIDDLEWARE

    def applicable(self, ctx: TargetContext) -> bool:
        """generic-http 가 이미 읽은 Server 헤더를 참조 (docs/01 §4.1)"""
        upstream = ctx.collected.get("generic-http")
        if upstream and upstream.web_server and upstream.web_server.product:
            return "apache" in upstream.web_server.product.lower()
        return bool(_SERVER_RE.search(ctx.get("/").header("server")))

    def collect(self, ctx: TargetContext) -> CollectResult:
        root = ctx.get("/")
        server = root.header("server")
        match = _SERVER_RE.search(server)
        version = match.group(1) if match else None

        result = CollectResult(
            web_server=StackFinding(
                product="Apache httpd",
                version=version,
                confidence=Confidence.HIGH if version else Confidence.LOW,
                evidence=f"Server: {server[:120]}" if server else "Server 헤더 없음",
            )
        )

        for header, marker, module in _MODULE_HINTS:
            value = root.header(header).lower()
            if value and (not marker or marker in value):
                result.components.append(
                    ComponentFinding(
                        type="apache_module",
                        slug=module,
                        # 헤더 흔적은 정황. 모듈 목록 조회가 아니므로 low
                        confidence=Confidence.LOW,
                        evidence=f"{header}: {value[:80]}",
                    )
                )
        return result


COLLECTOR = ApacheCollector()
