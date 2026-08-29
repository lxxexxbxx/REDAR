"""WordPress 수집기. 버전·테마·플러그인 + 노출 8종.

exposure_key 8종의 정본은 docs/00 §1.2 (wordpress 담당분).
주 진단 대상이 WordPress 이므로 이 수집기가 환경 기반 선별의 핵심 입력을 생성
"""
from __future__ import annotations

import json
import re

from app.collectors.base import (
    ORDER_APPLICATION,
    CollectResult,
    ComponentFinding,
    ExposureFinding,
    StackFinding,
    TargetContext,
)
from app.domain.enums import Confidence

_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+([\d.]+)""",
    re.I,
)
_README_VERSION_RE = re.compile(r"[Vv]ersion\s+([\d.]+)")
_ASSET_RE = re.compile(
    r"/wp-content/(plugins|themes)/([a-z0-9][a-z0-9._-]*)/[^\"'\s>]*", re.I
)
_VER_PARAM_RE = re.compile(r"[?&]ver=([\w.\-]+)")

# 로그인 시도 제한을 제공하는 플러그인. 탐지되면 제한 없음으로 단정하지 않음
_LOGIN_LIMITERS = frozenset({
    "limit-login-attempts-reloaded", "limit-login-attempts", "loginizer",
    "wordfence", "better-wp-security", "ithemes-security-pro",
    "all-in-one-wp-security-and-firewall", "wp-cerber", "wps-hide-login",
    "wp-limit-login-attempts", "sucuri-scanner",
})

# 백업·설정 파일 노출 후보. 응답 본문은 기록하지 않음 - 자격증명이 들어있음
_BACKUP_PATHS = (
    "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save",
    "/wp-config.php.orig", "/wp-config.php.txt", "/wp-config.bak",
    "/.env", "/wp-config.php.old",
)

_LOGIN_PROBE_COUNT = 3


class WordPressCollector:
    key = "wordpress"
    label = "WordPress"
    version = "0.1.0"
    detects = ("wp_version", "wp_plugin", "wp_theme", "rest_exposure")
    order = ORDER_APPLICATION

    def applicable(self, ctx: TargetContext) -> bool:
        """WordPress 징후가 없으면 실행하지 않음. 무관한 대상에 8회 요청 금지"""
        root = ctx.get("/")
        if not root.status:
            return False
        body = root.text
        return bool(
            _GENERATOR_RE.search(body)
            or "/wp-content/" in body
            or "/wp-includes/" in body
            or root.header("link").find("/wp-json/") >= 0
        )

    def collect(self, ctx: TargetContext) -> CollectResult:
        result = CollectResult()
        root = ctx.get("/")

        readme = ctx.get("/readme.html")
        version, version_evidence, exposed = _detect_version(root, readme)
        result.application = StackFinding(
            product="WordPress",
            version=version,
            # 버전 확정 불가 시 None + low. 추정값을 확정처럼 두지 않음 (M4 규칙 3)
            confidence=Confidence.HIGH if version else Confidence.LOW,
            evidence=version_evidence,
        )
        result.components = _detect_components(root.text, version)

        slugs = {c.slug for c in result.components} | ctx.component_slugs()
        result.exposures = [
            _xmlrpc(ctx),
            _rest_user_enum(ctx),
            _readme(readme),
            ExposureFinding(
                key="wp_version_exposed", value=exposed, path="/",
                evidence=version_evidence,
            ),
            *_login(ctx, slugs),
            _admin_page(ctx),
            _backup_files(ctx),
        ]
        return result


def _detect_version(root, readme) -> tuple[str | None, str, bool]:
    """(버전, 근거, 외부 노출 여부).

    노출 여부는 '우리가 원격에서 알아낼 수 있었는가' 와 같음
    """
    match = _GENERATOR_RE.search(root.text)
    if match:
        return match.group(1), f"meta generator: WordPress {match.group(1)}", True
    if readme.ok and "wordpress" in readme.text.lower():
        found = _README_VERSION_RE.search(readme.text)
        if found:
            return found.group(1), f"/readme.html: {found.group(1)}", True
        return None, "/readme.html 접근 가능하나 버전 표기 없음", True
    return None, "meta generator·readme 모두에서 버전 확인 불가", False


def _detect_components(body: str, wp_version: str | None) -> list[ComponentFinding]:
    """정적 자산 경로에서 플러그인·테마 추출.

    ?ver= 값이 WordPress 본체 버전과 같으면 구성요소 버전이 아니라 캐시 버스터
    구분이 불가하므로 version=None + low 로 둠 (M4 규칙 3)
    """
    found: dict[tuple[str, str], ComponentFinding] = {}
    for match in _ASSET_RE.finditer(body):
        kind, slug = match.group(1).lower(), match.group(2).lower()
        ctype = "wp_plugin" if kind == "plugins" else "wp_theme"
        asset = match.group(0)
        ver = _VER_PARAM_RE.search(asset)
        version = ver.group(1) if ver else None
        ambiguous = version is not None and version == wp_version
        key = (ctype, slug)

        candidate = ComponentFinding(
            type=ctype,
            slug=slug,
            version=None if ambiguous else version,
            # 자산 경로에 나타나면 로드된 것이므로 활성으로 봄
            active=True,
            confidence=(
                Confidence.MEDIUM if version and not ambiguous else Confidence.LOW
            ),
            evidence=(
                f"{asset[:120]} (ver 이 본체 버전과 동일해 판단 보류)"
                if ambiguous else asset[:120]
            ),
        )
        previous = found.get(key)
        # 같은 슬러그가 여러 자산에 나오면 버전이 확인된 쪽을 남김
        if previous is None or (previous.version is None and candidate.version):
            found[key] = candidate
    return sorted(found.values(), key=lambda c: (c.type, c.slug))


def _xmlrpc(ctx: TargetContext) -> ExposureFinding:
    """GET 은 405 + 안내 문구가 정상 응답. POST 는 보내지 않음 (M4 규칙 1)"""
    resp = ctx.get("/xmlrpc.php")
    enabled = resp.status == 405 or "xml-rpc server accepts post" in resp.text.lower()
    return ExposureFinding(
        key="xmlrpc_enabled", value=enabled, path="/xmlrpc.php",
        evidence=f"GET /xmlrpc.php {resp.status or resp.error}",
    )


def _rest_user_enum(ctx: TargetContext) -> ExposureFinding:
    path = "/wp-json/wp/v2/users"
    resp = ctx.get(path)
    listed = 0
    if resp.ok:
        try:
            payload = json.loads(resp.text)
            listed = sum(1 for u in payload if isinstance(u, dict) and "slug" in u)
        except (json.JSONDecodeError, TypeError):
            listed = 0
    return ExposureFinding(
        key="rest_user_enum", value=listed > 0, path=path,
        # 계정명 자체는 남기지 않음. 건수만 근거로 기록
        evidence=f"{resp.status or resp.error} · 계정 {listed}건 열거",
    )


def _readme(readme) -> ExposureFinding:
    return ExposureFinding(
        key="readme_accessible",
        value=readme.ok and "wordpress" in readme.text.lower(),
        path="/readme.html",
        evidence=f"GET /readme.html {readme.status or readme.error}",
    )


def _login(ctx: TargetContext, slugs: set[str]) -> list[ExposureFinding]:
    path = "/wp-login.php"
    responses = [ctx.get(path) for _ in range(_LOGIN_PROBE_COUNT)]
    first = responses[0]
    accessible = first.ok and "user_login" in first.text.lower()

    limiter = sorted(slugs & _LOGIN_LIMITERS)
    throttled = any(
        r.status == 429 or r.header("retry-after") for r in responses
    )
    # 인증 시도(POST)를 보내지 않으므로 '제한 없음' 은 단정이 아니라 관측 결과
    no_ratelimit = accessible and not throttled and not limiter

    return [
        ExposureFinding(
            key="wp_login_accessible", value=accessible, path=path,
            evidence=f"GET {path} {first.status or first.error}",
        ),
        ExposureFinding(
            key="wp_login_no_ratelimit", value=no_ratelimit, path=path,
            evidence=(
                f"GET x{_LOGIN_PROBE_COUNT} 제한 응답 없음 · 제한 플러그인 미탐지"
                if no_ratelimit else
                f"제한 응답 {throttled} · 제한 플러그인 {limiter or '없음'}"
            ),
        ),
    ]


def _admin_page(ctx: TargetContext) -> ExposureFinding:
    path = "/wp-admin/"
    resp = ctx.get(path)
    # 정상 설치는 wp-login.php 로 리다이렉트됨. 최종 URL 로 판별
    redirected_to_login = "wp-login.php" in resp.url
    public = resp.ok and not redirected_to_login
    return ExposureFinding(
        key="admin_page_public", value=public, path=path,
        evidence=f"GET {path} {resp.status or resp.error}"
                 + (" -> 로그인 리다이렉트" if redirected_to_login else ""),
    )


def _backup_files(ctx: TargetContext) -> ExposureFinding:
    """응답 본문을 근거에 남기지 않음. wp-config 백업에는 DB 자격증명이 있다"""
    for path in _BACKUP_PATHS:
        resp = ctx.get(path)
        if resp.ok and resp.text.strip():
            return ExposureFinding(
                key="dir_backup_files", value=True, path=path,
                evidence=f"{path} 접근 가능 ({resp.status}, {len(resp.text)}바이트)",
            )
    return ExposureFinding(
        key="dir_backup_files", value=False, path=_BACKUP_PATHS[0],
        evidence=f"백업 파일 후보 {len(_BACKUP_PATHS)}개 전부 접근 불가",
    )


COLLECTOR = WordPressCollector()
