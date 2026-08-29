"""Jinja2 -> 자체 완결형 HTML (docs/04 §3.1).

WeasyPrint 를 쓰지 않음. PDF 는 WebView 인쇄로 파생 (절대규칙 4-1).
외부 CSS·폰트·이미지 참조 0. 전부 인라인 / base64 임베딩

폰트 base64 는 캐시. 보고서마다 재인코딩하면 1.1MB 를 매번 인코딩하게 됨
"""
from __future__ import annotations

import base64
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from app.config import settings

TEMPLATE_DIR = Path(__file__).parent / "templates"

# 본문 400/700 을 각각 등록. 하나만 등록하면 굵은 글씨가 fake bold 가 됨
_FONTS = (
    ("NanumGothic", 400, "normal", "NanumGothic.woff2"),
    ("NanumGothic", 700, "normal", "NanumGothicBold.woff2"),
    ("D2Coding", 400, "normal", "D2Coding.woff2"),
)

# 자체 완결형 검사. src/href/url() 에 외부 스킴이 있으면 위반
_EXTERNAL_REF = re.compile(
    r"""(?:src|href)\s*=\s*["'](https?://|//)|url\(\s*["']?(https?://|//)""",
    re.I,
)


@lru_cache(maxsize=1)
def font_faces() -> str:
    """@font-face 블록. local() 을 쓰지 않음 - 시스템 폰트 의존 금지"""
    blocks = []
    for family, weight, style, filename in _FONTS:
        path = settings.FONTS_DIR / filename
        if not path.is_file():
            continue
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        blocks.append(
            f"@font-face{{font-family:'{family}';font-weight:{weight};"
            f"font-style:{style};font-display:block;"
            f"src:url(data:font/woff2;base64,{encoded}) format('woff2');}}"
        )
    return "\n".join(blocks)


@lru_cache(maxsize=1)
def base_css() -> str:
    return (TEMPLATE_DIR / "report.css").read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
        undefined=StrictUndefined,      # 오타 필드를 조용히 빈칸으로 만들지 않는다
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["nz"] = lambda value, default="해당 없음": (
        default if value in (None, "", [], {}) else value
    )
    return env


def render_html(report: dict[str, Any]) -> str:
    """Report JSON -> HTML. 렌더러는 JSON 밖 DB 를 조회하지 않음"""
    template = _env().get_template("report.html.j2")
    return template.render(
        r=report,
        font_faces=font_faces(),
        base_css=base_css(),
    )


def external_references(html: str) -> list[str]:
    """자체 완결형 검사용. 반환값이 비어야 한다 (TC-R12)"""
    return ["".join(m) for m in _EXTERNAL_REF.findall(html)]


def filename(report: dict[str, Any], ext: str) -> str:
    """report_{host}_{yyyymmdd_hhmm}.{ext} (docs/04 §7)"""
    meta = report.get("meta") or {}
    host = (meta.get("target_summary") or "unknown").replace(" ", "")
    stamp = (meta.get("scan_started_at") or "").replace("-", "").replace(":", "")
    stamp = stamp.replace(" ", "_")[:13] or "unknown"
    safe = re.sub(r"[^0-9A-Za-z가-힣._외건-]", "-", host)
    return f"report_{safe}_{stamp}.{ext}"
