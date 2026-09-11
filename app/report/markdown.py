"""LLM 조치 가이드 본문 -> 보고서용 HTML.

라이브러리를 넣지 않는다. 보고서는 자체 완결형 HTML 이고 외부 참조가 0이어야 하며
(절대규칙 4-1), 이 변환기가 만드는 태그는 renderer.active_content 검사를 통과해야 함

**입력은 LLM 응답이므로 신뢰하지 않는다.** 먼저 전부 이스케이프한 뒤 서식만 되살린다.
그래서 원문에 <script> 가 들어 있어도 글자로만 남는다

서식 규칙은 frontend/js/remediation.js 의 markdown() 과 같다. 화면에서 본 가이드와
보고서에 실린 가이드가 다르게 보이면 어느 쪽이 원본인지 알 수 없어짐

제목 단계는 h3 부터 시작한다. 보고서는 h1 이 파트, h2 가 절이므로 가이드가 h1 을
쓰면 파트로 보인다
"""
from __future__ import annotations

import re
from html import escape

from markupsafe import Markup

_FENCE_RE = re.compile(r"^\s*```")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_ITEM_RE = re.compile(r"^\s*(?:[-*]|\d+\.)\s+(.*)$")
_ROW_RE = re.compile(r"^\s*\|(.+)\|\s*$")
# |---|:--:|---| 구분줄. 표 머리와 본문을 가르는 줄이며 출력하지 않음
_DIVIDER_RE = re.compile(r"^\s*\|[\s:|-]+\|\s*$")

_CODE_RE = re.compile(r"`([^`]+)`")
_STRONG_RE = re.compile(r"\*\*([^*]+)\*\*")

# 보고서 제목 계층과 겹치지 않도록 h1 -> h3 으로 내림
_HEADING_OFFSET = 2
_MAX_HEADING = 6


def _inline(text: str) -> str:
    """이미 이스케이프된 한 줄에 인라인 서식만 되살림"""
    out = _CODE_RE.sub(r"<code>\1</code>", text)
    return _STRONG_RE.sub(r"<strong>\1</strong>", out)


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


class _Builder:
    """블록 상태를 들고 줄 단위로 쌓는다. 열린 블록은 끝에서 반드시 닫음"""

    def __init__(self) -> None:
        self.out: list[str] = []
        self.in_code = False
        self.in_list = False
        self.table: list[list[str]] = []

    def close_list(self) -> None:
        if self.in_list:
            self.out.append("</ul>")
            self.in_list = False

    def close_table(self) -> None:
        if not self.table:
            return
        head, *body = self.table
        self.out.append('<table class="guide-table">')
        self.out.append(
            "<thead><tr>"
            + "".join(f"<th>{_inline(c)}</th>" for c in head)
            + "</tr></thead>"
        )
        if body:
            self.out.append("<tbody>")
            for row in body:
                self.out.append(
                    "<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in row) + "</tr>"
                )
            self.out.append("</tbody>")
        self.out.append("</table>")
        self.table = []

    def close_blocks(self) -> None:
        self.close_list()
        self.close_table()


def to_html(text: str | None) -> Markup:
    """Markdown -> 보고서 HTML 조각. 빈 입력은 빈 문자열"""
    if not text or not text.strip():
        return Markup("")

    builder = _Builder()
    for raw in escape(text).split("\n"):
        if _FENCE_RE.match(raw):
            builder.close_blocks()
            builder.out.append(
                "</code></pre>" if builder.in_code
                else '<pre class="codeblock"><code>'
            )
            builder.in_code = not builder.in_code
            continue
        if builder.in_code:
            # 코드 블록 안은 서식을 적용하지 않음. 명령을 그대로 복사해야 함
            builder.out.append(raw)
            continue

        if _DIVIDER_RE.match(raw):
            continue                          # 표 구분줄. 출력하지 않음
        row = _ROW_RE.match(raw)
        if row:
            builder.close_list()
            builder.table.append(_cells(row.group(1)))
            continue
        builder.close_table()

        heading = _HEADING_RE.match(raw)
        if heading:
            builder.close_list()
            level = min(len(heading.group(1)) + _HEADING_OFFSET, _MAX_HEADING)
            builder.out.append(
                f"<h{level}>{_inline(heading.group(2))}</h{level}>"
            )
            continue

        item = _ITEM_RE.match(raw)
        if item:
            if not builder.in_list:
                builder.out.append("<ul>")
                builder.in_list = True
            builder.out.append(f"<li>{_inline(item.group(1))}</li>")
            continue

        if not raw.strip():
            builder.close_list()
            continue

        builder.close_list()
        builder.out.append(f"<p>{_inline(raw)}</p>")

    if builder.in_code:
        builder.out.append("</code></pre>")
    builder.close_blocks()
    return Markup("\n".join(builder.out))
