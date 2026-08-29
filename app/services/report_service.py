"""보고서 생성 흐름 제어 (docs/04 §3).

파이프라인: 조회 -> 집계 -> 환경 -> 매핑 -> 판정 -> 조치 수집 -> JSON 완성 -> 렌더
[1]~[7] 은 결정론적이며 LLM(M9)은 [8] 에서 산문 필드만 덮음
"""
from __future__ import annotations

import hashlib
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from app.config import settings
from app.domain.ids import new_id
from app.report import builder, renderer
from app.repository import guide as guide_repo
from app.repository import reports as report_repo
from app.repository import scans as scan_repo
from app.services.scan_service import ScanError

logger = logging.getLogger(__name__)

# 사용자 쓰기 경로. 번들 디렉터리는 임시라 재시작 시 소실됨 (M10 [2])
REPORT_DIR = settings.REPORTS_DIR
# PDF 는 WebView 인쇄로 파생. 서버가 만들지 않음 (절대규칙 4-1)
FORMATS = ("html", "json")
PDF_NOTE = (
    "PDF 는 HTML 을 브라우저·앱에서 인쇄(Ctrl+P / Cmd+P)하여 'PDF 로 저장' 으로"
    " 생성합니다. 보고서 HTML 은 폰트를 포함한 자체 완결형 파일입니다."
)

DEFAULT_OPTIONS = {
    "use_llm": False,
    "include_guide_mapping": True,
    "include_evidence": True,
    "exclude_false_positives": True,
    "include_guide_cases": True,
}


def create(
    conn: sqlite3.Connection, scan_id: str, options: dict[str, Any] | None = None
) -> dict[str, Any]:
    """보고서 생성. 실패해도 reports 행에 사유가 남음"""
    if scan_repo.get_scan(conn, scan_id) is None:
        raise ScanError("NOT_FOUND", "스캔을 찾을 수 없습니다.", status_code=404)

    opts = {**DEFAULT_OPTIONS, **(options or {})}
    report_id = new_id("rpt")
    report_repo.insert(
        conn, report_id=report_id, scan_id=scan_id, options=opts,
        guide_status=guide_repo.status(conn),
    )

    try:
        report = builder.build(
            conn, scan_id, report_id=report_id,
            include_evidence=opts["include_evidence"],
            include_guide_cases=opts["include_guide_cases"],
            exclude_false_positives=opts["exclude_false_positives"],
            use_llm=opts["use_llm"],
        )
        report["generated_at"] = datetime.now().isoformat(timespec="seconds")

        if opts["use_llm"]:
            # M9. 실패해도 템플릿 문장이 남아 있어야 한다 (절대규칙 2)
            from app.services import narrative_service

            report = narrative_service.apply(conn, report)

        llm_meta = report["meta"]["llm"]
        report_repo.finish(
            conn, report_id, report_json=builder.dumps(report),
            llm_used=bool(llm_meta.get("used")),
            llm_provider=llm_meta.get("provider"),
            llm_model=llm_meta.get("model"),
            llm_prompt_version=llm_meta.get("prompt_version"),
            llm_fallback_count=int(llm_meta.get("fallback_count") or 0),
        )
        _write_files(conn, report)
    except Exception as exc:  # noqa: BLE001 - 실패 사유를 행에 남겨야 한다
        logger.exception("보고서 생성 실패 %s", report_id)
        report_repo.fail(conn, report_id, str(exc))
        raise ScanError("INTERNAL_ERROR", f"보고서 생성 실패: {exc}") from exc

    return report_repo.get(conn, report_id) or {}


def _write_files(conn: sqlite3.Connection, report: dict[str, Any]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    payloads = {
        "html": renderer.render_html(report),
        "json": builder.dumps(report),
    }
    for fmt, text in payloads.items():
        path = REPORT_DIR / renderer.filename(report, fmt)
        path.write_text(text, encoding="utf-8")
        data = path.read_bytes()
        report_repo.add_file(
            conn, report["report_id"], fmt=fmt, file_path=str(path),
            size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
        )


def get(conn: sqlite3.Connection, report_id: str) -> dict[str, Any]:
    view = report_repo.get(conn, report_id)
    if view is None:
        raise ScanError("NOT_FOUND", "보고서를 찾을 수 없습니다.", status_code=404)
    return view


def download(
    conn: sqlite3.Connection, report_id: str, fmt: str
) -> tuple[str, str, str]:
    """(본문, 미디어 타입, 파일명). pdf 는 지원하지 않음"""
    view = get(conn, report_id)
    if fmt == "pdf":
        raise ScanError(
            "NOT_SUPPORTED",
            f"PDF 직접 생성은 지원하지 않습니다. {PDF_NOTE}",
            status_code=501,
        )
    if fmt not in FORMATS:
        raise ScanError("INVALID_REQUEST", f"지원하지 않는 형식: {fmt}")
    if view["report"] is None:
        raise ScanError("INVALID_REQUEST", "보고서가 완성되지 않았습니다.")

    report = view["report"]
    if fmt == "json":
        return builder.dumps(report), "application/json", renderer.filename(report, "json")
    return (
        renderer.render_html(report),
        "text/html; charset=utf-8",
        renderer.filename(report, "html"),
    )


def delete(conn: sqlite3.Connection, report_id: str) -> None:
    view = get(conn, report_id)
    for entry in view["files"]:
        Path(entry["file_path"]).unlink(missing_ok=True)
    report_repo.delete(conn, report_id)
