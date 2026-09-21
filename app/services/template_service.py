"""템플릿 관리 흐름 제어 (docs/00 §3).

official 템플릿은 수정·삭제 불가. fork 로 custom 사본을 만들어 편집함
파일 쓰기는 templates/custom/ 안으로 제한됨 - template_id 정규식이 1차 방어이고
경로 해석 결과 확인이 2차 방어 (M5 보안)
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

import yaml

from app.config import settings
from app.domain import template_meta
from app.domain.enums import Severity
from app.domain.vuln_type import normalize
from app.repository import settings_repo
from app.repository import templates as template_repo
from app.repository.rules import load_vuln_type_rules
from app.services import template_builder as builder
from app.services import template_validator as validator
from app.services.scan_service import ScanError

__all__ = ["ScanError"]

logger = logging.getLogger(__name__)

_SOURCE_OFFICIAL = "official"
_SOURCE_CUSTOM = "custom"
_SYNC_TIMEOUT_SEC = 600
# 자산 식별 전용 템플릿. 취약점이 아니므로 보고서 부록으로 간다 (docs/05 자주 하는 실수)
_DETECTION_TAGS = frozenset({"tech", "detect", "detection", "favicon"})


# ────────────────────────────────────────────── 경로


def custom_path(template_id: str) -> Path:
    """custom 템플릿 파일 경로. 디렉터리 밖으로 나가면 거부"""
    if not builder.TEMPLATE_ID_RE.match(template_id):
        raise ScanError(
            "INVALID_REQUEST",
            "템플릿 ID 는 소문자·숫자·하이픈만 허용",
            details=[{"field": "template_id", "reason": template_id}],
        )
    root = settings.CUSTOM_DIR.resolve()
    path = (root / f"{template_id}.yaml").resolve()
    if path.parent != root:
        # 정규식을 통과해도 경로 해석 결과를 다시 확인함
        raise ScanError("INVALID_REQUEST", "허용되지 않은 템플릿 경로입니다.")
    return path


# ────────────────────────────────────────────── 색인


def index_all(conn: sqlite3.Connection) -> dict[str, int]:
    """templates/ 트리를 훑어 DB 색인 갱신. 파일이 정본이고 DB 는 색인"""
    rules = load_vuln_type_rules(conn)
    counts = {"official": 0, "custom": 0, "skipped": 0}
    rows: list[dict[str, Any]] = []
    for source, directory in (
        (_SOURCE_OFFICIAL, settings.OFFICIAL_DIR),
        (_SOURCE_CUSTOM, settings.CUSTOM_DIR),
    ):
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*.yaml")) + sorted(
            directory.rglob("*.yml")
        ):
            row = _index_row(path, source, rules)
            if row:
                rows.append(row)
                counts[source] += 1
    if rows:
        counts["skipped"] = _upsert_tolerant(conn, rows)
    return counts


def _upsert_tolerant(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> int:
    """일괄 삽입. 실패 시 한 행씩 재시도해 문제 행만 버림.

    executemany 는 한 행이 제약에 걸리면 전체가 끊김. 공식 템플릿 수천 개 중
    하나 때문에 색인이 통째로 실패하면 사용자는 '서버 내부 오류' 만 보게 됨
    """
    try:
        template_repo.upsert_many(conn, rows)
        return 0
    except sqlite3.DatabaseError:
        logger.warning("일괄 색인 실패. 행 단위로 재시도", exc_info=True)

    skipped = 0
    for row in rows:
        try:
            template_repo.upsert(conn, row)
        except sqlite3.DatabaseError:
            skipped += 1
            logger.warning("템플릿 색인 건너뜀: %s", row.get("file_path"))
    return skipped


def _index_row(path: Path, source: str, rules) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8")
        document = yaml.safe_load(text)
    except (OSError, yaml.YAMLError):
        # 깨진 템플릿 하나가 색인 전체를 막지 않음
        logger.warning("템플릿 읽기 실패: %s", path)
        return None
    if not isinstance(document, dict) or not document.get("id"):
        return None

    info = document.get("info") or {}
    if not isinstance(info, dict):
        info = {}
    classification = info.get("classification") or {}
    if not isinstance(classification, dict):
        classification = {}
    metadata = info.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}

    tags = builder._split_tags(info.get("tags"))
    cve_ids = _listify(classification.get("cve-id"))
    cwe_ids = _listify(classification.get("cwe-id"))
    template_id = str(document["id"])

    return {
        "template_id": template_id,
        "source": source,
        "file_path": str(path),
        "name": str(info.get("name") or template_id),
        "description": info.get("description"),
        "severity": _severity_or_none(info.get("severity")),
        "vuln_type": normalize(
            tags=tags, cwe_ids=cwe_ids, template_id=template_id, rules=rules
        ).value,
        "cve_ids": cve_ids,
        "cwe_ids": cwe_ids,
        "tags": tags,
        "cvss_score": classification.get("cvss-score"),
        "cvss_vector": classification.get("cvss-metrics"),
        "fixed_version": None,
        "is_detection": bool(set(tags) & _DETECTION_TAGS),
        "component_slugs": template_meta.wp_component_slug(metadata, tags, text),
        "platform": template_meta.platform_of(metadata, tags),
        "form_json": None,
        "yaml_hash": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _severity_or_none(value: Any) -> str | None:
    """스키마 CHECK 를 통과하는 값만 저장.

    공식 템플릿에는 'unknown' 처럼 5종 밖의 값이 섞여 있음. 그대로 넣으면
    executemany 가 IntegrityError 로 끊겨 색인 전체가 실패함
    임의로 다른 등급에 욱여넣지 않고 비움 - 모르는 것을 'info' 로 만들면 거짓 등급
    """
    if value is None:
        return None
    text = str(value).strip().lower()
    return text if text in set(Severity) else None


def _listify(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return [str(value)]


# ────────────────────────────────────────────── 조회


def detail(conn: sqlite3.Connection, template_id: str) -> dict[str, Any]:
    row = template_repo.get(conn, template_id)
    if row is None:
        raise ScanError("NOT_FOUND", "템플릿을 찾을 수 없습니다.", status_code=404)
    path = Path(row["file_path"])
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    parsed = builder.parse(text) if text else {"form": None, "unsupported_fields": []}
    return {**row, "yaml": text, **parsed}


# ────────────────────────────────────────────── 생성 · 수정 · 삭제


def create(conn: sqlite3.Connection, form: dict[str, Any]) -> dict[str, Any]:
    yaml_text, template_id = _render(form)
    if template_repo.get(conn, template_id) is not None:
        raise ScanError(
            "CONFLICT",
            "같은 ID 의 템플릿 존재",
            status_code=409,
            details=[{"field": "info.id", "reason": template_id}],
        )
    return _write(conn, template_id, yaml_text, form)


def update(
    conn: sqlite3.Connection, template_id: str, form: dict[str, Any]
) -> dict[str, Any]:
    existing = _require_editable(conn, template_id)
    yaml_text, new_id = _render(form)
    if new_id != template_id:
        raise ScanError(
            "INVALID_REQUEST",
            "템플릿 ID 변경 불가. fork 사용",
            details=[{"field": "info.id", "reason": new_id}],
        )
    del existing
    return _write(conn, template_id, yaml_text, form)


def delete(conn: sqlite3.Connection, template_id: str) -> None:
    _require_editable(conn, template_id)
    path = custom_path(template_id)
    path.unlink(missing_ok=True)
    template_repo.delete(conn, template_id)


def fork(conn: sqlite3.Connection, template_id: str, new_id: str) -> dict[str, Any]:
    """official 사본을 custom 으로. 수정 불가 템플릿을 편집하는 유일한 경로"""
    source = detail(conn, template_id)
    if template_repo.get(conn, new_id) is not None:
        raise ScanError(
            "CONFLICT", "같은 ID 의 템플릿이 이미 있습니다.", status_code=409
        )

    document = yaml.safe_load(source["yaml"]) or {}
    if not builder.TEMPLATE_ID_RE.match(new_id):
        raise ScanError(
            "INVALID_REQUEST", "템플릿 ID 는 소문자·숫자·하이픈만 쓸 수 있습니다."
        )
    document["id"] = new_id
    yaml_text = yaml.safe_dump(
        document, sort_keys=False, allow_unicode=True, default_flow_style=False
    )
    return _write(conn, new_id, yaml_text, None)


def _render(form: dict[str, Any]) -> tuple[str, str]:
    try:
        yaml_text = builder.build(form)
    except builder.BuildError as exc:
        raise ScanError(
            "INVALID_REQUEST",
            exc.message,
            details=[{"field": exc.field, "reason": exc.message}],
        ) from exc
    return yaml_text, str((form.get("info") or {}).get("id"))


def _write(
    conn: sqlite3.Connection,
    template_id: str,
    yaml_text: str,
    form: dict[str, Any] | None,
) -> dict[str, Any]:
    checked = validator.validate(yaml_text)
    if not checked["policy"]["valid"]:
        raise ScanError(
            "INVALID_REQUEST",
            "정책 검증 실패",
            details=[
                {"field": e["field"], "reason": e["message"]}
                for e in checked["policy"]["errors"]
            ],
        )

    path = custom_path(template_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml_text, encoding="utf-8")

    rules = load_vuln_type_rules(conn)
    row = _index_row(path, _SOURCE_CUSTOM, rules) or {}
    if form is not None:
        row["form_json"] = json.dumps(form, ensure_ascii=False)
    template_repo.upsert(conn, row)

    return {
        "template_id": template_id,
        "source": _SOURCE_CUSTOM,
        "yaml": yaml_text,
        "warnings": checked["policy"]["warnings"],
        "syntax": checked["syntax"],
    }


def _require_editable(conn: sqlite3.Connection, template_id: str) -> dict[str, Any]:
    row = template_repo.get(conn, template_id)
    if row is None:
        raise ScanError("NOT_FOUND", "템플릿을 찾을 수 없습니다.", status_code=404)
    if row["source"] == _SOURCE_OFFICIAL:
        raise ScanError(
            "FORBIDDEN",
            "공식 템플릿은 수정·삭제 불가. fork 로 사본 생성",
            status_code=403,
        )
    return row


# ────────────────────────────────────────────── 갱신 (외부 통신)


def sync(conn: sqlite3.Connection, *, runner=None) -> dict[str, Any]:
    """공식 템플릿 갱신. 수동 트리거만. 오프라인 모드에서 403 (절대규칙 5)"""
    if settings_repo.offline_mode(conn):
        raise ScanError(
            "OFFLINE_MODE_BLOCKED",
            "오프라인 모드. 템플릿 갱신 불가",
            status_code=403,
        )
    raw = settings_repo.get_all(conn)
    if not settings_repo.as_bool(raw.get("ext_template_sync_enabled")):
        raise ScanError(
            "OFFLINE_MODE_BLOCKED",
            "템플릿 갱신 비활성. 설정에서 통신 지점 허용 필요",
            status_code=403,
        )

    before = {r["template_id"] for r in template_repo.search(conn, size=100_000)[0]}
    execute = runner or _run_update
    execute()
    try:
        counts = index_all(conn)
    except Exception as exc:
        logger.exception("템플릿 색인 실패")
        raise ScanError(
            "INDEX_FAILED",
            f"내려받기는 됐으나 색인 실패: {exc}. 폴더 재색인으로 재시도 가능",
            status_code=500,
        ) from exc
    after = {r["template_id"] for r in template_repo.search(conn, size=100_000)[0]}

    return {
        "updated": len(before & after),
        "added": len(after - before),
        # 파일이 사라진 템플릿은 색인에 남음. 삭제는 별도 정리 대상이며 여기서는 보고만
        "removed": len(before - after),
        "revision": template_repo.revision(conn),
        "indexed": counts,
    }


def _run_update() -> None:
    binary = settings.nuclei_bin()
    if not binary:
        raise ScanError("NUCLEI_UNAVAILABLE", "nuclei 실행 파일 없음", status_code=503)
    settings.OFFICIAL_DIR.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            [binary, "-update-templates", "-ud", str(settings.OFFICIAL_DIR), "-silent"],
            capture_output=True,
            text=True,
            timeout=_SYNC_TIMEOUT_SEC,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScanError(
            "NUCLEI_UNAVAILABLE", f"템플릿 갱신 실패: {exc}", status_code=502
        ) from exc

    if completed.returncode != 0:
        # nuclei 가 남긴 사유를 그대로 올림. 'CalledProcessError(1)' 만 보이면
        # 어느 단계에서 막혔는지 알 수 없다 (Windows 실행 차단·네트워크 차단 등)
        detail = (completed.stderr or completed.stdout or "").strip()
        logger.warning("템플릿 갱신 실패 rc=%s: %s", completed.returncode, detail)
        raise ScanError(
            "NUCLEI_UNAVAILABLE",
            f"템플릿 갱신 실패 (종료 코드 {completed.returncode})"
            + (f": {detail.splitlines()[-1][:300]}" if detail else ""),
            status_code=502,
        )
