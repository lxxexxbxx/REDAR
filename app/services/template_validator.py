"""템플릿 검증 2단계 (docs/00 §3).

  1) 문법  -> nuclei -validate 에 위임. 재구현하지 않음 (docs/05 §5.1 규약 6)
  2) 정책  -> 우리 구현. 필수 필드·ID 형식·느슨한 matcher 경고

nuclei 미설치는 검증 실패가 아님. 문법 단계를 건너뛰었다고 알림 (절대규칙 8)
"""
from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from app.config import settings
from app.domain.enums import Severity
from app.services import template_builder as builder

logger = logging.getLogger(__name__)

# 첫 실행은 nuclei 가 설정 디렉터리를 만드느라 20 초를 넘김
# 이후 호출은 0.2 초 수준 (실측)
_SYNTAX_TIMEOUT_SEC = 60

LOOSE_MATCHER = {
    "code": "LOOSE_MATCHER",
    "message": "matcher 가 status 하나뿐입니다. 정상 페이지에도 매칭되어 오탐이 날 수 있습니다.",
    "suggestion": "응답 본문의 고유 문자열을 word matcher 로 추가",
}


def validate(yaml_text: str) -> dict[str, Any]:
    """문법 + 정책. valid 는 두 단계를 합친 결과"""
    syntax = check_syntax(yaml_text)
    policy = check_policy(yaml_text)
    return {
        # 문법 단계를 건너뛴 경우(None)는 실패로 보지 않음
        "valid": policy["valid"] and syntax["valid"] is not False,
        "syntax": syntax,
        "policy": policy,
    }


def check_syntax(yaml_text: str) -> dict[str, Any]:
    binary = settings.nuclei_bin()
    if not binary:
        return {
            "valid": None,
            "checker": "nuclei -validate",
            "skipped": True,
            "reason": "nuclei 미설치. 문법 검증을 건너뜀",
        }

    with tempfile.TemporaryDirectory(prefix="redar-validate-") as tmp:
        path = Path(tmp) / "candidate.yaml"
        path.write_text(yaml_text, encoding="utf-8")
        try:
            proc = subprocess.run(
                [binary, "-validate", "-t", str(path), "-duc", "-silent"],
                capture_output=True, text=True, timeout=_SYNTAX_TIMEOUT_SEC,
                encoding="utf-8", errors="replace",
                # 대상 인자가 없으면 nuclei 가 stdin 을 읽으려 대기함
                # 파이프로 실행되면 무한 대기가 됨
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("nuclei -validate 실행 실패: %s", exc)
            return {
                "valid": None, "checker": "nuclei -validate",
                "skipped": True, "reason": f"실행 실패: {exc}",
            }

    message = (proc.stderr or proc.stdout or "").strip()
    return {
        "valid": proc.returncode == 0,
        "checker": "nuclei -validate",
        # 로그·응답에 템플릿 본문을 되돌리지 않음. nuclei 메시지만 전달
        "message": message[:600] or None,
    }


def check_policy(yaml_text: str) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []

    try:
        document = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        return {
            "valid": False,
            "errors": [{"field": "yaml", "message": f"YAML 구문 오류: {exc}"}],
            "warnings": [],
        }
    if not isinstance(document, dict):
        return {
            "valid": False,
            "errors": [{"field": "yaml", "message": "최상위가 매핑이 아닙니다."}],
            "warnings": [],
        }

    template_id = str(document.get("id") or "").strip()
    if not template_id:
        errors.append({"field": "id", "message": "템플릿 ID 를 입력하세요."})
    elif not builder.TEMPLATE_ID_RE.match(template_id):
        errors.append({
            "field": "id",
            "message": "템플릿 ID 는 소문자·숫자·하이픈만 쓸 수 있습니다.",
        })

    info = document.get("info") or {}
    if not isinstance(info, dict):
        info = {}
        errors.append({"field": "info", "message": "info 가 매핑이 아닙니다."})
    if not str(info.get("name") or "").strip():
        errors.append({"field": "info.name", "message": "이름을 입력하세요."})

    severity = str(info.get("severity") or "").strip()
    if not severity:
        errors.append({"field": "info.severity", "message": "severity 값을 고르세요."})
    elif severity not in {s.value for s in Severity}:
        errors.append({
            "field": "info.severity",
            "message": f"severity 값이 올바르지 않습니다: {severity}",
        })

    classification = info.get("classification") or {}
    if isinstance(classification, dict):
        cve = classification.get("cve-id")
        for value in ([cve] if isinstance(cve, str) else (cve or [])):
            if value and not builder.CVE_RE.match(str(value)):
                errors.append({
                    "field": "info.classification.cve-id",
                    "message": f"CVE ID 형식이 아닙니다: {value}",
                })
        cwe = classification.get("cwe-id")
        for value in ([cwe] if isinstance(cwe, str) else (cwe or [])):
            if value and not builder.CWE_RE.match(str(value)):
                errors.append({
                    "field": "info.classification.cwe-id",
                    "message": f"CWE ID 형식이 아닙니다: {value}",
                })

    requests = document.get("http") or document.get("requests") or []
    if not isinstance(requests, list) or not requests:
        errors.append({"field": "http", "message": "요청이 최소 1개 필요합니다."})
        requests = []

    matcher_total = 0
    for index, entry in enumerate(requests):
        if not isinstance(entry, dict):
            errors.append({"field": f"http[{index}]", "message": "매핑이 아닙니다."})
            continue
        if not entry.get("path"):
            errors.append({"field": f"http[{index}].path", "message": "경로를 입력하세요."})
        matchers = entry.get("matchers") or []
        if not isinstance(matchers, list):
            matchers = []
        matcher_total += len(matchers)
        if _is_loose(matchers):
            warnings.append({**LOOSE_MATCHER, "field": f"http[{index}].matchers"})

    if matcher_total == 0:
        errors.append({"field": "matchers", "message": "탐지 조건이 최소 1개 필요합니다."})

    return {"valid": not errors, "errors": errors, "warnings": warnings}


def _is_loose(matchers: list[Any]) -> bool:
    """status 만으로 판정하는 matcher 구성. 정상 페이지도 매칭됨"""
    kinds = {
        str(m.get("type") or "").strip()
        for m in matchers if isinstance(m, dict)
    }
    return bool(kinds) and kinds <= {"status"}
