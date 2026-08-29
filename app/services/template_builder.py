"""폼 <-> nuclei YAML 양방향 변환 (docs/00 §3.3, §3.4).

폼 스키마를 백엔드가 제공한다. 필드 추가 시 GUI 수정 없이 반영되어야 하고,
스키마와 변환 로직이 떨어져 있으면 '스키마에는 있으나 변환되지 않는 필드'가 생긴다.
그래서 두 개를 같은 파일에 둔다

YAML 인젝션 방지: 폼 값은 전부 스키마 검사(패턴·enum·타입)를 통과한 뒤
safe_dump 로 직렬화된다. 사용자 문자열을 YAML 텍스트에 이어붙이지 않는다
"""
from __future__ import annotations

import re
from typing import Any

import yaml

from app.domain.enums import Severity

# 파일 경로 조작 방지. template_id 가 파일명이 되므로 여기서 막는다 (M5 보안)
TEMPLATE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_RE = re.compile(r"^CWE-\d+$")

MATCHER_TYPES = ("status", "word", "regex", "dsl")
MATCHER_PARTS = ("body", "header", "all")
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE")
CONDITIONS = ("and", "or")

# 빌더가 다루는 최상위 키. 이 밖의 키는 unsupported_fields 로 보고한다
_SUPPORTED_TOP = frozenset({"id", "info", "http", "requests"})
_SUPPORTED_INFO = frozenset({
    "name", "author", "severity", "description", "classification", "tags",
})
# classification 하위도 마찬가지. cvss-metrics·epss·cpe 는 폼에 없어 재구성 시 사라진다
_SUPPORTED_CLASSIFICATION = frozenset({"cve-id", "cwe-id", "cvss-score"})
_SUPPORTED_REQUEST = frozenset({
    "method", "path", "body", "headers", "matchers", "matchers-condition",
})

FORM_SCHEMA: dict[str, Any] = {
    "sections": [
        {
            "key": "info",
            "label": "취약점 정보",
            "fields": [
                {"key": "id", "label": "템플릿 ID", "type": "string", "required": True,
                 "pattern": TEMPLATE_ID_RE.pattern, "help": "소문자·숫자·하이픈만"},
                {"key": "name", "label": "이름", "type": "string", "required": True},
                {"key": "severity", "label": "심각도", "type": "enum", "required": True,
                 "options": [s.value for s in Severity]},
                {"key": "description", "label": "설명", "type": "text"},
                # nuclei 가 필수로 요구한다. 없으면 'no template author field provided'
                # 로 로드 자체가 실패한다
                {"key": "author", "label": "작성자", "type": "string", "required": True},
                {"key": "tags", "label": "태그", "type": "list"},
            ],
        },
        {
            "key": "classification",
            "label": "보안 기준 매핑",
            "fields": [
                {"key": "cve_id", "label": "CVE ID", "type": "string",
                 "pattern": CVE_RE.pattern},
                {"key": "cwe_id", "label": "CWE ID", "type": "string",
                 "pattern": CWE_RE.pattern},
                {"key": "cvss_score", "label": "CVSS", "type": "number",
                 "min": 0, "max": 10},
            ],
        },
        {
            "key": "http",
            "label": "요청 시나리오",
            "repeatable": True,
            "min_items": 1,
            "fields": [
                {"key": "method", "label": "메서드", "type": "enum",
                 "options": list(HTTP_METHODS), "required": True},
                {"key": "path", "label": "경로", "type": "string", "required": True,
                 "help": "{{BaseURL}} 사용 가능"},
                {"key": "headers", "label": "헤더", "type": "keyvalue"},
                {"key": "body", "label": "본문", "type": "text"},
            ],
        },
        {
            "key": "matchers",
            "label": "탐지 조건",
            "repeatable": True,
            "min_items": 1,
            "fields": [
                {"key": "type", "label": "조건 종류", "type": "enum",
                 "options": list(MATCHER_TYPES), "required": True},
                {"key": "part", "label": "검사 대상", "type": "enum",
                 "options": list(MATCHER_PARTS)},
                {"key": "values", "label": "값", "type": "list", "required": True},
                {"key": "condition", "label": "결합", "type": "enum",
                 "options": list(CONDITIONS), "default": "and"},
            ],
        },
    ],
    "matchers_condition": {
        "key": "matchers-condition", "type": "enum",
        "options": list(CONDITIONS), "default": "and",
    },
}


class BuildError(ValueError):
    """폼 구조 오류. 어느 필드가 문제인지 담는다"""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field
        self.message = message


# ────────────────────────────────────────────── 폼 -> YAML

def build(form: dict[str, Any]) -> str:
    """폼 -> YAML 문자열. 구조를 벗어난 값은 BuildError"""
    info_in = _section_dict(form, "info")
    template_id = str(info_in.get("id") or "").strip()
    if not TEMPLATE_ID_RE.match(template_id):
        raise BuildError("info.id", "템플릿 ID 는 소문자·숫자·하이픈만 가능합니다.")

    name = str(info_in.get("name") or "").strip()
    if not name:
        raise BuildError("info.name", "이름이 없습니다.")

    severity = str(info_in.get("severity") or "").strip()
    if severity not in {s.value for s in Severity}:
        raise BuildError("info.severity", "severity 값이 유효하지 않습니다.")

    author = str(info_in.get("author") or "").strip()
    if not author:
        raise BuildError("info.author", "작성자가 없습니다. nuclei 가 필수로 요구합니다.")

    info: dict[str, Any] = {"name": name, "author": author, "severity": severity}
    if info_in.get("description"):
        info["description"] = str(info_in["description"])
    if info_in.get("tags"):
        info["tags"] = ",".join(_as_list("info.tags", info_in["tags"]))

    classification = _classification(_section_dict(form, "classification"))
    if classification:
        info["classification"] = classification

    requests = _requests(form)

    document: dict[str, Any] = {"id": template_id, "info": info, "http": requests}
    # sort_keys=False 로 nuclei 관례 순서 유지. allow_unicode 로 한글 설명 보존
    return yaml.safe_dump(
        document, sort_keys=False, allow_unicode=True, default_flow_style=False, width=120
    )


def _section_dict(form: dict[str, Any], key: str) -> dict[str, Any]:
    value = form.get(key) or {}
    if not isinstance(value, dict):
        raise BuildError(key, f"{key} 는 객체여야 합니다.")
    return value


def _as_list(field: str, value: Any) -> list[str]:
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    raise BuildError(field, "목록 형식이 아닙니다.")


def _classification(raw: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    cve = str(raw.get("cve_id") or "").strip()
    if cve:
        if not CVE_RE.match(cve):
            raise BuildError("classification.cve_id", "CVE ID 형식이 아닙니다.")
        out["cve-id"] = cve
    cwe = str(raw.get("cwe_id") or "").strip()
    if cwe:
        if not CWE_RE.match(cwe):
            raise BuildError("classification.cwe_id", "CWE ID 형식이 아닙니다.")
        out["cwe-id"] = cwe
    score = raw.get("cvss_score")
    if score not in (None, ""):
        try:
            value = float(score)
        except (TypeError, ValueError) as exc:
            raise BuildError("classification.cvss_score", "숫자가 아닙니다.") from exc
        if not 0 <= value <= 10:
            raise BuildError("classification.cvss_score", "0~10 범위를 벗어났습니다.")
        out["cvss-score"] = value
    return out


def _requests(form: dict[str, Any]) -> list[dict[str, Any]]:
    entries = form.get("http") or []
    if not isinstance(entries, list) or not entries:
        raise BuildError("http", "요청 시나리오가 최소 1개 필요합니다.")

    matchers = _matchers(form.get("matchers"))
    condition = form.get("matchers-condition") or "and"
    if condition not in CONDITIONS:
        raise BuildError("matchers-condition", "and 또는 or 만 가능합니다.")

    requests: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise BuildError(f"http[{index}]", "객체여야 합니다.")
        method = str(entry.get("method") or "GET").upper()
        if method not in HTTP_METHODS:
            raise BuildError(f"http[{index}].method", "허용되지 않은 메서드입니다.")
        path = str(entry.get("path") or "").strip()
        if not path:
            raise BuildError(f"http[{index}].path", "경로가 없습니다.")

        request: dict[str, Any] = {"method": method, "path": [path]}
        headers = entry.get("headers")
        if headers:
            if not isinstance(headers, dict):
                raise BuildError(f"http[{index}].headers", "키-값 형식이 아닙니다.")
            request["headers"] = {str(k): str(v) for k, v in headers.items()}
        if entry.get("body"):
            request["body"] = str(entry["body"])

        # matcher 는 첫 요청에만 붙인다. 여러 요청에 같은 조건을 복제하면
        # 어느 요청이 매칭됐는지 구분할 수 없다
        if index == 0:
            request["matchers-condition"] = condition
            request["matchers"] = matchers
        requests.append(request)
    return requests


def _matchers(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        raise BuildError("matchers", "탐지 조건이 최소 1개 필요합니다.")
    out: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise BuildError(f"matchers[{index}]", "객체여야 합니다.")
        kind = str(item.get("type") or "").strip()
        if kind not in MATCHER_TYPES:
            raise BuildError(f"matchers[{index}].type", "허용되지 않은 조건 종류입니다.")
        values = _as_list(f"matchers[{index}].values", item.get("values") or [])
        if not values:
            raise BuildError(f"matchers[{index}].values", "값이 없습니다.")

        matcher: dict[str, Any] = {"type": kind}
        # 드라이런이 matcher 별 결과를 특정하려면 이름이 필요하다 (M5 완료 조건)
        matcher["name"] = f"m{index}"
        if kind == "status":
            try:
                matcher["status"] = [int(v) for v in values]
            except ValueError as exc:
                raise BuildError(
                    f"matchers[{index}].values", "status 는 숫자여야 합니다."
                ) from exc
        else:
            part = str(item.get("part") or "body")
            if part not in MATCHER_PARTS:
                raise BuildError(f"matchers[{index}].part", "검사 대상이 잘못됐습니다.")
            matcher["part"] = part
            matcher[{"word": "words", "regex": "regex", "dsl": "dsl"}[kind]] = values
        item_condition = str(item.get("condition") or "").strip()
        if item_condition:
            if item_condition not in CONDITIONS:
                raise BuildError(f"matchers[{index}].condition", "and 또는 or 만 가능합니다.")
            matcher["condition"] = item_condition
        out.append(matcher)
    return out


# ────────────────────────────────────────────── YAML -> 폼

def parse(text: str) -> dict[str, Any]:
    """YAML -> 폼 + 미지원 필드 목록.

    공식 템플릿에는 빌더 폼으로 표현 불가한 문법이 있다. 실패로 처리하지 않고
    unsupported_fields 로 알린다 (M5 완료 조건, docs/05 자주 하는 실수)
    """
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise BuildError("yaml", f"YAML 구문 오류: {exc}") from exc
    if not isinstance(document, dict):
        raise BuildError("yaml", "최상위가 매핑이 아닙니다.")

    unsupported = sorted(set(document) - _SUPPORTED_TOP)
    info_raw = document.get("info") or {}
    if not isinstance(info_raw, dict):
        info_raw = {}
    unsupported += sorted(f"info.{k}" for k in set(info_raw) - _SUPPORTED_INFO)

    classification_raw = info_raw.get("classification") or {}
    if not isinstance(classification_raw, dict):
        classification_raw = {}
    unsupported += sorted(
        f"info.classification.{k}"
        for k in set(classification_raw) - _SUPPORTED_CLASSIFICATION
    )

    form: dict[str, Any] = {
        "info": {
            "id": document.get("id"),
            "name": info_raw.get("name"),
            "severity": info_raw.get("severity"),
            "description": info_raw.get("description"),
            "author": info_raw.get("author"),
            "tags": _split_tags(info_raw.get("tags")),
        },
        "classification": {
            "cve_id": _first(classification_raw.get("cve-id")),
            "cwe_id": _first(classification_raw.get("cwe-id")),
            "cvss_score": classification_raw.get("cvss-score"),
        },
        "http": [],
        "matchers": [],
        "matchers-condition": "and",
    }

    requests = document.get("http") or document.get("requests") or []
    if not isinstance(requests, list):
        requests = []
    for index, entry in enumerate(requests):
        if not isinstance(entry, dict):
            continue
        unsupported += sorted(
            f"http[{index}].{k}" for k in set(entry) - _SUPPORTED_REQUEST
        )
        paths = entry.get("path") or []
        if isinstance(paths, str):
            paths = [paths]
        form["http"].append({
            "method": str(entry.get("method") or "GET").upper(),
            "path": paths[0] if paths else "",
            "headers": entry.get("headers") if isinstance(entry.get("headers"), dict) else None,
            "body": entry.get("body"),
        })
        if index == 0:
            form["matchers-condition"] = entry.get("matchers-condition") or "and"
            parsed, matcher_unsupported = _parse_matchers(entry.get("matchers"), index)
            form["matchers"] = parsed
            unsupported += matcher_unsupported

    return {"form": form, "unsupported_fields": sorted(set(unsupported))}


def _parse_matchers(raw: Any, request_index: int) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(raw, list):
        return [], []
    out: list[dict[str, Any]] = []
    unsupported: list[str] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "").strip()
        if kind not in MATCHER_TYPES:
            # binary·xpath 등 폼에 없는 종류. 나머지는 채우고 이 항목만 보고
            unsupported.append(f"http[{request_index}].matchers[{index}].type={kind}")
            continue
        values = item.get("status") or item.get("words") or item.get("regex") \
            or item.get("dsl") or []
        if not isinstance(values, list):
            values = [values]
        out.append({
            "type": kind,
            "part": item.get("part") or ("body" if kind != "status" else None),
            "values": [str(v) for v in values],
            "condition": item.get("condition"),
        })
    return out, unsupported


def _split_tags(raw: Any) -> list[str]:
    if isinstance(raw, str):
        return [t.strip() for t in raw.split(",") if t.strip()]
    if isinstance(raw, list):
        return [str(t).strip() for t in raw if str(t).strip()]
    return []


def _first(value: Any) -> Any:
    """cve-id 는 문자열 또는 목록으로 온다"""
    if isinstance(value, list):
        return value[0] if value else None
    return value
