"""LLM 조치상세방안 가이드.

보고서는 신뢰도가 중요하므로 LLM 을 쓰지 않는다(절대규칙 2 개정). LLM 은
**완성된 보고서를 입력으로 받아 조치 절차를 풀어 쓰는 별도 기능**으로만 존재한다.
보고서 본문은 이 기능의 결과에 영향받지 않는다

흐름 2단계
  [1] 보고서 -> 프롬프트   **로컬 양식 렌더링. 통신 없음**
  [2] 프롬프트 -> 가이드   사용자가 확인한 뒤에만 전송

[1] 을 LLM 에 맡기지 않는 이유
  - 같은 보고서에 같은 프롬프트가 나와야 함 (보고서 결정론과 같은 원칙)
  - 통신이 없으니 오프라인·폐쇄망에서도 프롬프트를 뽑아 외부 LLM 에 직접 붙일 수 있음
  - 원하는 산출 구조(README 형식·단계별 명령·확인 방법)를 우리가 확정

[2] 통제 4겹 (docs/01 §7.1)
  기능 토글 -> 오프라인 검사 -> LLM 통신 지점 검사 -> 요청마다 명시 동의
"""
from __future__ import annotations

import sqlite3
from typing import Any

from app.adapters.llm import get_provider
from app.adapters.llm.base import LlmError
from app.adapters.llm.masking import Masker
from app.repository import reports as report_repo
from app.repository import settings_repo
from app.services.scan_service import ScanError

# 대화 히스토리 상한. 무제한이면 토큰이 계속 늘어 비용·지연이 커짐
MAX_MESSAGES = 20
MAX_MESSAGE_CHARS = 8000
# 가이드는 절차 문서라 길다
GUIDE_MAX_TOKENS = 6000
# 설정이 비어 있을 때 쓸 Provider. 통신 구현이 하나뿐임
DEFAULT_PROVIDER = "monogpt"
# '미설정' 으로 볼 값. settings_defaults.csv 가 문자열 'null' 을 넣으므로
# 빈 문자열만 검사하면 미설정을 '알 수 없는 Provider' 로 오판함
_UNSET = {None, "", "null", "none"}

_GUIDE_SYSTEM = (
    "너는 웹 서버·CMS 보안 조치를 안내하는 기술 문서 작성자다."
    " 답변은 Markdown 으로, 담당자가 위에서부터 따라가며 복사·실행하면 조치가"
    " 끝나도록 단계별로 작성하라."
    " 자리표시자(<경로>, YOUR_PATH 등)를 남기지 말고 주어진 환경 정보의 실제 값을 넣어라."
    " 새 도구 설치를 요구하지 말고 해당 제품·OS 에 이미 있는 명령으로 해결하라."
    " 불가피하면 그 단계에 '[추가 설치 필요]' 를 표시하라."
    " 각 단계에 실행 명령, 조치 확인 명령과 기대 출력, 되돌리는 방법을 함께 적어라."
    " 확실하지 않은 부분은 추측하지 말고 '확인 필요' 로 표시하라."
)


def provider_name(raw: dict[str, str]) -> str:
    """설정값 -> Provider 이름. 미설정이면 통신 구현"""
    configured = (raw.get("llm_provider") or "").strip().lower()
    return DEFAULT_PROVIDER if configured in _UNSET else configured


def _provider(raw: dict[str, str]):
    """실제 응답이 필요한 기능이므로 통신 Provider 를 씀.

    NullProvider 기본값은 보고서를 위한 것이었고(절대규칙 2), 보고서는 이제 LLM 을
    쓰지 않는다. 이 기능은 LLM 응답이 없으면 성립하지 않으므로 기본값이 반대다.
    Provider 선택은 화면에 두지 않는다 - 실제 구현이 하나뿐이라 고를 이유가 없고,
    비워두면 조용히 NullProvider 로 떨어져 '키를 넣었는데 안 된다' 가 됨
    """
    provider = get_provider(provider_name(raw), {
        "endpoint": raw.get("llm_endpoint"),
        "api_key": raw.get("llm_api_key"),
        "model": raw.get("llm_model"),
    })
    if not hasattr(provider, "complete"):
        raise ScanError(
            "LLM_UNAVAILABLE",
            f"알 수 없는 LLM Provider: {provider_name(raw)}",
            status_code=503,
        )
    return provider


def _blocked_reason(raw: dict[str, str]) -> str | None:
    """막힌 이유. 화면이 무엇을 켜야 하는지 알려줄 수 있어야 함"""
    if not settings_repo.as_bool(raw.get("llm_remediation_guide_enabled")):
        return "설정에서 'LLM 조치 가이드' 기능을 켜야 사용 가능"
    if settings_repo.as_bool(raw.get("offline_mode"), default=True):
        return "오프라인 모드. LLM 통신이 전부 차단된 상태"
    if not settings_repo.as_bool(raw.get("ext_llm_api_enabled")):
        return "설정에서 'LLM API' 통신 지점 허용 필요"
    if not raw.get("llm_api_key"):
        return "설정에서 MonoGPT API 키 입력 필요"
    return None


def status(conn: sqlite3.Connection) -> dict[str, Any]:
    raw = settings_repo.get_all(conn)
    return {
        # 메뉴 노출 여부. 꺼져 있으면 화면 자체가 없음
        "feature_enabled": settings_repo.as_bool(
            raw.get("llm_remediation_guide_enabled")
        ),
        "blocked_reason": _blocked_reason(raw),
        "model": raw.get("llm_model"),
        "masked": settings_repo.as_bool(
            raw.get("llm_mask_identifiers"), default=True
        ),
    }


def _guard(conn: sqlite3.Connection) -> dict[str, str]:
    raw = settings_repo.get_all(conn)
    reason = _blocked_reason(raw)
    if reason:
        raise ScanError("LLM_BLOCKED", reason, status_code=403)
    return raw


def report_context(report: dict[str, Any]) -> dict[str, Any]:
    """LLM 에 보낼 값. 화이트리스트 방식.

    보고서 JSON 을 통째로 보내면 findings_detail.evidence 의 요청·응답 원문이
    함께 나간다. 대상 서버가 돌려준 본문에는 내부 경로·토큰이 섞일 수 있어
    전송 금지 항목이다 (docs/01 §7.4). 조치 절차를 뽑는 데 필요한 것만 담음
    """
    meta = report.get("meta") or {}
    summary = report.get("executive_summary") or {}
    environment = report.get("environment_profile") or {}

    return {
        "targets": (meta.get("targets") or [])[:20],
        "stack": {
            key: {
                "product": (environment.get(key) or {}).get("product"),
                "version": (environment.get(key) or {}).get("version"),
                "confidence": (environment.get(key) or {}).get("confidence"),
            }
            for key in ("web_server", "language", "application")
            if (environment.get(key) or {}).get("product")
        },
        "components": [
            {
                "type": c.get("type"),
                "slug": c.get("slug"),
                "version": c.get("version"),
                "active": c.get("active"),
            }
            for c in (environment.get("components") or [])
        ][:40],
        # 노출 항목. 조치 대상이 곧 이 경로들이라 path 를 함께 넘김
        "exposures": [
            {"key": e.get("key"), "path": e.get("path")}
            for e in (environment.get("exposures") or []) if e.get("value")
        ],
        # 수집 실패는 '없음' 과 다르다. 가이드가 단정하지 않도록 함께 넘김
        "collectors_run": environment.get("collectors_run") or [],
        "collectors_failed": environment.get("collectors_failed") or [],
        "total_findings": summary.get("total_findings"),
        "by_severity": summary.get("by_severity"),
        "findings": [
            {
                "name": f.get("name"),
                "severity": f.get("severity"),
                "vuln_type": f.get("vuln_type"),
                "cve_ids": f.get("cve_ids"),
                "cwe_ids": f.get("cwe_ids"),
                "template_id": f.get("template_id"),
            }
            for f in (report.get("findings_detail") or [])
        ][:60],
        "remediation": [
            {
                "item_code": item.get("item_code"),
                "item_name": item.get("item_name"),
                "fixed_version": item.get("fixed_version"),
                # 가이드 원문은 그대로 인용. 재작성 요구하지 않음 (절대규칙 9)
                "guide_remediation_original": item.get("guide_remediation_original"),
            }
            for item in (report.get("remediation") or [])
        ][:30],
    }


def build_prompt(conn: sqlite3.Connection, report_id: str) -> dict[str, Any]:
    """[1] 보고서 -> 프롬프트. 로컬 렌더링이라 통신·동의가 필요 없음.

    기능 토글만 확인한다. 오프라인 모드에서도 동작해야 사용자가 프롬프트를
    복사해 외부 LLM 에 직접 쓸 수 있음 (폐쇄망 대체 경로)
    """
    raw = settings_repo.get_all(conn)
    if not settings_repo.as_bool(raw.get("llm_remediation_guide_enabled")):
        raise ScanError(
            "LLM_BLOCKED",
            "설정에서 'LLM 조치 가이드' 기능을 켜야 사용 가능",
            status_code=403,
        )

    row = report_repo.get(conn, report_id)
    report = (row or {}).get("report")
    if report is None:
        raise ScanError("NOT_FOUND", "보고서 없음", status_code=404)

    context = report_context(report)
    return {
        "report_id": report_id,
        "prompt": render_prompt(context),
        # 프롬프트는 로컬 텍스트라 마스킹하지 않음. 채팅으로 나갈 때만 치환됨
        "masked": False,
        "sent_keys": sorted(context),
        "excluded": ["요청·응답 원문", "추출값", "내부 경로", "자격증명"],
    }


def render_prompt(context: dict[str, Any]) -> str:
    """고정 양식. 같은 보고서면 같은 프롬프트가 나와야 함"""
    lines = [
        "아래는 웹 취약점 진단 결과다. 이 내용을 근거로 **조치 상세 가이드**를 작성해줘.",
        "",
        "## 출력 형식",
        "- Markdown. 위에서부터 순서대로 따라가면 조치가 끝나도록 작성",
        "- **복사해서 그대로 실행 가능한 명령**만 적을 것."
        " `<여기에 경로>` 같은 자리표시자를 남기지 말고, 아래 환경 정보의 실제 값을 넣을 것",
        "- 설정 파일을 바꿔야 하면 **파일 경로**와 **변경 전/후 줄**을 그대로 보여줄 것",
        "- 새 도구 설치를 요구하지 말 것. 해당 제품·OS 에 이미 있는 명령으로 해결할 것."
        " 불가피하면 그 단계에 `[추가 설치 필요]` 를 붙여 따로 구분",
        "- 각 단계마다 (1) 실행 명령 (2) 조치 확인 명령과 기대 출력 (3) 되돌리는 방법",
        "- 서비스 재시작·중단이 필요한 단계는 그 사실을 먼저 밝힐 것",
        "- 심각도가 높은 항목부터. 여러 항목이 같은 파일을 고치면 한 단계로 묶을 것",
        "- 진단 결과에 없는 취약점·수치를 새로 만들지 말 것",
        "- 확실하지 않으면 추측하지 말고 `확인 필요` 로 표시",
        "",
        "## 대상 환경 (REDAR 환경 조사 결과)",
    ]

    targets = context.get("targets") or []
    if targets:
        lines.append(f"- 진단 대상: {', '.join(targets)}")

    stack = context.get("stack") or {}
    if stack:
        for key, value in stack.items():
            version = value.get("version") or "버전 미확인"
            note = "" if value.get("confidence") == "high" else \
                f" (확신도 {value.get('confidence') or 'low'})"
            lines.append(
                f"- {_STACK_LABEL.get(key, key)}: {value['product']} {version}{note}"
            )
    else:
        lines.append("- 스택 미확인. 환경 조사에서 제품을 식별하지 못함")

    components = context.get("components") or []
    if components:
        lines += ["", f"### 구성요소 {len(components)}건"]
        for c in components:
            state = "" if c.get("active") is None else (
                " · 활성" if c["active"] else " · 비활성"
            )
            lines.append(
                f"- {c.get('type') or 'component'} `{c.get('slug')}`"
                f" {c.get('version') or '버전 미확인'}{state}"
            )

    exposures = context.get("exposures") or []
    if exposures:
        lines += ["", "### 확인된 노출 항목 — 조치 대상"]
        for e in exposures:
            path = f" — `{e['path']}`" if e.get("path") else ""
            lines.append(f"- {e.get('key')}{path}")

    failed = context.get("collectors_failed") or []
    if failed:
        lines += [
            "",
            f"> 수집 실패: {', '.join(failed)}."
            " 이 영역은 확인되지 않았으므로 '양호' 로 단정하지 말 것",
        ]

    lines += [
        "",
        "## 탐지 결과",
        f"총 {context.get('total_findings') or 0}건"
        f" · {_severity_line(context.get('by_severity') or {})}",
        "",
        "| 항목 | 심각도 | 유형 | CVE | CWE |",
        "|---|---|---|---|---|",
    ]
    for finding in context.get("findings") or []:
        lines.append(
            f"| {finding.get('name') or '-'} | {finding.get('severity') or '-'}"
            f" | {finding.get('vuln_type') or '-'}"
            f" | {', '.join(finding.get('cve_ids') or []) or '-'}"
            f" | {', '.join(finding.get('cwe_ids') or []) or '-'} |"
        )

    remediation = [
        item for item in (context.get("remediation") or [])
        if item.get("guide_remediation_original")
    ]
    if remediation:
        lines += [
            "",
            "## 점검항목 조치 원문 (가이드 인용)",
            "아래는 가이드 원문이다. **다듬거나 바꾸지 말고** 그대로 근거로 삼아,",
            "이 환경에서 실제로 어떤 명령을 어떤 순서로 실행하면 되는지 풀어서 설명해줘.",
            "",
        ]
        for item in remediation:
            lines.append(f"### {item.get('item_code')} {item.get('item_name') or ''}")
            if item.get("fixed_version"):
                lines.append(f"패치 목표 버전: {item['fixed_version']}")
            lines += ["```", str(item["guide_remediation_original"]).strip(), "```", ""]

    lines += [
        "## 주의",
        "- 탐지되지 않은 항목을 '양호' 로 단정하지 말 것. 원격 스캔은 계정 관리·"
        "파일 권한·서비스 데몬 설정을 볼 수 없음",
        "- 조치 전 대상 파일 백업 명령을 각 단계 첫 줄에 넣을 것",
        "- 위 환경 정보에 없는 경로·버전을 임의로 가정하지 말 것."
        " 정보가 부족하면 그 단계에 `확인 필요` 로 적고 확인 명령을 제시",
    ]
    return "\n".join(lines)


_STACK_LABEL = {
    "web_server": "웹 서버",
    "language": "언어 런타임",
    "application": "애플리케이션",
}


def _severity_line(by_severity: dict[str, Any]) -> str:
    parts = [f"{key} {value}" for key, value in by_severity.items() if value]
    return " · ".join(parts) if parts else "심각도 집계 없음"


def ask(
    conn: sqlite3.Connection,
    messages: list[dict[str, str]],
    *,
    confirmed: bool,
) -> dict[str, Any]:
    """[2] 프롬프트 -> 조치 가이드. 요청마다 명시 동의 필요"""
    raw = _guard(conn)
    if not confirmed:
        # 설정만으로 자동 전송되지 않음. 의존성 자동 설치와 같은 통제
        raise ScanError(
            "CONFIRM_REQUIRED",
            "프롬프트 전송에는 명시적 동의 필요 (confirm=true)",
        )
    cleaned = _clean(messages)
    if not cleaned:
        raise ScanError("INVALID_REQUEST", "보낼 내용 없음")

    # 프롬프트에는 실제 호스트·경로가 들어 있다. 나가는 길에만 치환하고
    # 돌아온 가이드는 되돌려 실제 값으로 보여줌 (docs/01 §7.4)
    masker = Masker() if settings_repo.as_bool(
        raw.get("llm_mask_identifiers"), default=True
    ) else None
    outbound = [
        {"role": m["role"], "content": masker.mask(m["content"]) if masker else m["content"]}
        for m in cleaned
    ]

    provider = _provider(raw)
    try:
        text = provider.complete(
            [{"role": "system", "content": _GUIDE_SYSTEM}, *outbound],
            max_tokens=GUIDE_MAX_TOKENS,
        )
    except LlmError as exc:
        raise ScanError("LLM_UNAVAILABLE", str(exc), status_code=502) from exc

    return {
        "role": "assistant",
        "content": masker.unmask(text) if masker else text,
        "model": raw.get("llm_model"),
        "masked": masker is not None,
    }


def _clean(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    """역할·길이 통제. 사용자가 보내는 값이라 경계에서 잘라냄"""
    cleaned = []
    for message in messages[-MAX_MESSAGES:]:
        role = message.get("role")
        content = (message.get("content") or "").strip()
        if role not in ("user", "assistant") or not content:
            continue
        cleaned.append({"role": role, "content": content[:MAX_MESSAGE_CHARS]})
    return cleaned
