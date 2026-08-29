"""공통 Enum. 정본은 docs/00_API_SPEC.md §0.4.

문자열 리터럴 분산 방지용 단일 정의 지점.
값 추가 순서: API 문서 -> GUI 표시 문자열 -> 이 파일
"""
from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SeverityGuide(StrEnum):
    """가이드 등급. 값이 한글이므로 멤버명은 로마자.

    사용처 2곳, 의미 상이 (docs/00 §0.4)
      findings.severity_guide      탐지 심각도 환산값   -> Part A
      guide_items.severity_guide   점검항목 고유 중요도 -> Part B
    """

    SANG = "상"
    JUNG = "중"
    HA = "하"


class VulnType(StrEnum):
    """14종. 미매핑은 전부 OTHER.

    v0.2 에서 CSRF / FILE_UPLOAD / OPEN_REDIRECT 추가. 근거는 실측.
    CWE-434(파일 업로드) 50건이 5곳으로 분산되어 유형별 분류축 무의미화
    """

    RCE = "rce"
    SQLI = "sqli"
    XSS = "xss"
    CSRF = "csrf"
    SSRF = "ssrf"
    AUTH_BYPASS = "auth_bypass"
    DESERIALIZATION = "deserialization"
    PATH_TRAVERSAL = "path_traversal"
    FILE_UPLOAD = "file_upload"
    OPEN_REDIRECT = "open_redirect"
    INFO_DISCLOSURE = "info_disclosure"
    ACCESS_CONTROL = "access_control"
    MISCONFIG = "misconfig"
    OTHER = "other"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


class FindingStatus(StrEnum):
    OPEN = "open"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    # 'fixed' 추가 금지. 도구는 조치 성공 판정 불가 (docs/01 §1.1)


class TemplateSource(StrEnum):
    OFFICIAL = "official"
    CUSTOM = "custom"


class GuideVerdict(StrEnum):
    SAFE = "safe"
    VULNERABLE = "vulnerable"
    # '점검하지 않음'과 '양호' 혼동 방지용 별도 값 (절대규칙 10)
    NOT_APPLICABLE = "not_applicable"


class CompareState(StrEnum):
    """fixed / still_vulnerable 아님

    스캐너는 '조치 성공' 판정 불가. '이번엔 탐지되지 않음'만 표현 가능
    """

    RESOLVED = "resolved"
    PERSISTED = "persisted"
    EMERGED = "emerged"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# GUI 표시 문자열. docs/00 §0.4 표기 그대로.
# GUI 측 중복 정의 방지용. API 로 전달
SEVERITY_LABELS: dict[Severity, str] = {
    Severity.CRITICAL: "치명적",
    Severity.HIGH: "높음",
    Severity.MEDIUM: "중간",
    Severity.LOW: "낮음",
    Severity.INFO: "정보",
}

VULN_TYPE_LABELS: dict[VulnType, str] = {
    VulnType.RCE: "원격 코드 실행",
    VulnType.SQLI: "SQL 인젝션",
    VulnType.XSS: "크로스사이트 스크립트",
    VulnType.CSRF: "크로스사이트 요청 위조",
    VulnType.SSRF: "서버사이드 요청 위조",
    VulnType.AUTH_BYPASS: "인증 우회",
    VulnType.DESERIALIZATION: "역직렬화",
    VulnType.PATH_TRAVERSAL: "경로 조작",
    VulnType.FILE_UPLOAD: "악성 파일 업로드",
    VulnType.OPEN_REDIRECT: "오픈 리다이렉트",
    VulnType.INFO_DISCLOSURE: "정보 노출",
    VulnType.ACCESS_CONTROL: "접근 통제",
    VulnType.MISCONFIG: "설정 오류",
    VulnType.OTHER: "기타",
}

GUIDE_VERDICT_LABELS: dict[GuideVerdict, str] = {
    GuideVerdict.SAFE: "양호",
    GuideVerdict.VULNERABLE: "취약",
    GuideVerdict.NOT_APPLICABLE: "해당 없음",
}

COMPARE_STATE_LABELS: dict[CompareState, str] = {
    CompareState.RESOLVED: "미탐지",
    CompareState.PERSISTED: "지속 탐지",
    CompareState.EMERGED: "신규 탐지",
}
