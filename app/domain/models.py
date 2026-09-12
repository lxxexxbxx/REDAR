"""계층 경계 Pydantic 모델. 정본은 docs/00_API_SPEC.md §1.

Report 골격(§1.3)을 타입으로 고정. 렌더러·LLM 은 소비만 하고 구조 변경 불가.
"대상 무관 동일 보고서" 요구사항의 구현 수단. 세부 필드는 M7 에서 builder 와 함께 정리
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.domain.enums import (
    Confidence,
    FindingStatus,
    GuideVerdict,
    Severity,
    SeverityGuide,
    TemplateSource,
    VulnType,
)

# 서술 문장 출처. LLM 실패 시 'template' (docs/04 §5.3)
NarrativeSource = Literal["llm", "template"]

# 응답 원문 절단 처리.
# findings 테이블에 절단 플래그 컬럼 없음 + db/schema.sql 동결.
# 별도 컬럼 대신 본문 말미 마커로 표시. 마커 존재 = 절단됨. M2 파서에서 사용
EVIDENCE_MAX_BYTES = 32 * 1024
EVIDENCE_TRUNCATED_MARKER = "\n...[REDAR] 응답 본문 32KB 초과로 절단됨"

# 자동 점검 커버리지 고지. 누락 시 '점검하지 않은 것'이 '양호'로 오독
# (절대규칙 10, docs/04 B-1). 숫자는 실제 guide_coverage 값 사용
# 강조 표시 대상. 보고서에서 이 문장만 굵게 렌더링 (renderer.emphasize)
COVERAGE_CAUTION = "탐지되지 않음이 전체 시스템의 양호를 뜻하지는 않습니다."
# 환경 기반 제외 고지. 제외 = 미탐지 제품 추정이며 점검 결과가 아님 (절대규칙 10)
EXCLUSION_CAUTION = "제외는 해당 제품이 탐지되지 않았다는 뜻이며 양호를 의미하지 않습니다."
COVERAGE_NOTICE_TEMPLATE = (
    "본 점검은 웹 요청 기반입니다. {scope}만 자동 점검 대상입니다. "
    + COVERAGE_CAUTION
)
_SCOPE_WITH_GUIDE = "가이드 전체 {items_total}개 점검항목 중 {items_covered}개"
# 본문 미탑재 시 전체 항목 수를 알 수 없음. 0개로 표기하면 커버리지가 완전한 것처럼 읽힘
_SCOPE_WITHOUT_GUIDE = "자동 점검 가능 항목 {items_covered}개(가이드 본문 미탑재)"


def format_coverage_notice(items_total: int, items_covered: int) -> str:
    template = _SCOPE_WITH_GUIDE if items_total else _SCOPE_WITHOUT_GUIDE
    scope = template.format(items_total=items_total, items_covered=items_covered)
    return COVERAGE_NOTICE_TEMPLATE.format(scope=scope)


class Strict(BaseModel):
    """미지의 필드 무시 방지. 경계에서 오타 검출용 기본값"""

    model_config = ConfigDict(extra="forbid")


# =========================================================== Finding (§1.1)


class Target(Strict):
    raw: str
    scheme: str | None = None
    host: str
    port: int | None = None
    path: str | None = None


class Evidence(Strict):
    request: str | None = None
    response: str | None = None
    extracted_values: list[str] = Field(default_factory=list)
    # 사용자 수동 재현용 문자열. 도구 실행 없음 (절대규칙 1)
    curl_command: str | None = None


class Finding(Strict):
    finding_id: str
    scan_id: str
    # 탐지 시점 계산 후 저장. 렌더링 시점 재계산 금지 (절대규칙 7)
    fingerprint: str

    source: str = "nuclei"
    template_id: str
    template_source: TemplateSource = TemplateSource.OFFICIAL
    matcher_name: str | None = None

    target: Target

    name: str
    description: str | None = None
    vuln_type: VulnType = VulnType.OTHER
    severity: Severity
    # 탐지 심각도 환산값. 점검항목 중요도(guide_items.severity_guide)와 다른 값
    severity_guide: SeverityGuide

    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None

    component_type: str | None = None
    component_slug: str | None = None

    evidence: Evidence = Field(default_factory=Evidence)
    # 가이드 DB 미탑재 시 빈 배열. 정상 상태 (절대규칙 3)
    guide_refs: list[str] = Field(default_factory=list)

    status: FindingStatus = FindingStatus.OPEN
    detected_at: datetime


# ================================================ EnvironmentProfile (§1.2)


class StackItem(Strict):
    product: str | None = None
    version: str | None = None
    confidence: Confidence = Confidence.MEDIUM


class EnvComponent(Strict):
    type: str
    slug: str
    name: str | None = None
    # 확정 불가 시 None + confidence=low. 추정값의 확정 표기 금지
    version: str | None = None
    active: bool | None = None
    confidence: Confidence = Confidence.MEDIUM
    evidence: str | None = None


class Exposure(Strict):
    # 키 정본은 docs/00 §1.2 의 11종. 수집기 미생성 키를 매핑에 두면 영구 미판정
    key: str
    value: bool
    path: str | None = None
    evidence: str | None = None


class EnvironmentProfile(Strict):
    profile_id: str
    scan_id: str
    target_host: str
    collected_at: datetime

    web_server: StackItem = Field(default_factory=StackItem)
    language: StackItem = Field(default_factory=StackItem)
    application: StackItem = Field(default_factory=StackItem)

    components: list[EnvComponent] = Field(default_factory=list)
    exposures: list[Exposure] = Field(default_factory=list)

    collectors_run: list[str] = Field(default_factory=list)
    # 수집기 실패는 스캔 중단 사유 아님. 기록 후 계속 진행
    collectors_failed: list[str] = Field(default_factory=list)


# ============================================================ Report (§1.3)


class GuideDbInfo(Strict):
    imported: bool = False
    version: str | None = None
    item_count: int = 0


class GuideCoverage(Strict):
    items_total: int = 0
    items_covered: int = 0


class MatchedComponent(Strict):
    slug: str
    version: str | None = None
    templates: list[str] = Field(default_factory=list)


class MatchedStack(Strict):
    product: str
    version: str | None = None
    templates: list[str] = Field(default_factory=list)


class SelectionBasis(Strict):
    """environment_driven 모드의 템플릿 선별 근거. 타 모드에서는 None.

    None 이어도 해당 절 렌더링 (조건부 섹션 금지, 절대규칙 4)
    """

    matched_components: list[MatchedComponent] = Field(default_factory=list)
    matched_stack: list[MatchedStack] = Field(default_factory=list)
    total_selected: int = 0
    total_available: int = 0


class LlmMeta(Strict):
    used: bool = False
    provider: str | None = None
    model: str | None = None
    prompt_version: str | None = None


class ReportMeta(Strict):
    target_summary: str
    scan_started_at: datetime | None = None
    scan_duration_sec: int | None = None
    tool_version: str
    nuclei_version: str | None = None
    template_revision: str | None = None
    guide_db: GuideDbInfo = Field(default_factory=GuideDbInfo)
    guide_coverage: GuideCoverage = Field(default_factory=GuideCoverage)
    selection_basis: SelectionBasis | None = None
    llm: LlmMeta = Field(default_factory=LlmMeta)


class TopRisk(Strict):
    finding_id: str
    name: str
    severity: Severity
    reason: str | None = None


def _zero_by_severity() -> dict[Severity, int]:
    return {s: 0 for s in Severity}


def _zero_by_vuln_type() -> dict[VulnType, int]:
    return {v: 0 for v in VulnType}


class ExecutiveSummary(Strict):
    total_findings: int = 0
    # 심각도 5종·유형 14종 항상 전부 포함. 0건도 0 유지 (절대규칙 4)
    by_severity: dict[Severity, int] = Field(default_factory=_zero_by_severity)
    by_vuln_type: dict[VulnType, int] = Field(default_factory=_zero_by_vuln_type)
    top_risks: list[TopRisk] = Field(default_factory=list)
    narrative: str = ""
    narrative_generated_by: NarrativeSource = "template"


class SeverityGroup(Strict):
    severity: Severity
    count: int = 0
    findings: list[str] = Field(default_factory=list)


class VulnTypeGroup(Strict):
    vuln_type: VulnType
    count: int = 0
    findings: list[str] = Field(default_factory=list)


def _all_severity_groups() -> list[SeverityGroup]:
    return [SeverityGroup(severity=s) for s in Severity]


def _all_vuln_type_groups() -> list[VulnTypeGroup]:
    return [VulnTypeGroup(vuln_type=v) for v in VulnType]


class FixTrack(Strict):
    summary: str | None = None
    steps: list[str] = Field(default_factory=list)


class RemediationItem(Strict):
    finding_ids: list[str] = Field(default_factory=list)
    title: str
    # 패치 트랙(즉시 조치) / 유형 트랙(근본 대책) 분리 (docs/04 A-6)
    root_fix: FixTrack = Field(default_factory=FixTrack)
    temporary_fix: FixTrack = Field(default_factory=FixTrack)
    source: Literal["guide", "template"] = "template"
    guide_item_code: str | None = None
    guide_citation: str | None = None
    # 가이드 원문 그대로. LLM 가공 문장으로 대체 금지 (절대규칙 9)
    guide_remediation_original: str | None = None
    narrative_generated_by: NarrativeSource = "template"


class PatchPlanItem(Strict):
    component_type: str
    slug: str
    installed_version: str | None = None
    # None = 버전 업그레이드 대상 아님(951행 중 332행).
    # 빈칸은 데이터 누락으로 오독되므로 렌더러가 문구로 대체 (docs/04 A-6)
    upgrade_to_at_least: str | None = None
    cve_ids: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    max_cvss: float | None = None


class GuideMappingItem(Strict):
    item_code: str
    item_code_raw: str | None = None
    # 가이드 본문 미탑재 시 아래 원문 필드 전부 None. 정상 상태
    item_name: str | None = None
    category: str | None = None
    # 점검항목 고유 중요도(가이드 원문값). findings.severity_guide 로 덮어쓰기 금지
    item_severity: SeverityGuide | None = None
    verdict: GuideVerdict
    is_primary: bool = False
    basis_finding_ids: list[str] = Field(default_factory=list)
    criteria_safe: str | None = None
    criteria_vuln: str | None = None
    remediation: str | None = None
    citation: str | None = None


class GuideMappingSummary(Strict):
    safe: int = 0
    vulnerable: int = 0
    not_applicable: int = 0


class GuideMapping(Strict):
    # False = 가이드 본문 미탑재. items 는 빈 배열, Part B 는 안내 문구로 대체
    available: bool = False
    items: list[GuideMappingItem] = Field(default_factory=list)
    summary: GuideMappingSummary = Field(default_factory=GuideMappingSummary)
    # 기본값 없음. 누락 시 검증 오류로 노출되어야 함 (절대규칙 10).
    # format_coverage_notice() 사용
    coverage_notice: str


class UnmappedFinding(Strict):
    finding_id: str
    name: str
    severity: Severity
    template_id: str
    reason: str = "no_mapping"


class FalsePositive(Strict):
    finding_id: str
    name: str
    severity: Severity
    note: str | None = None


# ─────────────────────────────────── LLM 조치 가이드 (Part D)
#
# Part A~C 는 진단 근거에서 결정론적으로 도출된다. 이 절만 생성 문장이므로
# 출처와 책임을 절 안에서 못 박지 않으면, 같은 문서 안에서 근거와 추정이
# 구분되지 않는다. 두 문장 모두 렌더러가 조건 없이 출력한다
LLM_GUIDE_ORIGIN_NOTICE = (
    "이 절의 내용은 LLM(생성형 AI)이 작성한 것입니다. 본 보고서의 다른 절과 달리"
    " 진단 근거에서 도출된 값이 아니며, 사실과 다른 내용이 포함될 수 있습니다."
    " 적용 전에 담당자가 내용을 확인해야 합니다."
)
LLM_GUIDE_RESPONSIBILITY_NOTICE = (
    "REDAR 는 조치 상세 방안을 제시할 뿐 실제 조치를 수행하지 않습니다."
    " 조치의 적용 여부와 방법은 사용자가 직접 판단해야 하며,"
    " 조치 수행과 그 결과에 대한 책임은 전적으로 사용자에게 있습니다."
)
# 강조 표시 대상. 보고서에서 이 구절만 굵게 렌더링 (renderer.emphasize)
LLM_GUIDE_CAUTION = "책임은 전적으로 사용자에게 있습니다."


class LlmRemediationGuide(Strict):
    """생성형 AI 가 작성한 조치 절차.

    보고서 생성 이후에 첨부된다. Part A~C 를 바꾸지 않으며, 첨부하지 않은
    보고서도 완성품이다 (절대규칙 2)
    """

    content: str
    model: str | None = None
    provider: str | None = None
    generated_at: datetime | None = None
    origin_notice: str = LLM_GUIDE_ORIGIN_NOTICE
    responsibility_notice: str = LLM_GUIDE_RESPONSIBILITY_NOTICE


class TemplateRef(Strict):
    template_id: str
    source: TemplateSource


class SeverityBandRow(Strict):
    cvss_range: str
    severity: Severity
    severity_guide: SeverityGuide


class Appendix(Strict):
    # app/config/severity_map.yaml 에서 생성. 환산 근거 명시용 표
    severity_conversion_table: list[SeverityBandRow] = Field(default_factory=list)
    templates_used: list[TemplateRef] = Field(default_factory=list)
    llm_generated_sections: list[str] = Field(default_factory=list)


class Report(Strict):
    """렌더링 이전에 완결된 보고서. 렌더러는 이 JSON 외 DB 조회 없음

    unmapped_findings / false_positives 누락 시 Part A 와 Part B 건수 불일치 발생.
    0건이어도 빈 배열로 존재
    """

    report_id: str
    scan_id: str
    generated_at: datetime

    meta: ReportMeta
    executive_summary: ExecutiveSummary = Field(default_factory=ExecutiveSummary)
    environment_profile: EnvironmentProfile | None = None

    findings_by_severity: list[SeverityGroup] = Field(
        default_factory=_all_severity_groups
    )
    findings_by_vuln_type: list[VulnTypeGroup] = Field(
        default_factory=_all_vuln_type_groups
    )
    findings_detail: list[Finding] = Field(default_factory=list)

    remediation: list[RemediationItem] = Field(default_factory=list)
    patch_plan: list[PatchPlanItem] = Field(default_factory=list)
    guide_mapping: GuideMapping

    unmapped_findings: list[UnmappedFinding] = Field(default_factory=list)
    false_positives: list[FalsePositive] = Field(default_factory=list)
    appendix: Appendix = Field(default_factory=Appendix)
    # 보고서 생성 후 사용자가 첨부. None = 미첨부이며 정상 상태.
    # 절은 항상 렌더링되고 미첨부면 안내 문구가 들어감 (절대규칙 4)
    llm_remediation_guide: LlmRemediationGuide | None = None
