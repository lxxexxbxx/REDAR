-- ============================================================
--  REDAR — SQLite 스키마
--  version: 0.2
--  대상: SQLite 3.35+ (json1, FTS5, STRICT 테이블 미사용)
--
--  v0.1 -> v0.2 변경 (근거: docs/CHANGELOG.md)
--   - VulnType 3종 추가 (csrf / file_upload / open_redirect)
--   - guide_items 원문 필드 확장 + 출처 페이지 + 이미지 + FTS
--   - component_advisories 신설 (패치 목표 버전)
--   - templates 에 cvss / fixed_version / is_detection / component_slugs
--   - guide_mappings 에 cve_id·cve_present·component_slug 매핑 키
--   - finding_guide_refs 에 is_primary / matched_by
--   - 뷰 3종 추가
-- ============================================================
--  적용:  sqlite3 redar.db < db/schema.sql
-- ============================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;          -- 스캔 중 쓰기 + GUI 읽기 병행
PRAGMA synchronous  = NORMAL;

-- ============================================================
-- 0. 메타
-- ============================================================

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- 단일 행 설정. key-value 로 두어 마이그레이션 없이 항목 추가 가능
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,            -- JSON 또는 스칼라 문자열
    updated_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);


-- ============================================================
-- 1. 스캔
-- ============================================================

CREATE TABLE IF NOT EXISTS scans (
    scan_id             TEXT PRIMARY KEY,            -- 'scn_' + ULID
    status              TEXT NOT NULL
        CHECK (status IN ('queued','running','completed','failed','canceled')),

    -- 템플릿 선별
    selection_mode      TEXT NOT NULL
        CHECK (selection_mode IN ('explicit','filter','environment_driven')),
    selection_detail    TEXT,                        -- JSON: template_ids / tags / severity
    selection_basis     TEXT,                        -- JSON: environment_driven 선별 근거

    -- 실행 옵션
    collect_environment INTEGER NOT NULL DEFAULT 1,  -- boolean
    opt_threads         INTEGER NOT NULL DEFAULT 20,
    opt_timeout_sec     INTEGER NOT NULL DEFAULT 10,
    opt_retries         INTEGER NOT NULL DEFAULT 1,
    opt_rate_limit      INTEGER,

    -- 실행 결과
    templates_total     INTEGER,
    templates_done      INTEGER,
    error_code          TEXT,
    error_message       TEXT,

    -- 재현성 기록 (보고서 meta 에 그대로 사용)
    tool_version        TEXT,
    nuclei_version      TEXT,
    template_revision   TEXT,

    created_at          TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    started_at          TEXT,
    finished_at         TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_status  ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);


-- 스캔 대상 (1 스캔 : N 대상)
CREATE TABLE IF NOT EXISTS scan_targets (
    scan_target_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    raw             TEXT NOT NULL,                   -- 사용자 입력 원문
    scheme          TEXT,
    host            TEXT NOT NULL,
    port            INTEGER,
    UNIQUE (scan_id, raw)
);

CREATE INDEX IF NOT EXISTS idx_scan_targets_scan ON scan_targets(scan_id);


-- ============================================================
-- 2. 환경 조사
-- ============================================================

CREATE TABLE IF NOT EXISTS environment_profiles (
    profile_id        TEXT PRIMARY KEY,              -- 'env_' + ULID
    scan_id           TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    target_host       TEXT NOT NULL,                 -- 'example.com:8080'

    -- 주요 스택. confidence: high | medium | low
    web_server_product     TEXT,
    web_server_version     TEXT,
    web_server_confidence  TEXT,
    language_product       TEXT,
    language_version       TEXT,
    language_confidence    TEXT,
    application_product    TEXT,
    application_version    TEXT,
    application_confidence TEXT,

    collectors_run    TEXT,                          -- JSON 배열
    collectors_failed TEXT,                          -- JSON 배열
    collected_at      TEXT NOT NULL DEFAULT (datetime('now','localtime')),

    UNIQUE (scan_id, target_host)
);

CREATE INDEX IF NOT EXISTS idx_env_scan ON environment_profiles(scan_id);


-- 구성요소 (WP 플러그인/테마, Apache 모듈 등)
CREATE TABLE IF NOT EXISTS env_components (
    component_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id    TEXT NOT NULL REFERENCES environment_profiles(profile_id) ON DELETE CASCADE,
    type          TEXT NOT NULL,                     -- wp_plugin | wp_theme | apache_module | ...
    slug          TEXT NOT NULL,
    name          TEXT,
    version       TEXT,                              -- NULL = 확정 불가
    active        INTEGER,                           -- boolean, NULL = 불명
    confidence    TEXT NOT NULL DEFAULT 'medium',
    evidence      TEXT,                              -- 판단 근거 경로/문자열
    UNIQUE (profile_id, type, slug)
);

CREATE INDEX IF NOT EXISTS idx_env_comp_profile ON env_components(profile_id);
CREATE INDEX IF NOT EXISTS idx_env_comp_slug    ON env_components(slug);


-- 노출 항목 (xmlrpc, 사용자 열거, 디렉터리 리스팅 등)
CREATE TABLE IF NOT EXISTS env_exposures (
    exposure_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id    TEXT NOT NULL REFERENCES environment_profiles(profile_id) ON DELETE CASCADE,
    key           TEXT NOT NULL,                     -- 'xmlrpc_enabled' 등
    value         INTEGER NOT NULL,                  -- boolean
    path          TEXT,
    evidence      TEXT,
    UNIQUE (profile_id, key)
);

CREATE INDEX IF NOT EXISTS idx_env_expo_profile ON env_exposures(profile_id);


-- ============================================================
-- 3. 탐지 결과
-- ============================================================

CREATE TABLE IF NOT EXISTS findings (
    finding_id       TEXT PRIMARY KEY,               -- 'fnd_' + ULID
    scan_id          TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,

    -- 스캔 간 동일 항목 식별.
    -- sha256(template_id | host | port | normalized_path | matcher_name)
    fingerprint      TEXT NOT NULL,

    source           TEXT NOT NULL DEFAULT 'nuclei',
    template_id      TEXT NOT NULL,
    template_source  TEXT NOT NULL DEFAULT 'official'
        CHECK (template_source IN ('official','custom')),
    matcher_name     TEXT,

    -- 대상
    target_raw       TEXT NOT NULL,
    target_scheme    TEXT,
    target_host      TEXT NOT NULL,
    target_port      INTEGER,
    target_path      TEXT,

    -- 분류
    name             TEXT NOT NULL,
    description      TEXT,
    vuln_type        TEXT NOT NULL DEFAULT 'other'
        CHECK (vuln_type IN ('rce','sqli','xss','csrf','ssrf','auth_bypass',
                             'deserialization','path_traversal','file_upload',
                             'open_redirect','info_disclosure','access_control',
                             'misconfig','other')),
    severity         TEXT NOT NULL
        CHECK (severity IN ('critical','high','medium','low','info')),
    -- severity 에서 환산하여 저장. 렌더링 시점 계산 금지 (원칙 P4).
    -- 주의: guide_items.severity_guide(점검항목 고유 중요도)와 다른 값이다.
    --       이쪽은 '이번 탐지의 심각도'를 가이드 등급으로 환산한 것이고,
    --       저쪽은 '점검항목 자체의 중요도'로 가이드 원문에 적힌 값이다.
    --       보고서 Part A 는 이 값을, Part B 는 guide_items 값을 쓴다.
    severity_guide   TEXT NOT NULL
        CHECK (severity_guide IN ('상','중','하')),

    cve_ids          TEXT,                           -- JSON 배열
    cwe_ids          TEXT,                           -- JSON 배열
    cvss_score       REAL,
    cvss_vector      TEXT,

    -- 영향 구성요소. 패치 계획(v_patch_plan) 산출에 필요
    component_type   TEXT,                           -- wp_plugin | wp_theme | core
    component_slug   TEXT,

    -- 근거
    ev_request       TEXT,
    ev_response      TEXT,
    ev_extracted     TEXT,                           -- JSON 배열
    ev_curl          TEXT,                           -- 사용자 수동 재현용. 도구가 실행하지 않음

    status           TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open','false_positive','accepted_risk')),
    status_note      TEXT,

    detected_at      TEXT NOT NULL DEFAULT (datetime('now','localtime')),

    -- 동일 스캔 내 중복 방지
    UNIQUE (scan_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_find_scan        ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_find_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_find_severity    ON findings(scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_find_vulntype    ON findings(scan_id, vuln_type);
CREATE INDEX IF NOT EXISTS idx_find_host        ON findings(scan_id, target_host);
CREATE INDEX IF NOT EXISTS idx_find_status      ON findings(scan_id, status);
CREATE INDEX IF NOT EXISTS idx_find_template    ON findings(template_id);
CREATE INDEX IF NOT EXISTS idx_find_component   ON findings(component_slug);


-- Finding ↔ 가이드 점검항목 (N:M)
CREATE TABLE IF NOT EXISTS finding_guide_refs (
    finding_id   TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    item_code    TEXT NOT NULL,                      -- guide_items.item_code (FK 아님: 본문 미탑재 가능)
    confidence   TEXT NOT NULL DEFAULT 'high',
    -- 대표 항목 여부. 보고서 Part B 본문은 is_primary=1 기준으로 묶는다.
    -- CVE 를 가진 탐지에는 WEB-25(패치)가 함께 붙는데, 그것을 대표로 삼으면
    -- 모든 CVE 가 패치 항목 하나로 수렴해 유형별 조치가 사라진다.
    is_primary   INTEGER NOT NULL DEFAULT 0,
    matched_by   TEXT,                               -- 'cwe_id:CWE-79' 등 매칭 근거
    PRIMARY KEY (finding_id, item_code)
);

CREATE INDEX IF NOT EXISTS idx_fgr_item ON finding_guide_refs(item_code);

-- 주의: item_code 에 FK 를 걸지 않는다.
--       가이드 본문(guide_items)이 미탑재인 상태에서도 매핑 결과를 보존해야 하기 때문.


-- ============================================================
-- 4. 템플릿
-- ============================================================

CREATE TABLE IF NOT EXISTS templates (
    template_id   TEXT PRIMARY KEY,                  -- nuclei 템플릿 id
    source        TEXT NOT NULL
        CHECK (source IN ('official','custom')),
    file_path     TEXT NOT NULL,
    name          TEXT NOT NULL,
    description   TEXT,
    severity      TEXT
        CHECK (severity IN ('critical','high','medium','low','info')),
    vuln_type     TEXT,
    cve_ids       TEXT,                              -- JSON 배열
    cwe_ids       TEXT,                              -- JSON 배열
    tags          TEXT,                              -- JSON 배열
    cvss_score    REAL,
    cvss_vector   TEXT,
    -- 템플릿 이름의 "< 4.2.7.1" 표기에서 추출한 패치 목표 버전.
    -- 보고서 A-6 "근본 조치: 패치 버전 명시" 의 근거값이다.
    fixed_version TEXT,
    -- 자산 식별 전용 템플릿(플러그인·테마 탐지). 취약점이 아니므로 부록 처리.
    is_detection  INTEGER NOT NULL DEFAULT 0,
    component_slugs TEXT,                            -- CSV. 대상 플러그인/테마 slug

    -- 빌더로 만든 경우 폼 구조 보존 (양방향 편집)
    form_json     TEXT,
    yaml_hash     TEXT,                              -- 외부 편집 감지용

    created_at    TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE INDEX IF NOT EXISTS idx_tpl_source   ON templates(source);
CREATE INDEX IF NOT EXISTS idx_tpl_severity ON templates(severity);
CREATE INDEX IF NOT EXISTS idx_tpl_detection ON templates(is_detection);


-- 구성요소 취약 버전 정보 (번들 · data/component_advisories.csv 에서 적재)
-- env_components.version(설치 버전)과 대조해 업그레이드 목표를 산출한다.
CREATE TABLE IF NOT EXISTS component_advisories (
    advisory_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    component_type  TEXT NOT NULL,                   -- wp_plugin | wp_theme | core
    slug            TEXT NOT NULL,
    cve_id          TEXT,
    template_id     TEXT,
    title           TEXT,
    affected_range  TEXT,                            -- '< 4.2.7.1'
    fixed_version   TEXT,                            -- '4.2.7.1'. NULL = 최신 버전으로
    -- 버전 정렬키. 문자열 MAX 는 '4.10.1' < '4.9.0' 으로 잘못 비교한다.
    -- 각 세그먼트를 5자리 zero-pad 하여 저장 ('4.10.1' -> '00004.00010.00001')
    fixed_version_key TEXT,
    severity        TEXT,
    cvss_score      REAL,
    reference       TEXT,
    data_source     TEXT NOT NULL DEFAULT 'nuclei-template',
    updated_at      TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- SQLite 는 테이블 UNIQUE 제약에 식을 쓸 수 없어 식 인덱스로 대체
CREATE UNIQUE INDEX IF NOT EXISTS uq_advisory
    ON component_advisories(component_type, slug,
                            COALESCE(cve_id,''), COALESCE(template_id,''));
CREATE INDEX IF NOT EXISTS idx_adv_slug ON component_advisories(component_type, slug);
CREATE INDEX IF NOT EXISTS idx_adv_cve  ON component_advisories(cve_id);


-- 스캔에서 실제 실행된 템플릿 (보고서 부록 · 재현성)
CREATE TABLE IF NOT EXISTS scan_templates (
    scan_id      TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    template_id  TEXT NOT NULL,
    source       TEXT NOT NULL,
    PRIMARY KEY (scan_id, template_id)
);


-- ============================================================
-- 5. 보고서
-- ============================================================

CREATE TABLE IF NOT EXISTS reports (
    report_id            TEXT PRIMARY KEY,           -- 'rpt_' + ULID
    scan_id              TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    compare_with_scan_id TEXT REFERENCES scans(scan_id) ON DELETE SET NULL,

    status               TEXT NOT NULL DEFAULT 'generating'
        CHECK (status IN ('generating','completed','failed')),

    -- 생성 옵션
    opt_use_llm                INTEGER NOT NULL DEFAULT 0,
    opt_include_guide_mapping  INTEGER NOT NULL DEFAULT 1,
    opt_include_evidence       INTEGER NOT NULL DEFAULT 1,
    opt_exclude_false_positives INTEGER NOT NULL DEFAULT 1,
    -- 가이드 '점검 및 조치 사례' 원문 포함 여부. 항목당 최대 8.7천 자라 옵션화한다
    opt_include_guide_cases     INTEGER NOT NULL DEFAULT 1,

    -- 저하 상태 기록 (§01 문서 §6)
    guide_db_available   INTEGER NOT NULL DEFAULT 0,
    guide_db_version     TEXT,
    llm_used             INTEGER NOT NULL DEFAULT 0,
    llm_provider         TEXT,
    llm_model            TEXT,
    llm_prompt_version   TEXT,
    llm_fallback_count   INTEGER NOT NULL DEFAULT 0, -- LLM 실패로 템플릿 문장 대체된 횟수

    -- 자동 점검 커버리지. 보고서 개요의 "탐지되지 않음 != 양호" 고지 근거.
    -- 원격 스캐너는 가이드 항목의 일부만 점검할 수 있다.
    guide_items_total    INTEGER,
    guide_items_covered  INTEGER,

    -- 완성된 Report JSON. 렌더러와 GUI 미리보기가 공통으로 소비
    report_json          TEXT,

    error_message        TEXT,
    generated_at         TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE INDEX IF NOT EXISTS idx_report_scan ON reports(scan_id);


CREATE TABLE IF NOT EXISTS report_files (
    file_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id   TEXT NOT NULL REFERENCES reports(report_id) ON DELETE CASCADE,
    format      TEXT NOT NULL CHECK (format IN ('pdf','html','json')),
    file_path   TEXT NOT NULL,
    size_bytes  INTEGER,
    sha256      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE (report_id, format)
);


-- ============================================================
-- 6. 가이드 데이터
-- ============================================================
--  3층 구조 (docs/03_GUIDE_DATA.md 참조)
--    (1) 스키마            : 저장소 포함  ← 이 파일
--    (2) 매핑 테이블        : 저장소 포함  ← guide_mappings, vuln_type_rules
--    (3) 가이드 본문        : 사용자 임포트 ← guide_items
-- ============================================================

-- (3) KISA 가이드 본문. 저장소에 포함하지 않으며 사용자가 임포트한다.
CREATE TABLE IF NOT EXISTS guide_items (
    item_code       TEXT PRIMARY KEY,                -- 'WA-02', 'WEB-25', 'U-01' ...
    -- 원문 약어. 10장 Web Application 은 'CI','SI' 등 하이픈 없는 별도 체계이고
    -- 원문에 'CC' 중복(18 쿠키 변조 / 20 자동화 공격)이 있어 PK 로 쓸 수 없다.
    -- PK 는 WA-nn 으로 정규화하고 원문 약어는 여기에 보존한다.
    item_code_raw   TEXT,
    item_name       TEXT NOT NULL,
    category        TEXT,                            -- §03_GUIDE_DATA 의 12종
    section         TEXT,                            -- 'UNIX > 1. 계정 관리'
    severity_guide  TEXT CHECK (severity_guide IN ('상','중','하')),

    -- --- 원문 필드. 재작성 금지, 그대로 인용한다 ---
    check_content   TEXT,                            -- 점검 내용
    check_purpose   TEXT,                            -- 점검 목적
    security_threat TEXT,                            -- 보안 위협
    reference_note  TEXT,                            -- 참고
    target          TEXT,                            -- 점검 대상
    criteria_safe   TEXT,                            -- 양호 판단기준
    criteria_vuln   TEXT,                            -- 취약 판단기준
    remediation     TEXT,                            -- 조치 방법 (요약 1~2문장)
    impact          TEXT,                            -- 조치 시 영향
    detail          TEXT,                            -- 상세 설명 (이동통신 M-xx 형)
    -- 점검 및 조치 사례. 실제 조치 절차 본문이며 항목당 평균 948자, 중앙값 451자, 최대 8,675자.
    -- 보고서 A-6 조치 사항의 실질 내용이 여기서 나온다.
    case_text       TEXT,
    reference       TEXT,

    -- 출처. 보고서에 "가이드 p.680 근거" 를 표기하기 위해 필요하다.
    page_start      INTEGER,
    page_end        INTEGER,

    guide_version   TEXT NOT NULL,
    imported_at     TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE INDEX IF NOT EXISTS idx_guide_category ON guide_items(category);
CREATE INDEX IF NOT EXISTS idx_guide_severity ON guide_items(severity_guide);


-- 가이드 캡처 이미지. 파일은 외부(data/guide_images/), DB 에는 경로만.
-- 본문과 마찬가지로 사용자 임포트 대상이다.
CREATE TABLE IF NOT EXISTS guide_item_images (
    image_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    item_code   TEXT NOT NULL REFERENCES guide_items(item_code) ON DELETE CASCADE,
    file_path   TEXT NOT NULL,
    page        INTEGER,
    caption     TEXT,
    sort_order  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_guide_img_item ON guide_item_images(item_code);


-- 전문 검색. 매핑 우선순위 4단계가 모두 실패했을 때 유사 항목을 제시하는 용도.
-- 자동 연결에는 쓰지 않는다 (결정론적 매핑 원칙).
CREATE VIRTUAL TABLE IF NOT EXISTS guide_items_fts USING fts5(
    item_code UNINDEXED,
    item_name, check_content, security_threat, remediation, case_text,
    tokenize='unicode61'
);


-- (2) 매핑 테이블. 우리 분석 산출물이며 저장소에 포함한다.
--     data/guide_mappings.csv 를 기동 시 upsert 한다.
CREATE TABLE IF NOT EXISTS guide_mappings (
    mapping_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    match_type     TEXT NOT NULL
        CHECK (match_type IN ('template_id','cve_id','cwe_id','exposure_key',
                              'component_slug','vuln_type','cve_present')),
    match_value    TEXT NOT NULL,
    item_code      TEXT NOT NULL,
    confidence     TEXT NOT NULL DEFAULT 'high'
        CHECK (confidence IN ('high','medium','low')),
    mapping_basis  TEXT,                             -- 매핑 근거 (검토 시 설명용)
    -- 저신뢰 매핑 검수 기록. confidence='low' 행은 검수 전까지 보고서에 "검토 필요" 표기
    reviewed       INTEGER NOT NULL DEFAULT 0,
    reviewed_by    TEXT,
    updated_at     TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE (match_type, match_value, item_code)
);

CREATE INDEX IF NOT EXISTS idx_gmap_lookup ON guide_mappings(match_type, match_value);

CREATE INDEX IF NOT EXISTS idx_gmap_reviewed ON guide_mappings(reviewed, confidence);

-- 매핑 우선순위(구현 규칙):
--   1) template_id     가장 구체적
--   2) cve_id
--   3) cwe_id
--   4) exposure_key    환경 조사 결과 기반
--   5) component_slug
--   6) vuln_type       가장 포괄적. fallback
-- 상위에서 매칭되면 하위는 적용하지 않는다. 이들이 is_primary=1 후보다.
--
-- 예외: match_type='cve_present' (match_value='*')
--   CVE 를 가진 탐지에 항상 추가로 붙는다. 우선순위 규칙 밖이며 is_primary=0 이다.
--   WordPress 플러그인 CVE 는 CWE 유형이 명확해 유형별 항목에 붙는데,
--   패치 항목(WEB-25)까지 같이 붙여야 "버전 올리기"라는 즉시 조치가 보고서에 남는다.
--     유형 트랙  CWE -> WA-xx   근본 대책   is_primary=1
--     패치 트랙  CVE -> WEB-25  즉시 조치   is_primary=0


-- (2) nuclei tags / cwe → VulnType 정규화 규칙. 저장소 포함.
--     data/vuln_type_rules.csv 를 기동 시 upsert 한다.
CREATE TABLE IF NOT EXISTS vuln_type_rules (
    rule_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    match_type  TEXT NOT NULL CHECK (match_type IN ('tag','cwe_id','template_prefix')),
    match_value TEXT NOT NULL,
    vuln_type   TEXT NOT NULL,
    priority    INTEGER NOT NULL DEFAULT 100,        -- 낮을수록 우선
    UNIQUE (match_type, match_value)
);

CREATE INDEX IF NOT EXISTS idx_vtr_lookup ON vuln_type_rules(match_type, match_value);


-- ============================================================
-- 7. 조회 편의 뷰
-- ============================================================

-- 스캔 요약 (목록 화면)
CREATE VIEW IF NOT EXISTS v_scan_summary AS
SELECT
    s.scan_id,
    s.status,
    s.started_at,
    s.finished_at,
    (SELECT group_concat(raw, ', ') FROM scan_targets t WHERE t.scan_id = s.scan_id) AS targets,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS cnt_critical,
    SUM(CASE WHEN f.severity = 'high'     THEN 1 ELSE 0 END) AS cnt_high,
    SUM(CASE WHEN f.severity = 'medium'   THEN 1 ELSE 0 END) AS cnt_medium,
    SUM(CASE WHEN f.severity = 'low'      THEN 1 ELSE 0 END) AS cnt_low,
    SUM(CASE WHEN f.severity = 'info'     THEN 1 ELSE 0 END) AS cnt_info,
    COUNT(f.finding_id) AS cnt_total
FROM scans s
LEFT JOIN findings f
       ON f.scan_id = s.scan_id
      AND f.status <> 'false_positive'
GROUP BY s.scan_id;


-- 가이드 매핑 결과 (본문 미탑재 시 item_name 등이 NULL 로 나온다)
CREATE VIEW IF NOT EXISTS v_finding_guide AS
SELECT
    f.finding_id,
    f.scan_id,
    f.name          AS finding_name,
    f.severity,
    f.target_host,
    r.item_code,
    r.confidence,
    r.is_primary,
    g.item_name,
    g.category,
    g.severity_guide AS item_severity,   -- findings.severity_guide 와 다른 값이다
    g.criteria_vuln,
    g.remediation,
    g.page_start
FROM findings f
JOIN finding_guide_refs r ON r.finding_id = f.finding_id
LEFT JOIN guide_items   g ON g.item_code  = r.item_code;


-- 보고서 Part B 본문 단위. 점검항목별로 묶고 우선순위를 확정한다.
-- 정렬을 SQL 로 고정하는 이유: 같은 스캔에 같은 순서가 나와야 재점검 비교가 성립한다.
-- LLM 은 이 순서에 개입하지 않는다.
CREATE VIEW IF NOT EXISTS v_report_sections AS
SELECT
    f.scan_id,
    r.item_code,
    g.item_name,
    g.category,
    g.severity_guide                AS item_severity,
    COUNT(DISTINCT f.finding_id)    AS finding_count,
    COUNT(DISTINCT f.target_host)   AS host_count,
    MAX(CASE f.severity WHEN 'critical' THEN 100 WHEN 'high' THEN 70
                        WHEN 'medium'   THEN 40  WHEN 'low'  THEN 15
                        ELSE 3 END) AS max_severity_weight,
    (CASE g.severity_guide WHEN '상' THEN 3 WHEN '중' THEN 2 WHEN '하' THEN 1
                           ELSE 0 END) * 1000
    + MAX(CASE f.severity WHEN 'critical' THEN 100 WHEN 'high' THEN 70
                          WHEN 'medium'   THEN 40  WHEN 'low'  THEN 15
                          ELSE 3 END) * 10
    + COUNT(DISTINCT f.target_host) AS priority_score
FROM findings f
JOIN finding_guide_refs r ON r.finding_id = f.finding_id AND r.is_primary = 1
LEFT JOIN guide_items   g ON g.item_code  = r.item_code
WHERE f.status <> 'false_positive'
GROUP BY f.scan_id, r.item_code;


-- 패치 계획. 설치 버전(env_components) x 취약 버전(component_advisories).
-- 보고서 A-6 "근본 조치: 패치 버전 명시" 에 그대로 쓰인다.
CREATE VIEW IF NOT EXISTS v_patch_plan AS
SELECT
    p.scan_id,
    p.target_host,
    c.type                AS component_type,
    c.slug,
    c.version             AS installed_version,
    -- 정렬키로 최대값을 고른 뒤 원본 버전 문자열을 되꺼낸다.
    -- MAX(fixed_version) 를 그냥 쓰면 '4.10.1' 이 '4.9.0' 보다 작다고 판정되어
    -- 패치 목표를 실제보다 낮게 제시하게 된다.
    substr(MAX(COALESCE(a.fixed_version_key,'') || '|' || COALESCE(a.fixed_version,'')),
           instr(MAX(COALESCE(a.fixed_version_key,'') || '|' || COALESCE(a.fixed_version,'')),
                 '|') + 1) AS upgrade_to_at_least,
    COUNT(DISTINCT a.cve_id)        AS cve_count,
    group_concat(DISTINCT a.cve_id) AS cve_ids,
    MAX(a.cvss_score)               AS max_cvss
FROM env_components c
JOIN environment_profiles p  ON p.profile_id = c.profile_id
JOIN component_advisories a  ON a.slug = c.slug AND a.component_type = c.type
GROUP BY p.scan_id, p.target_host, c.type, c.slug;


-- 자동 점검 커버리지. 보고서 개요의 "탐지되지 않음 != 양호" 고지 근거.
CREATE VIEW IF NOT EXISTS v_guide_coverage AS
SELECT
    (SELECT COUNT(*) FROM guide_items)                     AS items_total,
    (SELECT COUNT(DISTINCT item_code) FROM guide_mappings) AS items_covered;


-- ============================================================
-- 8. 초기값
-- ============================================================

INSERT OR IGNORE INTO schema_version (version) VALUES (1);
INSERT OR IGNORE INTO schema_version (version) VALUES (2);

-- settings 기본값은 data/settings_defaults.csv 가 유일한 출처다.
-- 초기 데이터를 SQL 에 두면 CSV 와 값이 갈라지고 재적재 경로가 두 개가 된다.
