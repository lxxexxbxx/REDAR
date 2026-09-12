-- scans.selection_mode 에 full_scan 추가. SQLite 는 CHECK 변경 불가라 테이블 재구성
--
-- FK 를 끄는 이유: 옛 테이블 DROP 이 ON DELETE CASCADE 를 일으켜 대상·탐지·환경·보고서
--   행이 전부 사라짐. 끈 상태의 DROP 은 하위 행을 건드리지 않고, 하위 테이블의
--   'REFERENCES scans' 는 이름으로 새 테이블에 다시 연결됨
-- 뷰를 먼저 지우는 이유: RENAME 이 스키마 전체를 재검증해 '없는 테이블' 오류 발생
PRAGMA foreign_keys = OFF;
BEGIN;

DROP VIEW IF EXISTS v_scan_summary;

CREATE TABLE scans_new (
    scan_id             TEXT PRIMARY KEY,
    status              TEXT NOT NULL
        CHECK (status IN ('queued','running','completed','failed','canceled')),
    selection_mode      TEXT NOT NULL
        CHECK (selection_mode IN ('explicit','filter','environment_driven','full_scan')),
    selection_detail    TEXT,
    selection_basis     TEXT,
    target_input        TEXT,
    collect_environment INTEGER NOT NULL DEFAULT 1,
    opt_threads         INTEGER NOT NULL DEFAULT 20,
    opt_timeout_sec     INTEGER NOT NULL DEFAULT 10,
    opt_retries         INTEGER NOT NULL DEFAULT 1,
    opt_rate_limit      INTEGER,
    templates_total     INTEGER,
    templates_done      INTEGER,
    error_code          TEXT,
    error_message       TEXT,
    tool_version        TEXT,
    nuclei_version      TEXT,
    template_revision   TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    started_at          TEXT,
    finished_at         TEXT
);

INSERT INTO scans_new (
    scan_id, status, selection_mode, selection_detail, selection_basis, target_input,
    collect_environment, opt_threads, opt_timeout_sec, opt_retries, opt_rate_limit,
    templates_total, templates_done, error_code, error_message,
    tool_version, nuclei_version, template_revision, created_at, started_at, finished_at
)
SELECT
    scan_id, status, selection_mode, selection_detail, selection_basis, target_input,
    collect_environment, opt_threads, opt_timeout_sec, opt_retries, opt_rate_limit,
    templates_total, templates_done, error_code, error_message,
    tool_version, nuclei_version, template_revision, created_at, started_at, finished_at
FROM scans;

DROP TABLE scans;
ALTER TABLE scans_new RENAME TO scans;

CREATE INDEX IF NOT EXISTS idx_scans_status  ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);

CREATE VIEW v_scan_summary AS
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

COMMIT;
PRAGMA foreign_keys = ON;
