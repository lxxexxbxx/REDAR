-- 사용자가 입력한 대상 원문. 포트 범위('localhost:33-4444')는 개별 대상으로
-- 전개해 실행하므로 scan_targets 에는 전개 결과만 남는다.
-- 스캔 요약·보고서 개요에 '무엇을 스캔하려 했는지' 를 그대로 보여주기 위한 JSON 배열
--
-- 번호가 003 인 이유: schema.sql 말미가 version 1·2 를 이미 적용됨으로 기록한다.
-- 001·002 로 두면 _apply_migrations 가 '적용 완료' 로 보고 건너뛴다.
ALTER TABLE scans ADD COLUMN target_input TEXT;
