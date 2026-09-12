-- 템플릿 제품 표지. 환경 기반 제외 판단 근거 (framework > WordPress 태그 > product)
-- NULL = 표지 없음 = 범용으로 보고 항상 실행. 재색인 전 기존 행도 안전 방향
ALTER TABLE templates ADD COLUMN platform TEXT;
