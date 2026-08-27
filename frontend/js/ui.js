/* 공통 렌더 유틸.
 *
 * 표시 문자열은 백엔드 Enum(app/domain/enums.py) 라벨과 일치 필수.
 * 여기가 유일한 사본. 값 변경 시 이 파일만 수정
 */

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL = {
  critical: "치명적",
  high: "높음",
  medium: "중간",
  low: "낮음",
  info: "정보",
};

export const VULN_TYPE_ORDER = [
  "rce", "sqli", "xss", "csrf", "ssrf", "auth_bypass", "deserialization",
  "path_traversal", "file_upload", "open_redirect", "info_disclosure",
  "access_control", "misconfig", "other",
];

export const VULN_TYPE_LABEL = {
  rce: "원격 코드 실행",
  sqli: "SQL 인젝션",
  xss: "크로스사이트 스크립트",
  csrf: "크로스사이트 요청 위조",
  ssrf: "서버사이드 요청 위조",
  auth_bypass: "인증 우회",
  deserialization: "역직렬화",
  path_traversal: "경로 조작",
  file_upload: "악성 파일 업로드",
  open_redirect: "오픈 리다이렉트",
  info_disclosure: "정보 노출",
  access_control: "접근 통제",
  misconfig: "설정 오류",
  other: "기타",
};

export const SCAN_STATUS_LABEL = {
  queued: "대기",
  running: "실행 중",
  completed: "완료",
  failed: "실패",
  canceled: "취소",
};

export const FINDING_STATUS_LABEL = {
  open: "미조치",
  false_positive: "오탐",
  accepted_risk: "위험 수용",
};

export const esc = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));

export const dash = (value) =>
  value === null || value === undefined || value === "" ? "—" : value;

export function fmtTime(value) {
  if (!value) return "—";
  const date = new Date(String(value).replace(" ", "T"));
  if (Number.isNaN(date.getTime())) return String(value);
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function fmtDuration(seconds) {
  // 외부 임포트 스캔은 실행 시간 부재. 0초로 표기하지 않음
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${seconds}초`;
  const min = Math.floor(seconds / 60);
  return `${min}분 ${seconds % 60}초`;
}

export const severityTag = (severity) =>
  `<span class="sev sev-${esc(severity)}">${esc(SEVERITY_LABEL[severity] || severity)}</span>`;

export const target = (t) =>
  t ? esc(t.host + (t.port ? `:${t.port}` : "") + (t.path || "")) : "—";

/* 시그니처: 고정 축 미터.
 * 심각도 5칸 항상 전부 렌더링. 0인 줄도 유지.
 * 슬롯 12칸 중 채워진 칸이 비율. 빈 슬롯은 테두리로 남김
 */
export function severityAxis(counts) {
  const values = SEVERITY_ORDER.map((key) => counts?.[key] ?? 0);
  const peak = Math.max(1, ...values);
  const SLOTS = 12;

  return `<div class="axis">${SEVERITY_ORDER.map((key, index) => {
    const count = values[index];
    const filled = count === 0 ? 0 : Math.max(1, Math.round((count / peak) * SLOTS));
    const slots = Array.from({ length: SLOTS }, (_, i) =>
      `<i class="slot${i < filled ? " on" : ""}"></i>`).join("");
    return `<div class="axis-row axis-${key}${count ? " filled" : ""}">
      <span class="label">${esc(SEVERITY_LABEL[key])}</span>
      <span class="count">${count}</span>
      <span class="slots" role="img" aria-label="${esc(SEVERITY_LABEL[key])} ${count}건">${slots}</span>
    </div>`;
  }).join("")}</div>`;
}

/* 유형 축 14칸. 미탐지 유형도 0으로 유지 (절대규칙 4) */
export function vulnTypeAxis(counts) {
  return `<div class="typeaxis">${VULN_TYPE_ORDER.map((key) => {
    const count = counts?.[key] ?? 0;
    return `<div class="typecell${count ? " filled" : ""}">
      <span class="n">${count}</span>
      <span class="k">${esc(VULN_TYPE_LABEL[key])}</span>
    </div>`;
  }).join("")}</div>`;
}

/* 커버리지 고지. 접기 불가 (절대규칙 10) */
export function coverageNotice(guide) {
  const covered = guide?.items_covered ?? 0;
  const total = guide?.item_count ?? 0;
  const scope = guide?.imported
    ? `가이드 전체 <span class="mono">${total}</span>개 점검항목 중 <span class="mono">${covered}</span>개`
    : `자동 점검 가능 항목 <span class="mono">${covered}</span>개 (가이드 본문 미탑재)`;
  return `<div class="coverage">
    본 점검은 원격 스캔 기반이며, ${scope}만 자동 점검 대상입니다.
    <strong>탐지되지 않음이 양호를 의미하지 않습니다.</strong>
    계정 관리·파일 권한·서비스 데몬 설정은 원격 스캐너로 점검할 수 없습니다.
  </div>`;
}

export function emptyState({ eyebrow, title, body, cta }) {
  return `<div class="empty">
    <div class="eyebrow">${esc(eyebrow)}</div>
    <h2>${esc(title)}</h2>
    <p>${body}</p>
    ${cta ? `<div class="cta">${cta}</div>` : ""}
  </div>`;
}

let toastTimer = null;
export function toast(message, kind = "ok") {
  document.querySelector(".toast")?.remove();
  const node = document.createElement("div");
  node.className = `toast${kind === "err" ? " err" : ""}`;
  node.setAttribute("role", "status");
  node.textContent = message;
  document.body.appendChild(node);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.remove(), 3600);
}
