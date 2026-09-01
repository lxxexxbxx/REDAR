/* 공통 렌더 유틸.
 *
 * 표시 문자열은 백엔드 Enum(app/domain/enums.py) 라벨과 일치 필수.
 * 여기가 유일한 사본. 값 변경 시 이 파일만 수정
 */

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

/* 표시값은 영문 원값. 보고서와 문자열이 같아야 대조가 됨 (docs/04 §2) */
export const SEVERITY_LABEL = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
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
  value === null || value === undefined || value === "" ? "-" : value;

export function fmtTime(value) {
  if (!value) return "-";
  const date = new Date(String(value).replace(" ", "T"));
  if (Number.isNaN(date.getTime())) return String(value);
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function fmtDuration(seconds) {
  // 외부 임포트 스캔은 실행 시간 부재. 0초로 표기하지 않음
  if (seconds === null || seconds === undefined) return "-";
  if (seconds < 60) return `${seconds}초`;
  const min = Math.floor(seconds / 60);
  return `${min}분 ${seconds % 60}초`;
}

export const severityTag = (severity) =>
  `<span class="sev sev-${esc(severity)}">${esc(SEVERITY_LABEL[severity] || severity)}</span>`;

export const target = (t) =>
  t ? esc(t.host + (t.port ? `:${t.port}` : "") + (t.path || "")) : "-";

/* 스캔 요약용 대상 표기.
 *
 * 포트 범위는 개별 포트로 전개해 실행하므로 targets 에는 수백 건이 들어갈 수 있음.
 * 요약에는 사용자가 입력한 원문을 그대로 보여줌 - 전개 결과를 나열하면 읽을 수 없음
 * 개별 탐지 결과는 실제 포트로 표기해야 조치 대상이 특정됨 (target 헬퍼)
 */
export function scanTargets(scan) {
  const input = scan?.target_input?.length ? scan.target_input : scan?.targets;
  if (!input?.length) return "대상 없음";
  const label = input.join(", ");
  const probe = scan?.target_probe;
  if (probe?.no_response?.length) {
    return `${label} · 응답 ${probe.responded.length}개 / 요청 ${probe.requested}개`;
  }
  const expanded = scan?.targets?.length ?? 0;
  return expanded > input.length ? `${label} · ${expanded}개 포트` : label;
}

/* 대상 응답 현황. 보고서는 응답한 대상만 싣지만 화면은 무응답도 보여준다 -
 * '요청했는데 안 나왔다' 를 사용자가 확인할 수 있어야 범위를 조정할 수 있음 */
export function targetProbe(scan) {
  const probe = scan?.target_probe;
  if (!probe || !probe.checked) return "";

  const dead = probe.no_response || [];
  const alive = probe.responded || [];
  return `<div class="panel">
    <div class="panel-head">
      <h2>요청 ${probe.requested}개 · 응답 ${alive.length}개 · 무응답 ${dead.length}개</h2>
    </div>
    <div class="hintbox">
      <b>응답한 대상 - 실제로 점검한 곳입니다</b>
      <div class="chips">${alive.length
        ? alive.map((t) => `<span class="chip strong">${esc(t)}</span>`).join(" ")
        : "<small>없습니다.</small>"}</div>
    </div>
    ${dead.length ? `<div class="hintbox">
      <b>무응답 - 연결되지 않아 점검하지 않았습니다</b>
      <small>보고서에는 개수만 기록되고 목록은 실리지 않습니다.</small>
      <div class="chips" style="margin-top:6px">${
        dead.slice(0, 40).map((t) => `<span class="chip">${esc(t)}</span>`).join(" ")
      }${dead.length > 40 ? ` <span class="chip">외 ${dead.length - 40}개</span>` : ""}</div>
    </div>` : ""}
  </div>`;
}

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

/* 커버리지 고지. 접기 불가 (절대규칙 10)
 * 문장은 GET /guide/status 가 내려준 것을 그대로 사용. 사본을 두면 보고서와 갈라짐
 */
export function coverageNotice(guide) {
  const notice = guide?.coverage_notice;
  if (!notice) return "";
  return `<div class="coverage">
    ${esc(notice)}
    <div style="margin-top:6px;color:var(--faint)">
      계정 관리·파일 권한·서비스 데몬 설정은 웹 요청으로 볼 수 없는 영역입니다.
    </div>
  </div>`;
}

/* 실행 환경. 결과를 어떤 도구·버전이 만들었는지 (재현성 근거)
 * 다른 기기에서 임포트한 결과와 직접 실행한 결과 구분 필요
 */
export function runEnvironment(scan) {
  const importedFrom = scan?.template_selection?.imported_from;
  const MODE_LABEL = {
    explicit: "직접 지정",
    filter: "조건 필터",
    environment_driven: "환경 기반 자동 선별",
  };
  const rows = [
    ["결과 출처", importedFrom
      ? `외부 임포트 · <span class="mono">${esc(importedFrom)}</span>`
      : "이 PC 에서 직접 실행"],
    ["REDAR 버전", esc(dash(scan?.tool_version))],
    ["nuclei 버전", scan?.nuclei_version ? `v${esc(scan.nuclei_version)}` : "기록 없음"],
    ["템플릿 리비전", esc(dash(scan?.template_revision))],
    ["선별 방식", esc(MODE_LABEL[scan?.template_selection?.mode] ||
      dash(scan?.template_selection?.mode))],
    ["환경 조사", scan?.collect_environment ? "수행" : "미수행"],
  ];
  return `<dl class="kv">${rows.map(([key, value]) =>
    `<dt>${esc(key)}</dt><dd>${value}</dd>`).join("")}</dl>`;
}

/* 진단 대상 환경. 수집기는 M4. 수집 예정 축을 미리 고정해 빈 상태로 보여준다 */
export const TARGET_ENV_FIELDS = [
  ["웹 서버", "제품 · 버전"],
  ["언어 런타임", "제품 · 버전"],
  ["애플리케이션", "제품 · 버전"],
  ["구성요소", "플러그인 · 테마 · 모듈"],
  ["노출 항목", "11종 점검"],
];

export function targetEnvironment(profile) {
  if (!profile) {
    return `<dl class="kv">${TARGET_ENV_FIELDS.map(([key, hint]) =>
      `<dt>${esc(key)}</dt><dd style="color:var(--faint)">미수집 - ${esc(hint)}</dd>`
    ).join("")}</dl>`;
  }
  return `<dl class="kv">
    <dt>웹 서버</dt><dd>${esc(dash(profile.web_server?.product))} ${esc(dash(profile.web_server?.version))}</dd>
    <dt>언어 런타임</dt><dd>${esc(dash(profile.language?.product))} ${esc(dash(profile.language?.version))}</dd>
    <dt>애플리케이션</dt><dd>${esc(dash(profile.application?.product))} ${esc(dash(profile.application?.version))}</dd>
    <dt>구성요소</dt><dd>${profile.components?.length ?? 0}개</dd>
    <dt>노출 항목</dt><dd>${(profile.exposures || []).filter((e) => e.value).length}건 확인</dd>
  </dl>`;
}

export function emptyState({ title, body, cta }) {
  return `<div class="empty">
    <h2>${esc(title)}</h2>
    <p>${body}</p>
    ${cta ? `<div class="cta">${cta}</div>` : ""}
  </div>`;
}

/* 확인 대화.
 *
 * window.confirm 을 쓰지 않는다. Tauri WebView 는 JS 기본 대화상자를 처리하지 않아
 * 창이 뜨지 않은 채 즉시 false 가 반환된다. 사용자에게는 '눌러도 취소됨' 으로 보인다
 * 브라우저 개발 환경에서만 동작하고 배포본에서 조용히 실패하는 구조라 직접 만든다
 */
export function confirmDialog({ title, body, confirmLabel = "진행", danger = false }) {
  document.querySelector(".modal-back")?.remove();

  return new Promise((resolve) => {
    const back = document.createElement("div");
    back.className = "modal-back";
    back.innerHTML = `
      <div class="modal" role="alertdialog" aria-modal="true" aria-label="${esc(title)}">
        <h2>${esc(title)}</h2>
        <p>${body}</p>
        <div class="actions">
          <button class="sm ghost" data-modal="cancel">취소</button>
          <button class="${danger ? "danger" : "primary"}" data-modal="ok">${esc(confirmLabel)}</button>
        </div>
      </div>`;

    const close = (answer) => {
      document.removeEventListener("keydown", onKey);
      back.remove();
      resolve(answer);
    };
    const onKey = (event) => {
      if (event.key === "Escape") close(false);
    };

    back.addEventListener("click", (event) => {
      const action = event.target.closest("[data-modal]")?.dataset.modal;
      if (action) close(action === "ok");
      else if (event.target === back) close(false);   // 바깥 클릭 = 취소
    });
    document.addEventListener("keydown", onKey);

    document.body.appendChild(back);
    back.querySelector('[data-modal="ok"]').focus();
  });
}

/* 한 줄 입력 대화. window.prompt 도 confirm 과 같은 이유로 쓸 수 없다 */
export function promptDialog({ title, body = "", label, value = "", confirmLabel = "확인" }) {
  document.querySelector(".modal-back")?.remove();

  return new Promise((resolve) => {
    const back = document.createElement("div");
    back.className = "modal-back";
    back.innerHTML = `
      <div class="modal" role="dialog" aria-modal="true" aria-label="${esc(title)}">
        <h2>${esc(title)}</h2>
        ${body ? `<p>${body}</p>` : ""}
        <label class="field" style="margin-top:14px">
          <span>${esc(label)}</span>
          <input type="text" data-modal-input value="${esc(value)}">
        </label>
        <div class="actions">
          <button class="sm ghost" data-modal="cancel">취소</button>
          <button class="primary" data-modal="ok">${esc(confirmLabel)}</button>
        </div>
      </div>`;

    const input = back.querySelector("[data-modal-input]");
    const close = (answer) => {
      document.removeEventListener("keydown", onKey);
      back.remove();
      resolve(answer);
    };
    const onKey = (event) => {
      if (event.key === "Escape") close(null);
      if (event.key === "Enter" && document.activeElement === input) {
        close(input.value.trim() || null);
      }
    };

    back.addEventListener("click", (event) => {
      const action = event.target.closest("[data-modal]")?.dataset.modal;
      if (action) close(action === "ok" ? input.value.trim() || null : null);
      else if (event.target === back) close(null);
    });
    document.addEventListener("keydown", onKey);

    document.body.appendChild(back);
    input.focus();
    input.select();
  });
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

/* environment_driven 선별 근거. 보고서 부록의 "N개 중 M개" 와 같은 값을 사용
 * 인벤토리 미탑재(총 0개) 상태를 감추지 않음 - 감추면 수치가 거짓이 된다 */
export function selectionBasis(basis) {
  if (!basis) return "";
  const total = basis.total_available ?? 0;
  const candidates = basis.candidate_templates ?? 0;
  // 환경 조사는 기록용이며 실행 범위를 좁히지 않는다. 문구가 '선별' 로 남으면
  // 실제로 무엇을 돌렸는지 거짓으로 읽힘
  const line = total
    ? `보유 템플릿 <strong>${total.toLocaleString()}개</strong>를 전부 실행했습니다.`
    : "보유 템플릿이 없어 nuclei 기본 저장소로 실행했습니다.";
  const tags = basis.environment_tags || [];
  return `<div class="coverage" style="border-left-color:var(--sev-low)">
    ${line}
    <div style="margin-top:6px;color:var(--faint)">
      환경 조사 결과 구성요소 ${(basis.matched_components || []).length}건 ·
      스택 ${(basis.matched_stack || []).length}건을 확인했습니다${
        tags.length ? ` (태그 ${esc(tags.join(", "))})` : ""}.
      ${candidates ? `이 중 ${candidates}건이 환경에 직접 대응하는 템플릿입니다.` : ""}
      선별 근거로만 기록하며 실행 범위는 줄이지 않습니다.
    </div>
  </div>`;
}
