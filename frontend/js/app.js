/* 화면 라우팅 + 렌더. 해시 라우팅이라 빌드 도구 불필요 */

import { api, ApiError, subscribeScan } from "./api.js";
import {
  FINDING_STATUS_LABEL, SCAN_STATUS_LABEL, SEVERITY_ORDER, SEVERITY_LABEL,
  VULN_TYPE_LABEL, VULN_TYPE_ORDER,
  coverageNotice, dash, emptyState, esc, fmtDuration, fmtTime,
  runEnvironment, severityAxis, severityTag, target, targetEnvironment,
  toast, vulnTypeAxis,
} from "./ui.js";

const NAV = [
  { path: "dashboard", label: "대시보드" },
  { path: "scan", label: "스캔 실행" },
  { path: "results", label: "탐지 결과" },
  { path: "templates", label: "템플릿", tag: "M5" },
  { path: "report", label: "보고서", tag: "M7" },
  { path: "settings", label: "설정" },
];

const state = {
  health: null,
  guide: null,
  settings: null,
  scanId: null,
  unsubscribe: null,
};

const view = () => document.getElementById("view");

function route() {
  const raw = location.hash.replace(/^#\/?/, "") || "dashboard";
  const [path, search] = raw.split("?");
  return { path, params: new URLSearchParams(search || "") };
}

const go = (path) => { location.hash = `#/${path}`; };

/* ------------------------------------------------------------ 상태 띠 */

function renderStateStrip() {
  const { health, guide, settings } = state;
  const allowCount = settings?.target_allowlist?.length ?? 0;
  const external = (settings?.external_endpoints || []).filter((e) => e.enabled);

  const cells = [
    {
      label: "백엔드",
      value: health ? "연결됨" : "연결 안 됨",
      dot: health ? "on" : "alert",
    },
    {
      label: "nuclei",
      value: health?.nuclei ? `v${health.nuclei}` : "미설치",
      dot: health?.nuclei ? "on" : "warn",
    },
    {
      label: "가이드 DB",
      value: guide?.imported ? `${guide.item_count}개 항목` : "미탑재",
      dot: guide?.imported ? "on" : "off",
    },
    {
      label: "스캔 대상",
      // 0이면 모든 스캔 거부. 눈에 띄어야 함
      value: allowCount ? `${allowCount}건 허용` : "허용 대상 없음",
      dot: allowCount ? "on" : "alert",
    },
    {
      label: "외부 통신",
      value: settings?.offline_mode
        ? "오프라인"
        : external.length ? `${external.length}곳 허용` : "전부 차단",
      dot: settings?.offline_mode ? "on" : external.length ? "warn" : "on",
    },
  ];

  document.getElementById("statestrip").innerHTML = cells.map((cell) => `
    <div class="state">
      <i class="dot ${cell.dot}"></i>
      <em>${esc(cell.label)}</em>
      <span class="mono">${esc(cell.value)}</span>
    </div>`).join("");
}

function renderNav(current) {
  document.getElementById("nav").innerHTML = NAV.map((item) => `
    <a href="#/${item.path}"${item.path === current ? ' aria-current="page"' : ""}>
      <span>${esc(item.label)}</span>
      ${item.tag ? `<span class="tag">${esc(item.tag)}</span>` : ""}
    </a>`).join("");
}

/* ------------------------------------------------------------ 대시보드 */

async function viewDashboard() {
  const { items } = await api.listScans({ size: 8 });
  const latest = items[0] || null;

  let aggregations = null;
  let detail = null;
  if (latest) {
    [aggregations, detail] = await Promise.all([
      api.listFindings(latest.scan_id, { size: 1 }).then((r) => r.aggregations),
      api.getScan(latest.scan_id),
    ]);
  }

  view().innerHTML = `
    <div class="view-head">
      <div class="eyebrow">진단 현황</div>
      <h1>대시보드</h1>
      <p>가장 최근 스캔의 심각도·유형 분포입니다. 각 축은 탐지 건수와 무관하게
         항상 전체 항목을 표시합니다.</p>
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head">
          <div class="eyebrow">심각도 · 5단계 고정</div>
          <h2>${latest ? "최근 스캔 분포" : "탐지 결과 없음"}</h2>
        </div>
        ${severityAxis(aggregations?.by_severity)}
      </div>

      <div class="panel">
        <div class="panel-head">
          <div class="eyebrow">스캔 정보</div>
          <h2>${latest ? esc(latest.targets.join(", ") || "대상 없음") : "스캔 기록 없음"}</h2>
        </div>
        ${latest ? `
          <dl class="kv">
            <dt>상태</dt><dd>${esc(SCAN_STATUS_LABEL[latest.status] || latest.status)}</dd>
            <dt>시작</dt><dd>${esc(fmtTime(latest.started_at || latest.created_at))}</dd>
            <dt>소요</dt><dd>${esc(fmtDuration(latest.duration_sec))}</dd>
            <dt>탐지</dt><dd>${latest.finding_counts
              ? Object.values(latest.finding_counts).reduce((a, b) => a + b, 0) : 0}건</dd>
            <dt>스캔 ID</dt><dd>${esc(latest.scan_id)}</dd>
          </dl>
          <div class="row" style="margin-top:16px">
            <button class="primary" data-open="${esc(latest.scan_id)}">결과 보기</button>
          </div>` : `
          <p style="color:var(--muted);margin:0">
            아직 실행한 스캔이 없습니다. 스캔 실행 화면에서 대상을 지정하세요.
          </p>
          <div class="row" style="margin-top:16px">
            <button class="primary" data-go="scan">스캔 실행</button>
          </div>`}
      </div>
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head">
          <div class="eyebrow">재현성</div>
          <h2>실행 환경</h2>
        </div>
        ${detail ? runEnvironment(detail) : `
          <p style="color:var(--muted);margin:0">스캔 기록이 없습니다.</p>`}
      </div>
      <div class="panel">
        <div class="panel-head">
          <div class="eyebrow">진단 대상</div>
          <h2>대상 환경</h2>
        </div>
        ${targetEnvironment(null)}
        <p style="color:var(--faint);font-size:12px;margin:12px 0 0">
          제품·버전·구성요소 식별은 환경 수집기가 담당합니다. M4 에서 구현됩니다.
        </p>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">취약점 유형 · 14종 고정</div>
        <h2>유형별 분포</h2>
      </div>
      ${vulnTypeAxis(aggregations?.by_vuln_type)}
      ${coverageNotice(state.guide)}
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">이력</div>
        <h2>최근 스캔</h2>
      </div>
      ${items.length ? scanTable(items) : emptyState({
        eyebrow: "기록 없음",
        title: "스캔 이력이 비어 있습니다",
        body: "스캔을 실행하면 이 목록에 남습니다.",
      })}
    </div>`;
}

function scanTable(items) {
  return `<table>
    <thead><tr>
      <th>대상</th><th>상태</th><th class="num">치명적</th><th class="num">높음</th>
      <th class="num">중간</th><th class="num">낮음</th><th class="num">정보</th>
      <th>시작</th><th>소요</th><th></th>
    </tr></thead>
    <tbody>${items.map((scan) => `
      <tr class="clickable" data-open="${esc(scan.scan_id)}">
        <td class="mono">${esc(scan.targets.join(", ") || "—")}</td>
        <td class="nowrap">${esc(SCAN_STATUS_LABEL[scan.status] || scan.status)}</td>
        ${SEVERITY_ORDER.map((key) => {
          const count = scan.finding_counts?.[key] ?? 0;
          return `<td class="num"${count ? ` style="color:var(--sev-${key})"` : ""}>${count}</td>`;
        }).join("")}
        <td class="mono nowrap">${esc(fmtTime(scan.started_at || scan.created_at))}</td>
        <td class="mono nowrap">${esc(fmtDuration(scan.duration_sec))}</td>
        <td><button class="sm danger" data-delete="${esc(scan.scan_id)}">삭제</button></td>
      </tr>`).join("")}
    </tbody></table>`;
}

/* ---------------------------------------------------------- 스캔 실행 */

function viewScan() {
  const allowlist = state.settings?.target_allowlist || [];
  const blocked = allowlist.length === 0;

  view().innerHTML = `
    <div class="view-head">
      <div class="eyebrow">스캔 설정</div>
      <h1>스캔 실행</h1>
      <p>대상은 설정에 등록된 허용 목록 안에서만 지정할 수 있습니다.</p>
    </div>

    ${blocked ? `<div class="coverage" style="border-left-color:var(--brand)">
      <strong>허용된 스캔 대상이 없습니다.</strong>
      기본값은 전부 차단이며, 설정에서 대상을 등록해야 스캔을 시작할 수 있습니다.
      <div class="cta" style="margin-top:10px">
        <button class="sm" data-go="settings">설정으로 이동</button>
      </div>
    </div>` : ""}

    <div class="grid-2" style="margin-top:16px">
      <div class="panel">
        <div class="panel-head">
          <div class="eyebrow">1 · 대상</div>
          <h2>스캔 대상</h2>
        </div>
        <label class="field">
          <span>대상 목록 (줄바꿈 구분)</span>
          <textarea id="targets" placeholder="http://192.168.1.50&#10;http://target.local:8080"></textarea>
          <small>허용 목록: ${allowlist.length
            ? allowlist.map((h) => `<span class="chip">${esc(h)}</span>`).join(" ")
            : "없음"}</small>
        </label>
        <div class="row">
          <input type="file" id="target-file" accept=".txt,.csv" class="sr-only">
          <button class="sm ghost" id="pick-file">파일에서 불러오기</button>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <div class="eyebrow">2 · 템플릿 선별</div>
          <h2>실행할 진단 항목</h2>
        </div>
        <label class="field">
          <span>선별 방식</span>
          <select id="mode">
            <option value="filter">조건 필터 — 태그·심각도로 선별</option>
            <option value="explicit">직접 지정 — 템플릿 ID 목록</option>
            <option value="environment_driven" disabled>환경 기반 자동 선별 (M4)</option>
          </select>
        </label>
        <div id="mode-fields"></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">3 · 실행 옵션</div>
        <h2>동작 설정</h2>
      </div>
      <div class="row" style="align-items:flex-start;gap:20px">
        <label class="field" style="flex:1;min-width:120px">
          <span>동시 실행</span>
          <input type="number" id="threads" value="${state.settings?.scan_defaults?.threads ?? 20}" min="1" max="200">
        </label>
        <label class="field" style="flex:1;min-width:120px">
          <span>타임아웃 (초)</span>
          <input type="number" id="timeout" value="${state.settings?.scan_defaults?.timeout_sec ?? 10}" min="1" max="300">
        </label>
        <label class="field" style="flex:1;min-width:120px">
          <span>재시도</span>
          <input type="number" id="retries" value="${state.settings?.scan_defaults?.retries ?? 1}" min="0" max="10">
        </label>
        <label class="field" style="flex:1;min-width:120px">
          <span>초당 요청 상한</span>
          <input type="number" id="ratelimit" placeholder="제한 없음" min="1">
        </label>
      </div>
      <div class="toggle">
        <input type="checkbox" id="collect-env">
        <span class="t-body">
          <b>환경 조사 수행</b>
          <small>제품·버전·플러그인을 먼저 식별합니다. 수집기는 M4에서 구현됩니다.</small>
        </span>
      </div>
      <div class="row" style="margin-top:6px">
        <button class="primary" id="start"${blocked ? " disabled" : ""}>스캔 시작</button>
        <span id="start-note" style="color:var(--faint);font-size:12px"></span>
      </div>
    </div>

    <div class="panel" id="live" hidden>
      <div class="panel-head spread">
        <div>
          <div class="eyebrow">진행 중</div>
          <h2 id="live-title">스캔 실행 중</h2>
          <div class="mono" id="live-id" style="font-size:11.5px;color:var(--faint);margin-top:3px"></div>
        </div>
        <button class="sm danger" id="cancel">중단</button>
      </div>
      <div class="progress sweeping" id="progress"><div class="bar"></div></div>
      <div class="row mono" style="margin-top:10px;font-size:12px;color:var(--muted)">
        <span id="live-phase">준비</span>
        <span id="live-count">탐지 0건</span>
      </div>
      <div class="livefeed" style="margin-top:14px">
        <table>
          <thead><tr><th>심각도</th><th>탐지 항목</th><th>유형</th><th>대상</th></tr></thead>
          <tbody id="live-rows"></tbody>
        </table>
      </div>
    </div>`;

  renderModeFields();
  document.getElementById("mode").addEventListener("change", renderModeFields);
}

function renderModeFields() {
  const mode = document.getElementById("mode").value;
  const host = document.getElementById("mode-fields");
  if (mode === "explicit") {
    host.innerHTML = `
      <label class="field">
        <span>템플릿 ID (쉼표 구분)</span>
        <input type="text" id="template-ids" placeholder="CVE-2026-33017, langflow-detect">
        <small>내려받거나 직접 작성한 템플릿의 ID를 지정합니다.</small>
      </label>`;
  } else {
    host.innerHTML = `
      <label class="field">
        <span>태그 (쉼표 구분)</span>
        <input type="text" id="tags" placeholder="cve, wordpress">
      </label>
      <label class="field">
        <span>심각도</span>
        <select id="severities" multiple size="5">
          ${SEVERITY_ORDER.map((key) =>
            `<option value="${key}">${esc(SEVERITY_LABEL[key])}</option>`).join("")}
        </select>
        <small>선택하지 않으면 전체 심각도를 대상으로 합니다.</small>
      </label>`;
  }
}

const splitList = (value) =>
  (value || "").split(/[\n,]/).map((s) => s.trim()).filter(Boolean);

async function startScan() {
  const targets = splitList(document.getElementById("targets").value);
  if (!targets.length) {
    toast("스캔 대상을 입력하세요.", "err");
    return;
  }
  const mode = document.getElementById("mode").value;
  const selection = { mode };
  if (mode === "explicit") {
    selection.template_ids = splitList(document.getElementById("template-ids")?.value);
  } else {
    selection.tags = splitList(document.getElementById("tags")?.value);
    selection.severity = Array.from(
      document.getElementById("severities")?.selectedOptions || []
    ).map((option) => option.value);
  }

  const rateLimit = Number(document.getElementById("ratelimit").value);
  const payload = {
    targets,
    template_selection: selection,
    collect_environment: document.getElementById("collect-env").checked,
    options: {
      threads: Number(document.getElementById("threads").value) || 20,
      timeout_sec: Number(document.getElementById("timeout").value) || 10,
      retries: Number(document.getElementById("retries").value) || 0,
      ...(rateLimit ? { rate_limit: rateLimit } : {}),
    },
  };

  const button = document.getElementById("start");
  button.disabled = true;
  try {
    const { scan_id } = await api.createScan(payload);
    state.scanId = scan_id;
    attachLiveFeed(scan_id);
  } catch (error) {
    button.disabled = false;
    showApiError(error);
  }
}

function attachLiveFeed(scanId) {
  const live = document.getElementById("live");
  live.hidden = false;
  document.getElementById("live-rows").innerHTML = "";
  document.getElementById("live-title").textContent = "스캔 실행 중";
  document.getElementById("live-id").textContent = scanId;

  const bar = document.querySelector("#progress .bar");
  const progress = document.getElementById("progress");
  const phase = document.getElementById("live-phase");
  const countLabel = document.getElementById("live-count");
  let found = 0;

  const PHASE_LABEL = {
    collecting_environment: "환경 조사",
    selecting_templates: "템플릿 선별",
    scanning: "스캔 진행",
    finalizing: "마무리",
  };

  state.unsubscribe?.();
  state.unsubscribe = subscribeScan(scanId, {
    progress(event) {
      if (event.percent !== null && event.percent !== undefined) {
        bar.style.width = `${event.percent}%`;
      }
      phase.textContent = PHASE_LABEL[event.phase] || event.phase || "진행";
      if (event.templates_total) {
        phase.textContent +=
          ` · ${event.templates_done ?? 0} / ${event.templates_total}`;
      }
    },
    finding(event) {
      found += 1;
      countLabel.textContent = `탐지 ${found}건`;
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${severityTag(event.severity)}</td>
        <td>${esc(event.name)}</td>
        <td>${esc(VULN_TYPE_LABEL[event.vuln_type] || event.vuln_type || "—")}</td>
        <td class="mono">${target(event.target)}</td>`;
      document.getElementById("live-rows").prepend(row);
    },
    done(event) {
      progress.classList.remove("sweeping");
      bar.style.width = "100%";
      phase.textContent = SCAN_STATUS_LABEL[event.status] || event.status;
      document.getElementById("start").disabled = false;
      document.getElementById("cancel").disabled = true;
      if (event.error) {
        toast(`${event.error.code}: ${event.error.message}`, "err");
      } else if (event.status === "completed") {
        toast("스캔 완료");
        document.getElementById("start-note").innerHTML =
          `<button class="sm" data-open="${esc(scanId)}">결과 보기</button>`;
      }
    },
  });
}

/* ---------------------------------------------------------- 탐지 결과 */

const resultFilters = { severity: "", vuln_type: "", status: "", sort: "severity" };

async function viewResults(params) {
  const scanId = params.get("scan") || state.scanId;
  if (!scanId) {
    const { items } = await api.listScans({ size: 20 });
    view().innerHTML = `
      <div class="view-head">
        <div class="eyebrow">결과 조회</div>
        <h1>탐지 결과</h1>
        <p>스캔을 선택하세요.</p>
      </div>
      <div class="panel">
        ${items.length ? scanTable(items) : emptyState({
          eyebrow: "기록 없음",
          title: "조회할 스캔이 없습니다",
          body: "스캔을 먼저 실행하세요.",
          cta: '<button class="primary" data-go="scan">스캔 실행</button>',
        })}
      </div>`;
    return;
  }

  state.scanId = scanId;
  const scan = await api.getScan(scanId);
  const data = await api.listFindings(scanId, {
    severity: resultFilters.severity,
    vuln_type: resultFilters.vuln_type,
    status: resultFilters.status,
    sort: resultFilters.sort,
    size: 200,
  });

  view().innerHTML = `
    <div class="view-head spread">
      <div>
        <div class="eyebrow">결과 조회</div>
        <h1>${esc(scan.targets.join(", ") || "대상 없음")}</h1>
        <p class="mono" style="font-size:12.5px;color:var(--muted)">
          ${esc(scanId)} · ${esc(SCAN_STATUS_LABEL[scan.status] || scan.status)}
          · ${esc(fmtTime(scan.started_at || scan.created_at))}${
            scan.duration_sec === null || scan.duration_sec === undefined
              ? "" : ` · ${esc(fmtDuration(scan.duration_sec))}`}
        </p>
      </div>
      <button class="sm" data-go="results-list">다른 스캔 선택</button>
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head">
          <div class="eyebrow">심각도 · 5단계 고정 · 오탐 제외</div>
          <h2>분포</h2>
        </div>
        ${severityAxis(data.aggregations.by_severity)}
      </div>
      <div class="panel">
        <div class="panel-head">
          <div class="eyebrow">대상별</div>
          <h2>호스트 분포</h2>
        </div>
        ${Object.keys(data.aggregations.by_host).length ? `<table>
          <thead><tr><th>호스트</th><th class="num">탐지</th></tr></thead>
          <tbody>${Object.entries(data.aggregations.by_host).map(([host, count]) =>
            `<tr><td class="mono">${esc(host)}</td><td class="num">${count}</td></tr>`
          ).join("")}</tbody></table>`
          : '<p style="color:var(--muted);margin:0">해당 없음</p>'}
      </div>
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head">
          <div class="eyebrow">재현성</div>
          <h2>실행 환경</h2>
        </div>
        ${runEnvironment(scan)}
      </div>
      <div class="panel">
        <div class="panel-head">
          <div class="eyebrow">진단 대상</div>
          <h2>대상 환경</h2>
        </div>
        ${targetEnvironment(null)}
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">유형 · 14종 고정</div>
        <h2>유형별 분포</h2>
      </div>
      ${vulnTypeAxis(data.aggregations.by_vuln_type)}
      ${coverageNotice(state.guide)}
    </div>

    <div class="panel">
      <div class="panel-head spread">
        <div>
          <div class="eyebrow">탐지 목록</div>
          <h2>${data.total}건</h2>
        </div>
      </div>
      <div class="filters">
        <select data-filter="severity">
          <option value="">전체 심각도</option>
          ${SEVERITY_ORDER.map((key) => `<option value="${key}"${
            resultFilters.severity === key ? " selected" : ""
          }>${esc(SEVERITY_LABEL[key])}</option>`).join("")}
        </select>
        <select data-filter="vuln_type">
          <option value="">전체 유형</option>
          ${VULN_TYPE_ORDER.map((key) => `<option value="${key}"${
            resultFilters.vuln_type === key ? " selected" : ""
          }>${esc(VULN_TYPE_LABEL[key])}</option>`).join("")}
        </select>
        <select data-filter="status">
          <option value="">전체 상태</option>
          ${Object.entries(FINDING_STATUS_LABEL).map(([key, label]) =>
            `<option value="${key}"${resultFilters.status === key ? " selected" : ""}>${esc(label)}</option>`
          ).join("")}
        </select>
        <select data-filter="sort">
          <option value="severity"${resultFilters.sort === "severity" ? " selected" : ""}>심각도순</option>
          <option value="detected_at"${resultFilters.sort === "detected_at" ? " selected" : ""}>탐지시각순</option>
          <option value="host"${resultFilters.sort === "host" ? " selected" : ""}>호스트순</option>
          <option value="name"${resultFilters.sort === "name" ? " selected" : ""}>이름순</option>
        </select>
      </div>
      ${data.items.length ? findingTable(data.items) : emptyState({
        eyebrow: "해당 없음",
        title: "조건에 맞는 탐지 결과가 없습니다",
        body: "필터를 해제하거나 다른 스캔을 선택하세요. 탐지 0건이 곧 안전을 의미하지는 않습니다.",
      })}
    </div>`;
}

function findingTable(items) {
  return `<table>
    <thead><tr>
      <th>심각도</th><th>탐지 항목</th><th>유형</th><th>대상</th>
      <th>CVE</th><th class="num">CVSS</th><th>상태</th>
    </tr></thead>
    <tbody>${items.map((f) => `
      <tr class="clickable${f.status === "false_positive" ? " fp" : ""}"
          data-finding="${esc(f.finding_id)}">
        <td>${severityTag(f.severity)}</td>
        <td>
          ${esc(f.name)}
          <div class="mono" style="color:var(--faint);font-size:11px">
            ${esc(f.template_id)}${f.matcher_name ? `:${esc(f.matcher_name)}` : ""}
          </div>
        </td>
        <td>${esc(VULN_TYPE_LABEL[f.vuln_type] || f.vuln_type)}</td>
        <td class="mono">${target(f.target)}</td>
        <td class="mono">${f.cve_ids.length ? esc(f.cve_ids.join(", ")) : "—"}</td>
        <td class="num">${dash(f.cvss_score)}</td>
        <td class="nowrap">${esc(FINDING_STATUS_LABEL[f.status] || f.status)}</td>
      </tr>`).join("")}
    </tbody></table>`;
}

async function openFinding(findingId) {
  const f = await api.getFinding(findingId);
  const drawer = document.createElement("aside");
  drawer.className = "drawer";
  drawer.setAttribute("role", "dialog");
  drawer.setAttribute("aria-label", "탐지 상세");
  drawer.innerHTML = `
    <div class="drawer-head">
      <div>
        ${severityTag(f.severity)}
        <h2 style="margin-top:8px">${esc(f.name)}</h2>
        <div class="mono" style="color:var(--faint);font-size:11.5px;margin-top:4px">
          ${esc(f.template_id)}${f.matcher_name ? `:${esc(f.matcher_name)}` : ""}
        </div>
      </div>
      <button class="sm ghost" data-close-drawer>닫기</button>
    </div>
    <div class="drawer-body">
      <section>
        <h3>분류</h3>
        <dl class="kv">
          <dt>유형</dt><dd>${esc(VULN_TYPE_LABEL[f.vuln_type] || f.vuln_type)}</dd>
          <dt>가이드 등급</dt><dd>${esc(f.severity_guide)}</dd>
          <dt>CVE</dt><dd>${f.cve_ids.length ? esc(f.cve_ids.join(", ")) : "해당 없음"}</dd>
          <dt>CWE</dt><dd>${f.cwe_ids.length ? esc(f.cwe_ids.join(", ")) : "해당 없음"}</dd>
          <dt>CVSS</dt><dd>${dash(f.cvss_score)} ${f.cvss_vector ? esc(f.cvss_vector) : ""}</dd>
          <dt>대상</dt><dd>${target(f.target)}</dd>
          <dt>탐지 시각</dt><dd>${esc(fmtTime(f.detected_at))}</dd>
          <dt>fingerprint</dt><dd>${esc(f.fingerprint.slice(0, 32))}…</dd>
        </dl>
      </section>

      <section>
        <h3>가이드 점검항목</h3>
        ${f.guide_items.length
          ? f.guide_items.map((item) => `<div class="chip strong">${esc(item.item_code)}</div>`).join(" ")
          : `<p style="color:var(--muted);margin:0;font-size:13px">
               가이드 본문이 탑재되지 않아 조치 문구를 표시할 수 없습니다.
               매핑은 M6에서 연결됩니다.
             </p>`}
      </section>

      ${f.description ? `<section>
        <h3>설명</h3>
        <p style="margin:0;color:var(--muted)">${esc(f.description)}</p>
      </section>` : ""}

      ${f.evidence.request ? `<section>
        <h3>요청</h3>
        <pre class="evidence">${esc(f.evidence.request)}</pre>
      </section>` : ""}

      ${f.evidence.response ? `<section>
        <h3>응답</h3>
        <pre class="evidence">${esc(f.evidence.response)}</pre>
      </section>` : ""}

      ${f.evidence.extracted_values.length ? `<section>
        <h3>추출값</h3>
        <pre class="evidence">${esc(f.evidence.extracted_values.join("\n"))}</pre>
      </section>` : ""}

      ${f.evidence.curl_command ? `<section>
        <h3>재현 명령 — 사용자가 직접 실행</h3>
        <pre class="evidence">${esc(f.evidence.curl_command)}</pre>
        <div class="row" style="margin-top:8px">
          <button class="sm" data-copy>명령 복사</button>
        </div>
      </section>` : ""}

      <section>
        <h3>판정</h3>
        <p style="color:var(--faint);font-size:12.5px;margin:0 0 10px">
          오탐으로 표시하면 집계에서 제외되고 보고서 부록에 사유가 기록됩니다.
        </p>
        <label class="field">
          <span>사유</span>
          <input type="text" id="fp-note" value="${esc(f.status_note || "")}"
                 placeholder="예: 해당 엔드포인트는 인증 미들웨어로 보호됨">
        </label>
        <div class="row">
          <button class="sm" data-status="open"${f.status === "open" ? " disabled" : ""}>미조치</button>
          <button class="sm" data-status="false_positive"${f.status === "false_positive" ? " disabled" : ""}>오탐</button>
          <button class="sm" data-status="accepted_risk"${f.status === "accepted_risk" ? " disabled" : ""}>위험 수용</button>
        </div>
      </section>
    </div>`;

  document.body.appendChild(drawer);
  drawer.querySelector("[data-close-drawer]").focus();

  drawer.addEventListener("click", async (event) => {
    const copy = event.target.closest("[data-copy]");
    if (copy) {
      await navigator.clipboard?.writeText(f.evidence.curl_command);
      toast("명령을 복사했습니다");
      return;
    }
    const status = event.target.closest("[data-status]")?.dataset.status;
    if (status) {
      try {
        await api.patchFinding(f.finding_id, {
          status,
          note: drawer.querySelector("#fp-note").value || null,
        });
        toast(`상태를 '${FINDING_STATUS_LABEL[status]}'로 변경했습니다`);
        drawer.remove();
        render();
      } catch (error) {
        showApiError(error);
      }
      return;
    }
    if (event.target.closest("[data-close-drawer]")) drawer.remove();
  });
}

/* ------------------------------------------------------------ 설정 */

function viewSettings() {
  const s = state.settings || {};
  view().innerHTML = `
    <div class="view-head">
      <div class="eyebrow">환경 설정</div>
      <h1>설정</h1>
      <p>스캔 대상과 외부 통신을 통제합니다. 기본값은 전부 차단입니다.</p>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">필수</div>
        <h2>스캔 허용 대상</h2>
      </div>
      <label class="field">
        <span>호스트 또는 CIDR (줄바꿈 구분)</span>
        <textarea id="allowlist">${esc((s.target_allowlist || []).join("\n"))}</textarea>
        <small>
          여기에 없는 대상은 400으로 거부됩니다. 호스트명은 정확히 일치해야 하며
          DNS 로 해석하지 않습니다. IP 범위를 허용하려면 <span class="mono">192.168.1.0/24</span>
          처럼 CIDR 로 등록하세요.
        </small>
      </label>
      <button class="primary" data-save="allowlist">허용 대상 저장</button>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">외부 통신</div>
        <h2>네트워크 통제</h2>
      </div>
      <div class="toggle">
        <input type="checkbox" id="offline" ${s.offline_mode ? "checked" : ""}>
        <span class="t-body">
          <b>오프라인 모드</b>
          <small>켜면 아래 세 지점이 개별 설정과 무관하게 전부 차단됩니다.</small>
        </span>
      </div>
      <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--line-soft)">
        ${(s.external_endpoints || []).map((endpoint) => `
          <div class="toggle">
            <input type="checkbox" data-endpoint="${esc(endpoint.key)}"
                   ${endpoint.configured ? "checked" : ""}
                   ${s.offline_mode ? "disabled" : ""}>
            <span class="t-body">
              <b>${esc(ENDPOINT_LABEL[endpoint.key] || endpoint.key)}</b>
              <small class="mono">${esc(endpoint.url || "—")}</small>
            </span>
          </div>`).join("")}
      </div>
      <p style="color:var(--faint);font-size:12px;margin:12px 0 0">
        이 세 곳이 REDAR 의 아웃바운드 통신 전부입니다. 템플릿 갱신은 이 항목을 켜고
        직접 실행할 때만 일어나며, 스캔 중 자동 갱신은 하지 않습니다.
      </p>
      <div class="row" style="margin-top:14px">
        <button class="primary" data-save="network">통신 설정 저장</button>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">기본값</div>
        <h2>스캔 옵션 기본값</h2>
      </div>
      <div class="row" style="align-items:flex-start;gap:20px">
        <label class="field" style="flex:1"><span>동시 실행</span>
          <input type="number" id="d-threads" value="${s.scan_defaults?.threads ?? 20}" min="1" max="200"></label>
        <label class="field" style="flex:1"><span>타임아웃 (초)</span>
          <input type="number" id="d-timeout" value="${s.scan_defaults?.timeout_sec ?? 10}" min="1" max="300"></label>
        <label class="field" style="flex:1"><span>재시도</span>
          <input type="number" id="d-retries" value="${s.scan_defaults?.retries ?? 1}" min="0" max="10"></label>
      </div>
      <button class="primary" data-save="defaults">기본값 저장</button>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">선택</div>
        <h2>LLM 설정</h2>
      </div>
      <div class="toggle">
        <input type="checkbox" id="llm-enabled" ${s.llm?.enabled ? "checked" : ""}>
        <span class="t-body">
          <b>보고서 서술문 생성에 LLM 사용</b>
          <small>끄면 사전 정의 문장을 씁니다. 판정·조치 문구는 LLM 이 만들지 않습니다.</small>
        </span>
      </div>
      <div class="toggle">
        <input type="checkbox" id="llm-mask" ${s.llm?.mask_identifiers !== false ? "checked" : ""}>
        <span class="t-body">
          <b>식별자 마스킹</b>
          <small>호스트·IP·경로를 TARGET_1 형태로 치환해 전송합니다.</small>
        </span>
      </div>
      <p style="color:var(--faint);font-size:12px;margin:10px 0 14px">
        요청·응답 원문과 추출값은 어떤 경우에도 전송하지 않습니다. 서술 레이어는 M9 에서 구현됩니다.
      </p>
      <button class="primary" data-save="llm">LLM 설정 저장</button>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">상태</div>
        <h2>도구 정보</h2>
      </div>
      <dl class="kv">
        <dt>nuclei</dt><dd>${state.health?.nuclei ? `v${esc(state.health.nuclei)}` : "미설치 — PATH 또는 REDAR_NUCLEI 확인"}</dd>
        <dt>가이드 본문</dt><dd>${state.guide?.imported
          ? `${state.guide.item_count}개 항목 · ${esc(dash(state.guide.version))}`
          : "미탑재 (정상 상태)"}</dd>
        <dt>매핑 테이블</dt><dd>${state.guide?.mapping_count ?? 0}행</dd>
        <dt>자동 점검</dt><dd>${state.guide?.items_covered ?? 0}개 항목</dd>
      </dl>
    </div>`;
}

const ENDPOINT_LABEL = {
  template_sync: "nuclei 템플릿 갱신",
  llm_api: "LLM API",
  cve_lookup: "CVE 정보 조회",
};

async function saveSettings(kind) {
  const patch = {};
  if (kind === "allowlist") {
    patch.target_allowlist = splitList(document.getElementById("allowlist").value);
  } else if (kind === "network") {
    patch.offline_mode = document.getElementById("offline").checked;
    patch.external_endpoints = Array.from(
      document.querySelectorAll("[data-endpoint]")
    ).map((input) => ({ key: input.dataset.endpoint, enabled: input.checked }));
  } else if (kind === "defaults") {
    patch.scan_defaults = {
      threads: Number(document.getElementById("d-threads").value),
      timeout_sec: Number(document.getElementById("d-timeout").value),
      retries: Number(document.getElementById("d-retries").value),
    };
  } else if (kind === "llm") {
    patch.llm = {
      enabled: document.getElementById("llm-enabled").checked,
      mask_identifiers: document.getElementById("llm-mask").checked,
    };
  }

  try {
    state.settings = await api.saveSettings(patch);
    renderStateStrip();
    toast("저장했습니다");
    if (kind === "network" || kind === "allowlist") render();
  } catch (error) {
    showApiError(error);
  }
}

/* -------------------------------------------------------- 미구현 화면 */

function viewTemplates() {
  view().innerHTML = `
    <div class="view-head">
      <div class="eyebrow">진단 항목 관리</div>
      <h1>템플릿</h1>
      <p>진단 항목은 nuclei YAML 템플릿으로만 표현됩니다. REDAR 는 사용자 스크립트를
         실행하지 않습니다.</p>
    </div>
    <div class="panel">
      <div class="pending">
        <h3>M5 에서 구현</h3>
        <p style="margin:0">이 화면은 아래 세 가지를 담습니다.</p>
        <ul>
          <li>공식 템플릿 목록 조회 — <span class="mono">templates/official/</span> 폴더에 직접 넣거나,
              설정에서 템플릿 갱신을 허용한 뒤 내려받습니다</li>
          <li>직접 작성한 템플릿 관리 — <span class="mono">templates/custom/</span></li>
          <li>폼 기반 템플릿 빌더 — YAML 을 모르는 사용자가 폼 입력으로 템플릿을 만듭니다</li>
        </ul>
      </div>
    </div>
    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">현재</div>
        <h2>지금 할 수 있는 것</h2>
      </div>
      <p style="color:var(--muted);margin:0">
        템플릿 파일을 <span class="mono">templates/custom/</span> 에 두고
        스캔 실행 화면에서 <strong>직접 지정</strong> 방식으로 템플릿 ID 를 입력하면
        바로 실행됩니다.
      </p>
    </div>`;
}

function viewReport() {
  view().innerHTML = `
    <div class="view-head">
      <div class="eyebrow">산출물</div>
      <h1>보고서</h1>
      <p>보고서는 대상과 무관하게 항상 같은 목차로 생성됩니다. 탐지 0건인 절도
         사라지지 않고 "해당 없음" 으로 남습니다.</p>
    </div>
    <div class="panel">
      <div class="pending">
        <h3>M7 에서 구현</h3>
        <ul>
          <li>Part A — 진단 결과 (요약 · 심각도별 · 유형별 · 조치 사항 · 오탐 내역)</li>
          <li>Part B — 주요정보통신기반시설 상세가이드 매핑 (가이드 본문 탑재 시)</li>
          <li>부록 — 심각도 환산표 · 실행 템플릿 목록</li>
          <li>자체 완결형 HTML 1차 산출물, PDF 는 인쇄로 파생</li>
        </ul>
      </div>
      ${coverageNotice(state.guide)}
    </div>`;
}

/* ------------------------------------------------------------ 부트 */

function showApiError(error) {
  if (error instanceof ApiError) {
    const detail = error.details?.[0]?.reason;
    toast(detail ? `${error.message} (${detail})` : error.message, "err");
  } else {
    toast("요청을 처리하지 못했습니다.", "err");
  }
}

async function refreshContext() {
  const results = await Promise.allSettled([
    api.health(), api.guideStatus(), api.settings(),
  ]);
  [state.health, state.guide, state.settings] = results.map((r) =>
    r.status === "fulfilled" ? r.value : null);
  renderStateStrip();
}

async function render() {
  const { path, params } = route();
  renderNav(path === "results-list" ? "results" : path);
  document.querySelector(".drawer")?.remove();

  try {
    if (path === "dashboard") await viewDashboard();
    else if (path === "scan") viewScan();
    else if (path === "results") await viewResults(params);
    else if (path === "results-list") {
      state.scanId = null;
      await viewResults(new URLSearchParams());
    } else if (path === "templates") viewTemplates();
    else if (path === "report") viewReport();
    else if (path === "settings") viewSettings();
    else go("dashboard");
  } catch (error) {
    view().innerHTML = emptyState({
      eyebrow: "오류",
      title: "화면을 불러오지 못했습니다",
      body: esc(error.message || "알 수 없는 오류"),
      cta: '<button class="primary" data-reload>다시 시도</button>',
    });
  }
}

document.addEventListener("click", async (event) => {
  const t = event.target;

  const goTarget = t.closest("[data-go]")?.dataset.go;
  if (goTarget) { go(goTarget); return; }

  if (t.closest("[data-reload]")) { render(); return; }

  const deleteId = t.closest("[data-delete]")?.dataset.delete;
  if (deleteId) {
    event.stopPropagation();
    if (!confirm("스캔과 탐지 결과·보고서를 함께 삭제합니다. 계속할까요?")) return;
    try {
      await api.deleteScan(deleteId);
      if (state.scanId === deleteId) state.scanId = null;
      toast("삭제했습니다");
      render();
    } catch (error) { showApiError(error); }
    return;
  }

  const openId = t.closest("[data-open]")?.dataset.open;
  if (openId) { location.hash = `#/results?scan=${encodeURIComponent(openId)}`; return; }

  const findingId = t.closest("[data-finding]")?.dataset.finding;
  if (findingId) { openFinding(findingId).catch(showApiError); return; }

  if (t.closest("#start")) { startScan(); return; }

  if (t.closest("#cancel")) {
    try {
      await api.cancelScan(state.scanId);
      toast("중단을 요청했습니다");
    } catch (error) { showApiError(error); }
    return;
  }

  if (t.closest("#pick-file")) { document.getElementById("target-file").click(); return; }

  const saveKind = t.closest("[data-save]")?.dataset.save;
  if (saveKind) { saveSettings(saveKind); return; }
});

document.addEventListener("change", async (event) => {
  const filterKey = event.target.dataset?.filter;
  if (filterKey) {
    resultFilters[filterKey] = event.target.value;
    render();
    return;
  }
  if (event.target.id === "target-file") {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const result = await api.importTargets(file);
      document.getElementById("targets").value = result.targets.join("\n");
      toast(result.invalid_lines.length
        ? `${result.count}건 불러옴 · ${result.invalid_lines.length}줄 건너뜀`
        : `${result.count}건 불러옴`);
    } catch (error) { showApiError(error); }
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") document.querySelector(".drawer")?.remove();
});

window.addEventListener("hashchange", render);

(async function boot() {
  await refreshContext();
  await render();
})();
