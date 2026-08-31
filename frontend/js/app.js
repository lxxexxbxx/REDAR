/* 화면 라우팅 + 렌더. 해시 라우팅이라 빌드 도구 불필요 */

import { api, ApiError, subscribeScan } from "./api.js";
import {
  handleTemplateChange, handleTemplateClick, viewTemplates,
} from "./templates.js";
import { handleReportClick, viewReport } from "./reports.js";
import * as tasks from "./tasks.js";
import {
  dependencyPanel, handleDependencyChange, handleDependencyClick,
  missingDependencyNotice,
} from "./dependencies.js";
import {
  FINDING_STATUS_LABEL, SCAN_STATUS_LABEL, SEVERITY_ORDER, SEVERITY_LABEL,
  VULN_TYPE_LABEL, VULN_TYPE_ORDER,
  confirmDialog, coverageNotice, dash, emptyState, esc, fmtDuration, fmtTime,
  scanTargets,
  runEnvironment, selectionBasis, severityAxis, severityTag, target,
  targetEnvironment, targetProbe,
  toast, vulnTypeAxis,
} from "./ui.js";

const NAV = [
  { path: "dashboard", label: "대시보드" },
  { path: "scan", label: "스캔" },
  { path: "results", label: "탐지 결과" },
  { path: "templates", label: "템플릿" },
  { path: "report", label: "보고서" },
  { path: "settings", label: "설정" },
];

const state = {
  health: null,
  guide: null,
  settings: null,
  preflight: null,
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
  let environment = null;
  if (latest) {
    [aggregations, detail, environment] = await Promise.all([
      api.listFindings(latest.scan_id, { size: 1 }).then((r) => r.aggregations),
      api.getScan(latest.scan_id),
      // 환경 조사는 스캔마다 있을 수도 없을 수도 있음. 실패해도 대시보드는 뜸
      api.scanEnvironment(latest.scan_id).then((r) => r.items[0] || null, () => null),
    ]);
  }

  view().innerHTML = `
    ${missingDependencyNotice(state.dependencies)}
    <div class="view-head">
      <div class="eyebrow">진단 현황</div>
      <h1>대시보드</h1>
      <p>가장 최근 스캔의 심각도·유형 분포. 탐지가 0건인 항목도 사라지지 않고 그대로 표시</p>
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
          <h2>${latest ? esc(scanTargets(latest)) : "스캔 기록 없음"}</h2>
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
          <div class="actions">
            <button class="primary" data-open="${esc(latest.scan_id)}">결과 보기</button>
          </div>` : `
          <p style="color:var(--muted);margin:0">
            아직 실행한 스캔 없음. 스캔 화면에서 대상 지정 필요
          </p>
          <div class="actions">
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
          <p style="color:var(--muted);margin:0">스캔 기록 없음</p>`}
      </div>
      <div class="panel">
        <div class="panel-head">
          <div class="eyebrow">진단 대상</div>
          <h2>대상 환경</h2>
        </div>
        ${targetEnvironment(environment)}
        ${environment ? `
          <p style="color:var(--faint);font-size:12px;margin:12px 0 0">
            수집기 ${esc((environment.collectors_run || []).join(" · ") || "없음")}
            ${environment.collectors_failed?.length
              ? ` · 실패 ${esc(environment.collectors_failed.join(", "))}` : ""}
          </p>` : `
          <p style="color:var(--faint);font-size:12px;margin:12px 0 0">
            환경 조사를 수행한 스캔 없음. 스캔 실행 시 <b>대상 환경 먼저 조사</b> 체크 필요
          </p>`}
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
        title: "스캔 이력 없음",
        body: "스캔을 실행하면 여기에 기록됨",
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
        <td class="mono">${esc(scanTargets(scan))}</td>
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

/* 준비 상태 문구. 막힌 이유마다 다음 행동을 한 곳에 모음 */
const BLOCKER_HINT = {
  NUCLEI_MISSING: "탐지 엔진이 없으면 스캔 자체가 실행되지 않음",
  ALLOWLIST_EMPTY: "허락 없이 남의 서버를 스캔하지 않도록, 등록한 대상만 진단하는 구조",
  NO_TEMPLATES: "템플릿은 \"이런 취약점이 있는지 확인하는 방법\"을 적어둔 파일. "
              + "하나도 없으면 스캔은 끝나지만 결과는 항상 0건",
};

function preflightPanel(ready) {
  if (!ready) return "";
  if (ready.ready) {
    const t = ready.templates;
    const detail = t.official + t.custom
      ? `공식 ${t.official}개 · 직접 작성 ${t.custom}개`
      : `nuclei 기본 저장소 사용 · ${t.nuclei_store}`;
    return `<div class="coverage" style="border-left-color:var(--ok)">
      <strong>스캔 준비 완료</strong> 템플릿 ${esc(detail)}
    </div>`;
  }
  return `<div class="coverage" style="border-left-color:var(--brand)">
    <strong>지금은 스캔할 수 없음</strong> 아래를 먼저 해결 필요
    ${ready.blockers.map((b) => `
      <div class="blocker">
        <b>${esc(b.message)}</b>
        <small>${esc(BLOCKER_HINT[b.code] || "")}</small>
        <div class="cta">
          <button class="sm" data-go="${esc(b.goto)}">${esc(b.action)}</button>
        </div>
      </div>`).join("")}
  </div>`;
}

async function refreshPreflight() {
  const host = document.getElementById("preflight");
  if (!host) return;
  try {
    state.preflight = await api.scanPreflight();
  } catch {
    state.preflight = null;                 // 점검 실패가 스캔 화면을 막지 않음
  }
  host.innerHTML = preflightPanel(state.preflight);
  const start = document.getElementById("start");
  if (start && state.preflight) start.disabled = !state.preflight.ready;
}

function viewScan() {
  const allowlist = state.settings?.target_allowlist || [];
  const blocked = allowlist.length === 0;

  view().innerHTML = `
    <div class="view-head">
      <div class="eyebrow">스캔 설정</div>
      <h1>스캔</h1>
      <p>대상 주소를 넣고 진단 방식을 고르면 끝. 잘 모르겠으면 기본값 그대로 두고
         <b>스캔 시작</b> 을 누르면 됨</p>
    </div>

    <div id="preflight"></div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">1단계</div>
        <h2>진단 대상</h2>
      </div>
      <label class="field">
        <span>대상 주소 · 여러 개면 줄바꿈</span>
        <textarea id="targets" placeholder="http://192.168.1.50:8080&#10;http://localhost:7860&#10;localhost:8000-8100"></textarea>
        <small>
          <b>포트를 꼭 붙이세요.</b> 생략하면 80·443 만 검사해서 다른 포트에 떠 있는
          서비스는 찾지 못함. 어느 포트인지 모르면
          <span class="mono">localhost:8000-8100</span> 처럼 범위로 입력 가능
          (범위가 넓으면 실행 전에 다시 확인)
        </small>
        <small class="mono" id="target-count"></small>
      </label>
      <div class="hintbox">
        <b>등록된 대상</b>
        ${allowlist.length
          ? `<div class="chips">${allowlist.map((h) =>
              `<button type="button" class="chip pick" data-pick="${esc(h)}">${esc(h)}</button>`
            ).join(" ")}</div>
             <small>누르면 위 칸에 자동 입력</small>`
          : `<small>없음. 설정에서 등록 필요</small>`}
      </div>
      <div class="actions">
        <input type="file" id="target-file" accept=".txt,.csv" class="sr-only">
        <button class="sm ghost" id="pick-file">파일에서 불러오기</button>
        <span style="color:var(--faint);font-size:12px">한 줄에 하나씩 적힌 txt·csv</span>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">2단계</div>
        <h2>진단 항목 선별</h2>
        <p class="lede">nuclei 는 "이런 취약점이 있는지 확인하는 방법"을 적어둔 파일(템플릿)을
           하나씩 실행해서 진단. 그 파일을 몇 개나, 어떤 기준으로 고를지 선택</p>
      </div>
      <div class="choices" id="mode">
        ${SCAN_MODES.map((m, i) => `
          <label class="choice">
            <input type="radio" name="mode" value="${m.value}" ${i === 0 ? "checked" : ""}>
            <span class="c-body">
              <b>${esc(m.title)}${m.badge ? ` <em class="badge">${esc(m.badge)}</em>` : ""}</b>
              <small>${m.body}</small>
            </span>
          </label>`).join("")}
      </div>
      <div id="mode-fields"></div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">3단계</div>
        <h2>실행 옵션</h2>
        <p class="lede">그대로 둬도 무방. 대상 서버가 느리거나 부하를 줄이고 싶을 때만 조정</p>
      </div>
      <div class="row" style="align-items:flex-start;gap:20px">
        <label class="field" style="flex:1;min-width:150px">
          <span>동시 실행</span>
          <input type="number" id="threads" value="${state.settings?.scan_defaults?.threads ?? 20}" min="1" max="200">
          <small>한 번에 보낼 요청 수. 낮출수록 느리지만 부하 적음</small>
        </label>
        <label class="field" style="flex:1;min-width:150px">
          <span>응답 대기 · 초</span>
          <input type="number" id="timeout" value="${state.settings?.scan_defaults?.timeout_sec ?? 10}" min="1" max="300">
          <small>이 시간 안에 답이 없으면 넘어감</small>
        </label>
        <label class="field" style="flex:1;min-width:150px">
          <span>재시도</span>
          <input type="number" id="retries" value="${state.settings?.scan_defaults?.retries ?? 1}" min="0" max="10">
          <small>실패한 요청을 다시 보낼 횟수</small>
        </label>
        <label class="field" style="flex:1;min-width:150px">
          <span>초당 요청 상한</span>
          <input type="number" id="ratelimit" placeholder="제한 없음" min="1">
          <small>운영 중인 서버라면 지정 권장</small>
        </label>
      </div>
      <div class="toggle">
        <input type="checkbox" id="collect-env" checked>
        <span class="t-body">
          <b>대상 환경 먼저 조사</b>
          <small>어떤 웹서버·CMS·플러그인을 쓰는지 확인. 보고서에 대상 정보가 함께 실림</small>
        </span>
      </div>
      <div id="range-notice"></div>
      <div class="actions">
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
      <div class="row mono" style="margin-top:var(--gap);font-size:12px;color:var(--muted)">
        <span id="live-phase">준비</span>
        <span id="live-count">탐지 0건</span>
      </div>
      <div class="livefeed" style="margin-top:var(--gap)">
        <table>
          <thead><tr><th>심각도</th><th>탐지 항목</th><th>유형</th><th>대상</th></tr></thead>
          <tbody id="live-rows"></tbody>
        </table>
      </div>
    </div>`;

  renderModeFields();
  document.getElementById("mode").addEventListener("change", renderModeFields);
  const targetBox = document.getElementById("targets");
  targetBox.addEventListener("input", renderTargetCount);
  renderTargetCount();
  refreshPreflight();
}

/* 입력한 범위가 몇 개 대상으로 펼쳐지는지 즉시 표시.
 * 실제 판정은 서버가 하지만, 눌러본 뒤에야 아는 것과 적으면서 아는 것은 다름 */
const RANGE_RE = /^((?:[a-z][a-z0-9+.\-]*:\/\/)?[^/:]+):(\d{1,5})-(\d{1,5})([/?].*)?$/i;

function expandedTargetCount(lines) {
  let total = 0;
  for (const line of lines) {
    const match = RANGE_RE.exec(line);
    if (!match) { total += 1; continue; }
    const start = Number(match[2]), end = Number(match[3]);
    total += end >= start ? end - start + 1 : 1;
  }
  return total;
}

function renderTargetCount() {
  const note = document.getElementById("target-count");
  if (!note) return;
  const lines = splitList(document.getElementById("targets").value);
  const total = expandedTargetCount(lines);
  if (!lines.length) { note.textContent = ""; return; }
  note.textContent = total > lines.length
    ? `입력 ${lines.length}줄 → 실제 스캔 대상 ${total}개`
    : `스캔 대상 ${total}개`;
  note.style.color = total > 300 ? "var(--warn)" : "var(--faint)";
}

/* 선별 방식. 화면 문구와 API mode 값의 단일 출처 (docs/00 §TemplateSelection) */
const SCAN_MODES = [
  {
    value: "environment_driven",
    title: "환경 기반 자동 선별",
    badge: "권장",
    body: "대상이 무엇으로 만들어졌는지 먼저 살펴본 뒤, 그 환경에 해당하는 항목만 검사. "
        + "쓸데없는 요청이 적어 빠르고 부하도 적음",
  },
  {
    value: "filter",
    title: "조건 필터 선별",
    body: "주제(태그)와 심각도로 범위 지정. 예를 들어 워드프레스 관련 항목만, "
        + "또는 위험도가 높은 것만 검사",
  },
  {
    value: "explicit",
    title: "템플릿 직접 지정",
    body: "검사할 템플릿 ID 를 직접 입력. 특정 취약점 하나를 다시 확인할 때 사용",
  },
];

/* 태그 추천. 자유 입력이 막막하다는 피드백. 값은 nuclei 표준 태그 */
const TAG_PRESETS = [
  { tag: "cve", label: "알려진 취약점 (CVE)" },
  { tag: "wordpress", label: "워드프레스" },
  { tag: "apache", label: "Apache 웹서버" },
  { tag: "nginx", label: "nginx 웹서버" },
  { tag: "exposure", label: "노출된 파일·설정" },
  { tag: "misconfig", label: "설정 실수" },
];

function scanMode() {
  return document.querySelector('input[name="mode"]:checked')?.value || "environment_driven";
}

function renderModeFields() {
  const host = document.getElementById("mode-fields");
  const mode = scanMode();

  // 환경 기반 선별은 조사 결과가 입력. 끄면 백엔드가 400 으로 거부하므로 미리 고정
  const env = document.getElementById("collect-env");
  if (env) {
    const required = mode === "environment_driven";
    if (required) env.checked = true;
    env.disabled = required;
    env.closest(".toggle").querySelector("small").textContent = required
      ? "어떤 웹서버·CMS·플러그인을 쓰는지 확인. 환경 기반 선별에 필요해 항상 켜짐"
      : "어떤 웹서버·CMS·플러그인을 쓰는지 확인. 보고서에 대상 정보가 함께 실림";
  }

  if (mode === "environment_driven") {
    host.innerHTML = `
      <div class="hintbox">
        <b>추가 입력 없음</b>
        <small>대상 조사 결과에 따라 검사 항목이 정해짐. 조사에서 아무것도 못 찾으면
          검사 항목이 0개가 될 수 있으며, 이때는 <b>조건 필터 선별</b> 사용</small>
      </div>`;
    return;
  }

  if (mode === "explicit") {
    host.innerHTML = `
      <label class="field">
        <span>템플릿 ID · 쉼표 구분</span>
        <input type="text" id="template-ids" placeholder="CVE-2026-33017, wordpress-detect">
        <small>템플릿 화면 목록에서 ID 확인 가능</small>
      </label>`;
    return;
  }

  host.innerHTML = `
    <label class="field">
      <span>주제</span>
      <input type="text" id="tags" placeholder="비워두면 주제 제한 없음">
      <div class="chips" style="margin-top:8px">
        ${TAG_PRESETS.map((p) =>
          `<button type="button" class="chip pick" data-tag="${esc(p.tag)}">${esc(p.label)}</button>`
        ).join(" ")}
      </div>
      <small>눌러서 추가. 여러 개면 쉼표로 구분되며 하나라도 맞으면 검사 대상</small>
    </label>
    <label class="field">
      <span>심각도</span>
      <div class="chips" id="sev-picks">
        ${SEVERITY_ORDER.map((key) =>
          `<button type="button" class="chip pick sev-pick" data-sev="${key}">${esc(SEVERITY_LABEL[key])}</button>`
        ).join(" ")}
      </div>
      <small>아무것도 고르지 않으면 전체 심각도 검사</small>
    </label>`;
}

function appendLine(id, value) {
  const box = document.getElementById(id);
  const lines = splitList(box.value);
  if (!lines.includes(value)) lines.push(value);
  box.value = lines.join("\n");
}

function appendToken(id, value) {
  const box = document.getElementById(id);
  const tokens = splitList(box.value);
  if (!tokens.includes(value)) tokens.push(value);
  box.value = tokens.join(", ");
}

const splitList = (value) =>
  (value || "").split(/[\n,]/).map((s) => s.trim()).filter(Boolean);

/* 화면 입력 → 요청 본문. 최초 실행과 범위 확인 후 재실행이 공유 */
function buildScanPayload() {
  const mode = scanMode();
  const selection = { mode };
  if (mode === "explicit") {
    selection.template_ids = splitList(document.getElementById("template-ids")?.value);
  } else if (mode === "filter") {
    selection.tags = splitList(document.getElementById("tags")?.value);
    selection.severity = Array.from(
      document.querySelectorAll("#sev-picks .on")
    ).map((node) => node.dataset.sev);
  }

  const rateLimit = Number(document.getElementById("ratelimit").value);
  return {
    targets: splitList(document.getElementById("targets").value),
    template_selection: selection,
    collect_environment: document.getElementById("collect-env").checked,
    options: {
      threads: Number(document.getElementById("threads").value) || 20,
      timeout_sec: Number(document.getElementById("timeout").value) || 10,
      retries: Number(document.getElementById("retries").value) || 0,
      ...(rateLimit ? { rate_limit: rateLimit } : {}),
    },
  };
}

async function startScan() {
  const payload = buildScanPayload();
  if (!payload.targets.length) {
    toast("스캔 대상 입력 필요", "err");
    return;
  }

  const button = document.getElementById("start");
  button.disabled = true;
  try {
    const { scan_id } = await api.createScan(payload);
    rangeNotice("");
    state.scanId = scan_id;
    attachLiveFeed(scan_id);
  } catch (error) {
    button.disabled = false;
    // 포트 범위가 넓으면 서버가 되물음. 화면 안에서 확인받음 -
    // 브라우저 기본 대화상자는 데스크톱 셸에서 뜨지 않아 조용히 취소됨
    if (error instanceof ApiError && error.code === "LARGE_TARGET_EXPANSION") {
      rangeNotice(`
        <strong>포트 범위가 넓음</strong> ${esc(error.message)}.
        <div style="margin-top:6px;color:var(--faint)">
          닫힌 포트는 빠르게 넘어가지만, 방화벽이 응답을 버리면 포트마다 대기 시간이 쌓임.
          범위를 좁히거나 아래 버튼으로 진행
        </div>
        <div class="cta">
          <button class="primary" id="confirm-range">이대로 스캔</button>
          <button class="sm ghost" id="cancel-range">범위 수정</button>
        </div>`);
      return;
    }
    showApiError(error);
  }
}

/* 범위 확인 막대. 스캔 버튼 바로 위에 붙여 놓쳐지지 않게 함 */
function rangeNotice(html) {
  const host = document.getElementById("range-notice");
  if (!host) return;
  host.innerHTML = html
    ? `<div class="coverage" style="border-left-color:var(--warn)">${html}</div>`
    : "";
}

async function confirmRangeAndStart() {
  rangeNotice("");
  const button = document.getElementById("start");
  button.disabled = true;
  try {
    const { scan_id } = await api.createScan({
      ...buildScanPayload(), confirm_expanded: true,
    });
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
    probing_targets: "대상 응답 확인",
    collecting_environment: "환경 조사",
    selecting_templates: "템플릿 선별",
    scanning: "스캔 진행",
    finalizing: "마무리",
  };

  // 하단 도크에도 같은 진행을 보냄. 다른 화면으로 옮겨도 상태가 보임
  const dockId = tasks.begin("스캔", scanId);

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
      tasks.update(dockId, {
        detail: phase.textContent,
        percent: event.percent ?? null,
      });
    },
    finding(event) {
      found += 1;
      countLabel.textContent = `탐지 ${found}건`;
      tasks.update(dockId, { detail: `${phase.textContent} · 탐지 ${found}건` });
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
        tasks.fail(dockId, `${event.error.code}: ${event.error.message}`);
        toast(`${event.error.code}: ${event.error.message}`, "err");
      } else if (event.status === "completed") {
        tasks.done(dockId, `탐지 ${found}건`);
        toast("스캔 완료");
        document.getElementById("start-note").innerHTML =
          `<button class="sm" data-open="${esc(scanId)}">결과 보기</button>`;
      } else {
        tasks.done(dockId, SCAN_STATUS_LABEL[event.status] || event.status);
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
        <p>조회할 스캔 선택 필요</p>
      </div>
      <div class="panel">
        ${items.length ? scanTable(items) : emptyState({
          eyebrow: "기록 없음",
          title: "조회할 스캔 없음",
          body: "스캔을 먼저 실행 필요",
          cta: '<button class="primary" data-go="scan">스캔 실행</button>',
        })}
      </div>`;
    return;
  }

  state.scanId = scanId;
  const scan = await api.getScan(scanId);
  const environment = await api
    .scanEnvironment(scanId)
    .then((r) => r.items[0] || null, () => null);
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
        <h1>${esc(scanTargets(scan))}</h1>
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
        ${targetEnvironment(environment)}
        ${selectionBasis(scan.selection_basis)}
      </div>
    </div>

    ${targetProbe(scan)}

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
        title: "조건에 맞는 결과 없음",
        body: "필터 해제 또는 다른 스캔 선택. 탐지 0건이 곧 안전을 뜻하지는 않음",
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
        <h2 style="margin-top:4px">${esc(f.name)}</h2>
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
               가이드 본문 미탑재. 조치 문구 표시 불가.
               가이드 파일을 임포트하면 이 자리에 원문 그대로 표시
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
        <div class="actions">
          <button class="sm" data-copy>명령 복사</button>
        </div>
      </section>` : ""}

      <section>
        <h3>판정</h3>
        <p style="color:var(--faint);font-size:12.5px;margin:0 0 10px">
          오탐으로 표시하면 집계에서 빠지고, 보고서 부록에 사유가 남음
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
      toast("명령 복사됨");
      return;
    }
    const status = event.target.closest("[data-status]")?.dataset.status;
    if (status) {
      try {
        await api.patchFinding(f.finding_id, {
          status,
          note: drawer.querySelector("#fp-note").value || null,
        });
        toast(`상태 변경됨 · ${FINDING_STATUS_LABEL[status]}`);
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
      <p>어디를 스캔할 수 있는지, 어디로 통신할 수 있는지 지정. 처음 상태는 전부 차단</p>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">필수</div>
        <h2>스캔 허용 대상</h2>
      </div>
      <label class="field">
        <span>진단할 대상 · 한 줄에 하나</span>
        <textarea id="allowlist" placeholder="192.168.1.50&#10;target.local&#10;192.168.1.0/24">${esc((s.target_allowlist || []).join("\n"))}</textarea>
        <small>
          주소를 통째로 붙여넣어도 됨. <span class="mono">http://192.168.1.50:8080/admin</span> 은
          저장할 때 <span class="mono">192.168.1.50</span> 으로 정리됨.
          한 대역을 통째로 허용하려면 <span class="mono">192.168.1.0/24</span> 처럼 입력.
          여기 없는 대상은 스캔이 거부되며, 이름은 그대로 비교하고 DNS 조회는 하지 않음
        </small>
      </label>
      <div class="actions">
        <button class="primary" data-save="allowlist">허용 대상 저장</button>
      </div>
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
          <small>켜면 아래 네 곳을 개별 설정과 무관하게 전부 차단. 끄면 아래에서 하나씩 선택 가능</small>
        </span>
      </div>
      <p id="endpoint-note" style="color:var(--warn);font-size:12px;margin:4px 0 0">${
        s.offline_mode ? "오프라인 모드가 켜져 있어 아래 항목은 잠김. 끄면 개별 선택 가능" : ""
      }</p>
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
        REDAR 가 바깥으로 나가는 통신은 이 네 곳뿐. 켜두더라도 사용자가 직접 실행할 때만
        통신하며 저절로 나가지 않음
      </p>
      <div class="actions">
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
        <label class="field" style="flex:1"><span>응답 대기 · 초</span>
          <input type="number" id="d-timeout" value="${s.scan_defaults?.timeout_sec ?? 10}" min="1" max="300"></label>
        <label class="field" style="flex:1"><span>재시도</span>
          <input type="number" id="d-retries" value="${s.scan_defaults?.retries ?? 1}" min="0" max="10"></label>
      </div>
      <div class="actions">
        <button class="primary" data-save="defaults">기본값 저장</button>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">필수 도구</div>
        <h2>의존성</h2>
      </div>
      ${dependencyPanel(state.dependencies)}
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
          <small>끄면 미리 정해둔 문장 사용. 취약점 판정과 조치 문구는 어떤 경우에도 LLM 이 만들지 않음</small>
        </span>
      </div>
      <div class="toggle">
        <input type="checkbox" id="llm-mask" ${s.llm?.mask_identifiers !== false ? "checked" : ""}>
        <span class="t-body">
          <b>식별자 마스킹</b>
          <small>주소·IP·경로를 TARGET_1 같은 가짜 이름으로 바꿔 전송</small>
        </span>
      </div>
      <p style="color:var(--faint);font-size:12px;margin:10px 0 14px">
        요청·응답 원문과 추출값은 어떤 경우에도 전송하지 않음. 보고서의 설명 문장에만 사용
      </p>
      <div class="actions">
        <button class="primary" data-save="llm">LLM 설정 저장</button>
      </div>
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
  dependency_install: "의존성 자동 설치 (nuclei · Go)",
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
    toast("저장됨");
    if (kind === "network" || kind === "allowlist") render();
  } catch (error) {
    showApiError(error);
  }
}

/* -------------------------------------------------------- 미구현 화면 */

/* ------------------------------------------------------------ 부트 */

function showApiError(error) {
  if (error instanceof ApiError) {
    const detail = error.details?.[0]?.reason;
    toast(detail ? `${error.message} (${detail})` : error.message, "err");
  } else {
    toast("요청 처리 실패", "err");
  }
}

async function refreshContext() {
  const results = await Promise.allSettled([
    api.health(), api.guideStatus(), api.settings(), api.dependencies(),
  ]);
  [state.health, state.guide, state.settings, state.dependencies] =
    results.map((r) => (r.status === "fulfilled" ? r.value : null));
  renderStateStrip();
}

async function refreshAndRender() {
  await refreshContext();
  await render();
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
    } else if (path === "templates") await viewTemplates();
    else if (path === "report") await viewReport();
    else if (path === "settings") viewSettings();
    else go("dashboard");
  } catch (error) {
    view().innerHTML = emptyState({
      eyebrow: "오류",
      title: "화면을 불러오지 못함",
      body: esc(error.message || "알 수 없는 오류"),
      cta: '<button class="primary" data-reload>다시 시도</button>',
    });
  }
}

document.addEventListener("click", async (event) => {
  const t = event.target;

  if (tasks.handleDockClick(t)) return;

  // 칩 입력. 자유 입력만 두면 무엇을 적어야 할지 알 수 없다는 피드백
  const pick = t.closest(".pick");
  if (pick) {
    if (pick.dataset.pick) appendLine("targets", pick.dataset.pick);
    else if (pick.dataset.tag) appendToken("tags", pick.dataset.tag);
    else if (pick.dataset.sev) pick.classList.toggle("on");
    return;
  }

  const goTarget = t.closest("[data-go]")?.dataset.go;
  if (goTarget) { go(goTarget); return; }

  if (t.closest("[data-reload]")) { render(); return; }

  const deleteId = t.closest("[data-delete]")?.dataset.delete;
  if (deleteId) {
    event.stopPropagation();
    const ok = await confirmDialog({
      title: "스캔 삭제",
      body: "이 스캔의 탐지 결과와 보고서까지 함께 삭제됨. 되돌릴 수 없음",
      confirmLabel: "삭제",
      danger: true,
    });
    if (!ok) return;
    try {
      await api.deleteScan(deleteId);
      if (state.scanId === deleteId) state.scanId = null;
      toast("삭제됨");
      render();
    } catch (error) { showApiError(error); }
    return;
  }

  const openId = t.closest("[data-open]")?.dataset.open;
  if (openId) { location.hash = `#/results?scan=${encodeURIComponent(openId)}`; return; }

  const findingId = t.closest("[data-finding]")?.dataset.finding;
  if (findingId) { openFinding(findingId).catch(showApiError); return; }

  if (t.closest("#start")) { startScan(); return; }
  if (t.closest("#confirm-range")) { confirmRangeAndStart(); return; }
  if (t.closest("#cancel-range")) {
    rangeNotice("");
    document.getElementById("targets").focus();
    return;
  }

  if (t.closest("#cancel")) {
    try {
      await api.cancelScan(state.scanId);
      toast("중단 요청됨");
    } catch (error) { showApiError(error); }
    return;
  }

  if (t.closest("#pick-file")) { document.getElementById("target-file").click(); return; }

  const saveKind = t.closest("[data-save]")?.dataset.save;
  if (saveKind) { saveSettings(saveKind); return; }

  // 템플릿 화면은 자기 이벤트를 스스로 처리. 처리했으면 true
  try {
    if (await handleDependencyClick(t, refreshAndRender)) return;
    if (await handleTemplateClick(t)) return;
    if (await handleReportClick(t)) return;
  } catch (error) { showApiError(error); }
});

document.addEventListener("change", async (event) => {
  try {
    if (await handleDependencyChange(event.target, refreshAndRender)) return;
    if (await handleTemplateChange(event.target)) return;
  } catch (error) { showApiError(error); }

  // 오프라인 모드는 개별 지점을 덮어씀. 저장 후 재렌더까지 기다리면
  // 체크박스가 잠긴 채로 보여 '체크가 안 된다' 로 읽힘
  if (event.target.id === "offline") {
    const locked = event.target.checked;
    document.querySelectorAll("[data-endpoint]").forEach((node) => {
      node.disabled = locked;
    });
    document.getElementById("endpoint-note").textContent = locked
      ? "오프라인 모드가 켜져 있어 아래 항목은 잠김. 끄면 개별 선택 가능"
      : "";
    return;
  }

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
