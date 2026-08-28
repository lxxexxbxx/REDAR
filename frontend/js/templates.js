/* 템플릿 화면. 폼은 GET /templates/schema 를 그려서 만든다.
 *
 * 필드 정의를 프론트에 복제하지 않는다 - 백엔드에 필드가 추가되면 이 화면이
 * 자동으로 따라간다 (docs/00 §3). 그래서 렌더러는 타입별로만 분기한다 */
import { api, ApiError } from "./api.js";
import { esc, dash, toast } from "./ui.js";

const view = () => document.getElementById("view");

const SOURCE_LABEL = { official: "공식", custom: "직접 작성" };
const SEVERITY_LABEL = {
  critical: "치명적", high: "높음", medium: "중간", low: "낮음", info: "정보",
};

const filters = { source: "", severity: "", q: "" };
const state = { schema: null, items: [], total: 0, editing: null };

/* ------------------------------------------------------------ 화면 */

export async function viewTemplates() {
  if (!state.schema) state.schema = await api.templateSchema();
  const listed = await api.listTemplates({
    source: filters.source, severity: filters.severity, q: filters.q, size: 100,
  });
  state.items = listed.items;
  state.total = listed.total;

  view().innerHTML = `
    <div class="view-head">
      <div class="eyebrow">진단 항목 관리</div>
      <h1>템플릿</h1>
      <p>진단 항목은 nuclei YAML 템플릿으로만 표현됩니다. REDAR 는 사용자 스크립트를
         실행하지 않습니다.</p>
    </div>

    <div class="panel">
      <div class="panel-head spread">
        <div>
          <div class="eyebrow">인벤토리 · ${state.total}개</div>
          <h2>보유 템플릿</h2>
        </div>
        <div class="row">
          <button class="sm" data-tpl="reindex">폴더 재색인</button>
          <button class="sm" data-tpl="sync">공식 템플릿 갱신</button>
        </div>
      </div>

      <div class="filters">
        <select data-tpl-filter="source">
          <option value="">출처 전체</option>
          <option value="official"${filters.source === "official" ? " selected" : ""}>공식</option>
          <option value="custom"${filters.source === "custom" ? " selected" : ""}>직접 작성</option>
        </select>
        <select data-tpl-filter="severity">
          <option value="">심각도 전체</option>
          ${Object.entries(SEVERITY_LABEL).map(([key, label]) =>
            `<option value="${key}"${filters.severity === key ? " selected" : ""}>${label}</option>`
          ).join("")}
        </select>
        <input type="text" data-tpl-filter="q" placeholder="ID · 이름 검색"
               value="${esc(filters.q)}">
      </div>

      ${state.items.length ? templateTable(state.items) : `
        <div class="empty">
          <div class="eyebrow">${state.total === 0 && !filters.q ? "인벤토리 비어 있음" : "결과 없음"}</div>
          <h2>표시할 템플릿이 없습니다</h2>
          <p>아래에서 직접 만들거나, <span class="mono">templates/official/</span> 에
             파일을 넣고 <strong>폴더 재색인</strong>을 누르세요.</p>
        </div>`}
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">${state.editing ? "수정" : "새로 만들기"}</div>
        <h2>${state.editing ? esc(state.editing) : "폼으로 템플릿 작성"}</h2>
      </div>
      <form id="tpl-form" autocomplete="off">
        ${state.schema.sections.map(section).join("")}
        ${conditionField()}
      </form>
      <div class="actions">
        <button class="primary" data-tpl="save">${state.editing ? "수정 저장" : "저장"}</button>
        <button data-tpl="preview">YAML 미리보기 · 검증</button>
        ${state.editing ? '<button data-tpl="cancel-edit">편집 취소</button>' : ""}
      </div>
      <div id="tpl-result"></div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">시험 실행</div>
        <h2>드라이런</h2>
      </div>
      <p style="color:var(--muted);margin:0 0 12px">
        저장 전에 대상 1개로 실제 요청을 보내 matcher 별 매칭 결과를 확인합니다.
        allowlist 통제가 스캔과 동일하게 적용됩니다.
      </p>
      <label class="field">
        <span>대상</span>
        <input type="text" id="tpl-target" placeholder="http://192.168.1.50">
      </label>
      <div class="actions">
        <button data-tpl="dryrun">드라이런 실행</button>
      </div>
      <div id="tpl-dryrun"></div>
    </div>`;
}

function templateTable(items) {
  return `<table>
    <thead><tr>
      <th>ID</th><th>이름</th><th>심각도</th><th>유형</th><th>출처</th><th>태그</th>
    </tr></thead>
    <tbody>${items.map((t) => `
      <tr class="clickable" data-tpl-open="${esc(t.template_id)}">
        <td class="mono">${esc(t.template_id)}</td>
        <td>${esc(t.name)}${t.is_detection
          ? ' <span class="chip">자산 식별</span>' : ""}</td>
        <td>${t.severity
          ? `<span class="sev sev-${esc(t.severity)}">${esc(SEVERITY_LABEL[t.severity] || t.severity)}</span>`
          : "—"}</td>
        <td>${esc(dash(t.vuln_type))}</td>
        <td>${esc(SOURCE_LABEL[t.source] || t.source)}</td>
        <td class="mono" style="font-size:11.5px;color:var(--muted)">
          ${esc((t.tags || []).slice(0, 3).join(", ")) || "—"}</td>
      </tr>`).join("")}
    </tbody></table>`;
}

/* ------------------------------------------------- 스키마 기반 폼 렌더 */

function section(spec) {
  const body = spec.repeatable
    ? `<div data-groups="${spec.key}">
         ${groupHtml(spec, 0)}
       </div>
       <div class="actions">
         <button class="sm" data-tpl-add="${spec.key}">${esc(spec.label)} 추가</button>
       </div>`
    : `<div class="form-grid">
         ${spec.fields.map((f) => fieldHtml(spec.key, f)).join("")}
       </div>`;

  return `<section style="margin-bottom:20px">
    <h3 style="font-family:var(--mono);font-size:10px;letter-spacing:.14em;
               text-transform:uppercase;color:var(--faint);font-weight:400;
               margin-bottom:10px">${esc(spec.label)}</h3>
    ${body}
  </section>`;
}

function groupHtml(spec, index) {
  return `<div data-group="${spec.key}" style="border-left:2px solid var(--line);
              padding-left:14px;margin-bottom:12px">
    <div class="form-grid">
      ${spec.fields.map((f) => fieldHtml(spec.key, f)).join("")}
    </div>
    <div class="actions">
      <button class="sm ghost" data-tpl-remove="${spec.key}">이 항목 삭제</button>
    </div>
  </div>`;
}

function fieldHtml(sectionKey, field) {
  const id = `${sectionKey}.${field.key}`;
  const required = field.required ? " required" : "";
  const label = `<span>${esc(field.label)}${field.required ? " *" : ""}</span>`;
  let control;

  switch (field.type) {
    case "enum":
      control = `<select data-field="${id}"${required}>
        ${field.required ? "" : '<option value="">선택 없음</option>'}
        ${(field.options || []).map((o) =>
          `<option value="${esc(o)}"${o === field.default ? " selected" : ""}>${esc(o)}</option>`
        ).join("")}
      </select>`;
      break;
    case "text":
      control = `<textarea data-field="${id}" rows="3"${required}></textarea>`;
      break;
    case "keyvalue":
      control = `<textarea data-field="${id}" data-kv="1" rows="2"
        placeholder="Content-Type: application/json"></textarea>`;
      break;
    case "number":
      control = `<input type="number" data-field="${id}" step="0.1"
        ${field.min !== undefined ? `min="${field.min}"` : ""}
        ${field.max !== undefined ? `max="${field.max}"` : ""}${required}>`;
      break;
    case "list":
      control = `<input type="text" data-field="${id}" data-list="1"
        placeholder="쉼표로 구분"${required}>`;
      break;
    default:
      control = `<input type="text" data-field="${id}"
        ${field.pattern ? `pattern="${esc(field.pattern)}"` : ""}${required}>`;
  }

  const wide = field.type === "text" || field.type === "keyvalue" ? " wide" : "";
  return `<label class="field${wide}">
    ${label}${control}
    ${field.help ? `<small>${esc(field.help)}</small>` : ""}
  </label>`;
}

function conditionField() {
  const spec = state.schema.matchers_condition;
  return `<label class="field" style="max-width:220px">
    <span>탐지 조건 결합</span>
    <select data-field="matchers-condition">
      ${(spec.options || []).map((o) =>
        `<option value="${esc(o)}"${o === spec.default ? " selected" : ""}>${esc(o)}</option>`
      ).join("")}
    </select>
  </label>`;
}

/* ------------------------------------------------------- 폼 -> 객체 */

function readControl(node) {
  const raw = node.value.trim();
  if (!raw) return null;
  if (node.dataset.list) return raw.split(",").map((v) => v.trim()).filter(Boolean);
  if (node.dataset.kv) {
    const out = {};
    for (const line of raw.split("\n")) {
      const at = line.indexOf(":");
      if (at > 0) out[line.slice(0, at).trim()] = line.slice(at + 1).trim();
    }
    return Object.keys(out).length ? out : null;
  }
  if (node.type === "number") return Number(raw);
  return raw;
}

export function collectForm() {
  const form = document.getElementById("tpl-form");
  const out = { "matchers-condition": "and" };

  for (const spec of state.schema.sections) {
    if (spec.repeatable) {
      out[spec.key] = [...form.querySelectorAll(`[data-group="${spec.key}"]`)]
        .map((group) => {
          const entry = {};
          for (const node of group.querySelectorAll("[data-field]")) {
            const key = node.dataset.field.split(".").pop();
            const value = readControl(node);
            if (value !== null) entry[key] = value;
          }
          return entry;
        })
        .filter((entry) => Object.keys(entry).length);
    } else {
      const entry = {};
      for (const node of form.querySelectorAll(`[data-field^="${spec.key}."]`)) {
        if (node.closest("[data-group]")) continue;
        const key = node.dataset.field.split(".").pop();
        const value = readControl(node);
        if (value !== null) entry[key] = value;
      }
      out[spec.key] = entry;
    }
  }
  const condition = form.querySelector('[data-field="matchers-condition"]');
  if (condition?.value) out["matchers-condition"] = condition.value;
  return out;
}

function fillForm(form) {
  const node = document.getElementById("tpl-form");
  const set = (selector, value) => {
    const target = node.querySelector(selector);
    if (!target || value === null || value === undefined) return;
    target.value = Array.isArray(value)
      ? value.join(", ")
      : (typeof value === "object"
          ? Object.entries(value).map(([k, v]) => `${k}: ${v}`).join("\n")
          : String(value));
  };

  for (const [key, value] of Object.entries(form.info || {})) set(`[data-field="info.${key}"]`, value);
  for (const [key, value] of Object.entries(form.classification || {})) {
    set(`[data-field="classification.${key}"]`, value);
  }
  set('[data-field="matchers-condition"]', form["matchers-condition"]);

  for (const sectionKey of ["http", "matchers"]) {
    const entries = form[sectionKey] || [];
    const container = node.querySelector(`[data-groups="${sectionKey}"]`);
    if (!container) continue;
    const spec = state.schema.sections.find((s) => s.key === sectionKey);
    container.innerHTML = entries.map((_, i) => groupHtml(spec, i)).join("")
      || groupHtml(spec, 0);
    [...container.querySelectorAll("[data-group]")].forEach((group, index) => {
      for (const [key, value] of Object.entries(entries[index] || {})) {
        const target = group.querySelector(`[data-field$=".${key}"]`);
        if (target && value !== null) {
          target.value = Array.isArray(value)
            ? value.join(", ")
            : (typeof value === "object"
                ? Object.entries(value).map(([k, v]) => `${k}: ${v}`).join("\n")
                : String(value));
        }
      }
    });
  }
}

/* ----------------------------------------------------------- 동작 */

function renderCheck(result) {
  const target = document.getElementById("tpl-result");
  const syntax = result.syntax || {};
  const policy = result.policy || {};
  target.innerHTML = `
    <pre class="evidence" style="margin-top:14px">${esc(result.yaml || "")}</pre>
    <div class="coverage" style="border-left-color:${
      policy.valid ? "var(--ok)" : "var(--brand)"}">
      <strong>정책 검증 ${policy.valid ? "통과" : "실패"}</strong>
      · 문법 ${syntax.skipped
        ? `건너뜀 (${esc(syntax.reason || "")})`
        : (syntax.valid ? "통과" : "실패")}
      ${policy.errors?.length ? `
        <div style="margin-top:8px">${policy.errors.map((e) =>
          `<div><span class="mono">${esc(e.field)}</span> — ${esc(e.message)}</div>`
        ).join("")}</div>` : ""}
      ${policy.warnings?.length ? `
        <div style="margin-top:8px;color:var(--warn)">${policy.warnings.map((w) =>
          `<div><span class="mono">${esc(w.code)}</span> ${esc(w.message)}
           <div style="color:var(--faint)">${esc(w.suggestion || "")}</div></div>`
        ).join("")}</div>` : ""}
    </div>`;
}

async function preview() {
  // YAML 은 서버가 만든 것을 그대로 보여준다 (validate 응답에 포함)
  renderCheck(await api.validateTemplate({ form: collectForm() }));
}

async function save() {
  const form = collectForm();
  const result = state.editing
    ? await api.updateTemplate(state.editing, form)
    : await api.createTemplate(form);
  toast(state.editing ? "수정했습니다" : "저장했습니다");
  state.editing = null;
  await viewTemplates();
  renderCheck({ ...result, policy: { valid: true, warnings: result.warnings || [] },
                syntax: result.syntax || {} });
}

async function dryrun() {
  const target = document.getElementById("tpl-target").value.trim();
  const box = document.getElementById("tpl-dryrun");
  if (!target) { toast("대상을 입력하세요", "err"); return; }

  const built = await api.validateTemplate({ form: collectForm() });
  if (!built.policy.valid) {
    toast("정책 검증을 먼저 통과해야 합니다", "err");
    renderCheck(built);
    return;
  }
  const result = await api.dryrunTemplate({
    yaml: built.yaml, target, timeout_sec: 10,
  });
  const request = result.requests?.[0] || {};
  box.innerHTML = `
    <div class="coverage" style="margin-top:14px;border-left-color:${
      result.matched ? "var(--ok)" : "var(--warn)"}">
      <strong>${result.matched ? "매칭됨" : "매칭되지 않음"}</strong>
      · ${result.duration_ms}ms
      ${request.response_status ? ` · 응답 ${request.response_status}` : ""}
      <div style="margin-top:8px">
        ${(request.matcher_results || []).map((m) => `
          <div><span class="mono">${esc(m.name || m.type)}</span>
            ${esc(m.type)} —
            <span style="color:${m.matched ? "var(--ok)" : "var(--brand)"}">
              ${m.matched ? "매칭" : "미매칭"}</span></div>`).join("")}
      </div>
    </div>
    ${request.response_excerpt
      ? `<pre class="evidence" style="margin-top:10px">${esc(request.response_excerpt)}</pre>`
      : ""}`;
}

async function openTemplate(templateId) {
  const detail = await api.getTemplate(templateId);
  document.querySelector(".drawer")?.remove();
  const node = document.createElement("aside");
  node.className = "drawer";
  node.innerHTML = `
    <div class="drawer-head">
      <div>
        <div class="eyebrow">${esc(SOURCE_LABEL[detail.source] || detail.source)}</div>
        <h2 style="margin-top:4px">${esc(detail.name)}</h2>
        <div class="mono" style="color:var(--faint);font-size:11.5px;margin-top:4px">
          ${esc(detail.template_id)}</div>
      </div>
      <button class="sm ghost" data-tpl="close">닫기</button>
    </div>
    <div class="drawer-body">
      <section>
        <h3>분류</h3>
        <dl class="kv">
          <dt>심각도</dt><dd>${esc(dash(detail.severity))}</dd>
          <dt>유형</dt><dd>${esc(dash(detail.vuln_type))}</dd>
          <dt>CVE</dt><dd>${esc((detail.cve_ids || []).join(", ") || "—")}</dd>
          <dt>CWE</dt><dd>${esc((detail.cwe_ids || []).join(", ") || "—")}</dd>
          <dt>태그</dt><dd>${esc((detail.tags || []).join(", ") || "—")}</dd>
        </dl>
      </section>
      ${detail.unsupported_fields?.length ? `
        <section>
          <h3>빌더 미지원 문법</h3>
          <div class="coverage" style="border-left-color:var(--warn)">
            폼으로 편집하면 아래 항목이 유실됩니다. YAML 을 직접 수정하세요.
            <div class="mono" style="margin-top:6px;color:var(--text)">
              ${esc(detail.unsupported_fields.join(", "))}</div>
          </div>
        </section>` : ""}
      <section>
        <h3>YAML</h3>
        <pre class="evidence" style="max-height:340px">${esc(detail.yaml || "")}</pre>
      </section>
      <section>
        <h3>동작</h3>
        <div class="actions">
          ${detail.source === "custom"
            ? `<button class="sm" data-tpl-edit="${esc(detail.template_id)}">폼으로 편집</button>
               <button class="sm danger" data-tpl-delete="${esc(detail.template_id)}">삭제</button>`
            : `<button class="sm" data-tpl-fork="${esc(detail.template_id)}">사본 만들어 편집</button>
               <p style="color:var(--faint);font-size:12px;margin:8px 0 0">
                 공식 템플릿은 수정·삭제할 수 없습니다.</p>`}
        </div>
      </section>
    </div>`;
  document.body.appendChild(node);
}

/* ------------------------------------------------- 이벤트 (app.js 위임) */

export async function handleTemplateClick(target) {
  const action = target.closest("[data-tpl]")?.dataset.tpl;
  const add = target.closest("[data-tpl-add]")?.dataset.tplAdd;
  const remove = target.closest("[data-tpl-remove]");
  const open = target.closest("[data-tpl-open]")?.dataset.tplOpen;
  const edit = target.closest("[data-tpl-edit]")?.dataset.tplEdit;
  const del = target.closest("[data-tpl-delete]")?.dataset.tplDelete;
  const forkId = target.closest("[data-tpl-fork]")?.dataset.tplFork;

  if (add) {
    const spec = state.schema.sections.find((s) => s.key === add);
    const container = document.querySelector(`[data-groups="${add}"]`);
    container.insertAdjacentHTML("beforeend", groupHtml(spec, container.children.length));
    return true;
  }
  if (remove) {
    const group = remove.closest("[data-group]");
    const container = group.parentElement;
    // 최소 1개는 남긴다. 스키마의 min_items 를 화면에서도 지킨다
    if (container.children.length > 1) group.remove();
    else toast("최소 1개는 필요합니다", "err");
    return true;
  }
  if (open) { await openTemplate(open); return true; }

  if (edit) {
    const detail = await api.getTemplate(edit);
    state.editing = edit;
    document.querySelector(".drawer")?.remove();
    await viewTemplates();
    if (detail.form) fillForm(detail.form);
    if (detail.unsupported_fields?.length) {
      toast(`미지원 문법 ${detail.unsupported_fields.length}건은 폼에 반영되지 않습니다`, "err");
    }
    return true;
  }
  if (del) {
    if (!confirm(`${del} 을 삭제합니다. 계속할까요?`)) return true;
    await api.deleteTemplate(del);
    document.querySelector(".drawer")?.remove();
    toast("삭제했습니다");
    await viewTemplates();
    return true;
  }
  if (forkId) {
    const newId = prompt("새 템플릿 ID (소문자·숫자·하이픈)", `${forkId}-copy`.toLowerCase());
    if (!newId) return true;
    await api.forkTemplate(forkId, newId);
    document.querySelector(".drawer")?.remove();
    toast("사본을 만들었습니다");
    state.editing = newId;
    await viewTemplates();
    const detail = await api.getTemplate(newId);
    if (detail.form) fillForm(detail.form);
    return true;
  }

  switch (action) {
    case "reindex": {
      const result = await api.reindexTemplates();
      toast(`색인 완료 · 공식 ${result.indexed.official} · 직접 작성 ${result.indexed.custom}`);
      await viewTemplates();
      return true;
    }
    case "sync": {
      const result = await api.syncTemplates();
      toast(`갱신 ${result.added}개 추가 · ${result.updated}개 유지`);
      await viewTemplates();
      return true;
    }
    case "preview": await preview(); return true;
    case "save": await save(); return true;
    case "dryrun": await dryrun(); return true;
    case "cancel-edit":
      state.editing = null;
      await viewTemplates();
      return true;
    case "close":
      document.querySelector(".drawer")?.remove();
      return true;
    default:
      return false;
  }
}

export async function handleTemplateChange(node) {
  const key = node.dataset?.tplFilter;
  if (!key) return false;
  filters[key] = node.value;
  await viewTemplates();
  return true;
}

export { ApiError };
