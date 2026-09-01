/* 보고서 화면 + 스캔 비교.
 *
 * 미리보기는 Report JSON 을 그대로 사용. 화면이 DB 를 다시 조회하면 파일 산출물과
 * 갈라짐 (docs/04 §3). PDF 는 브라우저 인쇄로 파생 (절대규칙 4-1) */
import { api } from "./api.js";
import {
  confirmDialog, esc, dash, fmtTime, scanTargets, toast, SEVERITY_LABEL,
} from "./ui.js";
import * as tasks from "./tasks.js";

const view = () => document.getElementById("view");

const VERDICT_LABEL = { safe: "양호", vulnerable: "취약", not_applicable: "해당 없음" };
const COMPARE_LABEL = { resolved: "미탐지", persisted: "지속 탐지", emerged: "신규 탐지" };

const state = { scans: [], reports: [], compare: null, selected: null };

/* ------------------------------------------------------------ 화면 */

export async function viewReport() {
  const [{ items: scans }, { items: reports }] = await Promise.all([
    api.listScans({ size: 50 }),
    api.listReports({ size: 50 }),
  ]);
  state.scans = scans;
  state.reports = reports;

  view().innerHTML = `
    <div class="view-head">
      <h1>보고서</h1>
      <p>보고서는 대상이 무엇이든 항상 같은 목차로 만들어집니다. 탐지 0건인 항목도
         사라지지 않고 "해당 없음" 으로 남습니다.</p>
    </div>

    <div class="panel">
      <div class="panel-head">
        <h2>새 보고서</h2>
      </div>
      ${scans.length ? `
        <label class="field">
          <span>대상 스캔</span>
          <select id="rpt-scan">
            ${scans.map((s) => `<option value="${esc(s.scan_id)}">
              ${esc(scanTargets(s))} ·
              ${esc(fmtTime(s.started_at || s.created_at))}</option>`).join("")}
          </select>
        </label>
        <div class="toggle">
          <input type="checkbox" id="rpt-evidence" checked>
          <span class="t-body"><b>탐지 근거 포함</b>
            <small>요청·응답 원문을 보고서에 넣습니다. 민감 정보가 섞일 수 있으니 공유 전에 확인하세요.</small></span>
        </div>
        <p style="color:var(--faint);font-size:12px;margin:10px 0 0">
          보고서는 LLM 을 쓰지 않습니다. 같은 스캔에 항상 같은 보고서가 나와야 근거
          대조가 가능하므로 문장까지 전부 사전 정의값입니다. 조치 절차를 LLM 으로
          받아 보시려면 <b>조치 가이드</b> 메뉴를 쓰세요.
        </p>
        <div class="actions">
          <button class="primary" data-rpt="create">보고서 생성</button>
        </div>` : `
        <div class="empty">
          <h2>보고서를 만들 스캔 없음</h2>
          <p>스캔을 먼저 실행하거나 외부 결과를 가져오세요.</p>
          <div class="cta"><button class="primary" data-go="scan">스캔 실행</button></div>
        </div>`}
    </div>

    <div class="panel">
      <div class="panel-head">
        <h2>생성된 보고서 ${reports.length}건</h2>
      </div>
      ${reports.length ? reportTable(reports) : `
        <p class="empty" style="margin:0">아직 생성된 보고서가 없습니다.</p>`}
    </div>

    <div class="panel">
      <div class="panel-head">
        <h2>스캔 비교</h2>
      </div>
      <p style="color:var(--muted);margin:0 0 12px">
        조치 전후 두 스캔의 차이만 보여 드립니다. 조치 성공 여부는 도구가 판정하지 않으며,
        비교 결과는 보고서에 실리지 않습니다.
      </p>
      ${scans.length >= 2 ? `
        <div class="row" style="align-items:flex-start">
          <label class="field" style="flex:1">
            <span>기준 스캔 · 이전</span>
            <select id="cmp-base">${scanOptions(scans, 1)}</select>
          </label>
          <label class="field" style="flex:1">
            <span>비교 스캔 · 이후</span>
            <select id="cmp-target">${scanOptions(scans, 0)}</select>
          </label>
        </div>
        <div class="actions">
          <button data-rpt="compare">비교 실행</button>
        </div>` : `
        <p class="empty" style="margin:0">비교하려면 스캔이 2건 이상 필요합니다.</p>`}
      <div id="cmp-result">${state.compare ? compareResult(state.compare) : ""}</div>
    </div>`;
}

function scanOptions(scans, selectedIndex) {
  return scans.map((s, i) => `<option value="${esc(s.scan_id)}"${
    i === selectedIndex ? " selected" : ""}>
    ${esc(scanTargets(s))} · ${esc(fmtTime(s.started_at || s.created_at))}
  </option>`).join("");
}

function reportTable(reports) {
  return `<table>
    <thead><tr>
      <th>보고서 ID</th><th>생성</th><th>가이드</th><th>LLM</th><th>파일</th><th></th>
    </tr></thead>
    <tbody>${reports.map((r) => `
      <tr>
        <td class="mono" style="font-size:11.5px">${esc(r.report_id)}</td>
        <td class="mono nowrap">${esc(fmtTime(r.generated_at))}</td>
        <td>${r.guide_db_available ? "탑재" : "미탑재"}</td>
        <td>${r.llm_used ? "사용" : "미사용"}</td>
        <td class="nowrap">
          <button class="sm" data-rpt-open="${esc(r.report_id)}">미리보기</button>
          <button class="sm" data-rpt-html="${esc(r.report_id)}">HTML</button>
          <button class="sm ghost" data-rpt-json="${esc(r.report_id)}">JSON</button>
        </td>
        <td><button class="sm danger" data-rpt-delete="${esc(r.report_id)}">삭제</button></td>
      </tr>`).join("")}
    </tbody></table>`;
}

function compareResult(result) {
  const rows = ["resolved", "persisted", "emerged"];
  return `
    <table style="margin-top:14px">
      <thead><tr><th style="width:30mm">분류</th><th class="num" style="width:20mm">건수</th><th>설명</th></tr></thead>
      <tbody>
        <tr><td>미탐지</td><td class="num">${result.summary.resolved}</td>
            <td>이번 스캔에서 탐지되지 않음</td></tr>
        <tr><td>지속 탐지</td><td class="num">${result.summary.persisted}</td>
            <td>양쪽 모두에서 탐지</td></tr>
        <tr><td>신규 탐지</td><td class="num">${result.summary.emerged}</td>
            <td>이번 스캔에서 새로 탐지</td></tr>
      </tbody>
    </table>
    <div class="coverage" style="border-left-color:var(--warn)">${esc(result.disclaimer)}</div>
    ${rows.map((key) => `
      <h3 style="font-size:14px;margin:14px 0 6px">${COMPARE_LABEL[key]}
        (${result[key].length}건)</h3>
      ${result[key].length ? `<table>
        <thead><tr><th>탐지 항목</th><th style="width:22mm">심각도</th><th>대상</th></tr></thead>
        <tbody>${result[key].map((e) => `
          <tr><td>${esc(e.name)}</td>
              <td><span class="sev sev-${esc(e.severity)}">${esc(SEVERITY_LABEL[e.severity] || e.severity)}</span></td>
              <td class="mono">${esc(e.target_host)}</td></tr>`).join("")}
        </tbody></table>` : '<p class="empty" style="margin:0">해당 없음</p>'}`).join("")}
    ${environmentDiff(result.environment_diff)}`;
}

function environmentDiff(diff) {
  const total = diff.changed.length + diff.added.length + diff.removed.length;
  return `<h3 style="font-size:14px;margin:14px 0 6px">환경 변화 (${total}건)</h3>
    ${total ? `<table>
      <thead><tr><th>항목</th><th style="width:34mm">이전</th><th style="width:34mm">이후</th></tr></thead>
      <tbody>
        ${diff.changed.map((c) => `<tr><td class="mono">${esc(c.key)}</td>
          <td class="mono">${esc(String(c.before))}</td>
          <td class="mono">${esc(String(c.after))}</td></tr>`).join("")}
        ${diff.added.map((c) => `<tr><td class="mono">${esc(c.key)}</td>
          <td class="empty">-</td><td class="mono">${esc(String(c.after))}</td></tr>`).join("")}
        ${diff.removed.map((c) => `<tr><td class="mono">${esc(c.key)}</td>
          <td class="mono">${esc(String(c.before))}</td><td class="empty">-</td></tr>`).join("")}
      </tbody></table>`
      : '<p class="empty" style="margin:0">해당 없음</p>'}`;
}

/* ------------------------------------------------------ 미리보기 드로어 */

function previewDrawer(report) {
  const summary = report.executive_summary;
  const guide = report.guide_mapping;
  const node = document.createElement("aside");
  node.className = "drawer";
  node.innerHTML = `
    <div class="drawer-head">
      <div>
        <h2 style="margin-top:4px">${esc(report.meta.target_summary)}</h2>
        <div class="mono" style="color:var(--faint);font-size:11.5px;margin-top:4px">
          ${esc(report.report_id)}</div>
      </div>
      <button class="sm ghost" data-rpt="close">닫기</button>
    </div>
    <div class="drawer-body">
      <section>
        <h3>종합 의견</h3>
        <p style="margin:0">${esc(summary.narrative)}</p>
        <p style="color:var(--faint);font-size:12px;margin:6px 0 0">사전 정의 문장</p>
      </section>
      <section>
        <h3>집계</h3>
        <dl class="kv">
          <dt>총 탐지</dt><dd>${summary.total_findings}건</dd>
          ${report.findings_by_severity.map((s) =>
            `<dt>${esc(s.label)}</dt><dd>${s.count}건</dd>`).join("")}
        </dl>
      </section>
      <section>
        <h3>점검항목 판정</h3>
        <dl class="kv">
          ${Object.entries(guide.summary).map(([key, n]) =>
            `<dt>${esc(VERDICT_LABEL[key] || key)}</dt><dd>${n}건</dd>`).join("")}
        </dl>
        <div class="coverage">${esc(guide.coverage_notice)}</div>
      </section>
      <section>
        <h3>조치 사항</h3>
        <dl class="kv">
          <dt>안전 버전 업데이트</dt><dd>${report.patch_plan.length}건</dd>
          <dt>점검항목 조치</dt><dd>${report.remediation.length}건</dd>
          <dt>미매핑 탐지</dt><dd>${report.unmapped_findings.length}건</dd>
          <dt>오탐 제외</dt><dd>${report.false_positives.length}건</dd>
        </dl>
      </section>
      <section>
        <h3>PDF 로 저장</h3>
        <p style="margin:0;color:var(--muted)">HTML 을 열고 인쇄(Cmd/Ctrl+P) 에서
           <strong>PDF 로 저장</strong> 을 고르세요. 보고서 HTML 은 폰트까지 담고 있어
           파일 하나로 공유할 수 있습니다.</p>
        <div class="actions">
          <button class="sm" data-rpt-html="${esc(report.report_id)}">HTML 내려받기</button>
        </div>
      </section>
    </div>`;
  document.body.appendChild(node);
}

/* ------------------------------------------------------------ 동작 */

function download(blobText, filename, type) {
  const url = URL.createObjectURL(new Blob([blobText], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export async function handleReportClick(target) {
  const action = target.closest("[data-rpt]")?.dataset.rpt;
  const open = target.closest("[data-rpt-open]")?.dataset.rptOpen;
  const html = target.closest("[data-rpt-html]")?.dataset.rptHtml;
  const jsonId = target.closest("[data-rpt-json]")?.dataset.rptJson;
  const del = target.closest("[data-rpt-delete]")?.dataset.rptDelete;

  if (open) {
    const view = await api.getReport(open);
    document.querySelector(".drawer")?.remove();
    previewDrawer(view.report);
    return true;
  }
  if (html || jsonId) {
    const id = html || jsonId;
    const format = html ? "html" : "json";
    const { text, filename } = await api.downloadReport(id, format);
    download(text, filename, html ? "text/html" : "application/json");
    toast(`${filename} 을 내려받았습니다.`);
    return true;
  }
  if (del) {
    const ok = await confirmDialog({
      title: "보고서 삭제",
      body: "보고서와 생성된 파일을 함께 삭제합니다. 되돌릴 수 없습니다.",
      confirmLabel: "삭제",
      danger: true,
    });
    if (!ok) return true;
    await api.deleteReport(del);
    toast("삭제했습니다.");
    await viewReport();
    return true;
  }

  switch (action) {
    case "create": {
      const scanId = document.getElementById("rpt-scan").value;
      const created = await tasks.track(
        "보고서 생성", scanId,
        () => api.createReport(scanId, {
          include_evidence: document.getElementById("rpt-evidence").checked,
        }),
      );
      toast(`보고서를 만들었습니다 · ${created.files.join(", ")}`);
      await viewReport();
      return true;
    }
    case "compare": {
      const base = document.getElementById("cmp-base").value;
      const target2 = document.getElementById("cmp-target").value;
      if (base === target2) { toast("서로 다른 두 스캔을 고르세요.", "err"); return true; }
      state.compare = await api.compareScans(base, target2);
      document.getElementById("cmp-result").innerHTML = compareResult(state.compare);
      return true;
    }
    case "close":
      document.querySelector(".drawer")?.remove();
      return true;
    default:
      return false;
  }
}
