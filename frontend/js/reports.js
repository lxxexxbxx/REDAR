/* 보고서 화면.
 *
 * 미리보기는 Report JSON 을 그대로 사용. 화면이 DB 를 다시 조회하면 파일 산출물과
 * 갈라짐 (docs/04 §3). PDF 는 브라우저 인쇄로 파생 (절대규칙 4-1) */
import { api } from "./api.js";
import {
  confirmDialog, esc, dash, fmtTime, scanTargets, toast,
} from "./ui.js";
import * as tasks from "./tasks.js";
import { generateAndAttachGuide, sendConfirmBody } from "./remediation.js";

const view = () => document.getElementById("view");

/* LLM 조치 가이드 동시 생성 옵션. 기능이 꺼져 있으면 항목 자체가 없음 (메뉴와 같은 조건)
 * 전송이 막혀 있으면 비활성으로 두고 무엇을 켜야 하는지 알려줌 */
function guideToggle(status) {
  if (!status?.feature_enabled) return "";
  const blocked = status.blocked_reason;
  return `<div class="toggle">
      <input type="checkbox" id="rpt-guide"${blocked ? " disabled" : ""}>
      <span class="t-body"><b>LLM 조치 상세 가이드 포함 (4절)</b>
        <small>${blocked
          ? `지금은 사용할 수 없습니다 · ${esc(blocked)} · <a href="#/settings">설정으로 이동</a>`
          : "보고서를 만든 뒤 조치 가이드 메뉴와 같은 순서(프롬프트 → LLM → 첨부)로 4절을 "
            + "채웁니다. 외부 통신이 발생하며, 4절에는 LLM 이 작성했다는 사실과 조치 책임이 "
            + "사용자에게 있다는 고지가 함께 실립니다."}</small></span>
    </div>`;
}

const VERDICT_LABEL = { safe: "양호", vulnerable: "취약", not_applicable: "해당 없음" };

/* ------------------------------------------------------------ 화면 */

export async function viewReport() {
  const [{ items: scans }, { items: reports }, remediation] = await Promise.all([
    api.listScans({ size: 50 }),
    api.listReports({ size: 50 }),
    // 상태 조회 실패가 보고서 화면을 막지 않음. 옵션만 숨김
    api.remediationStatus().catch(() => null),
  ]);
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
        ${guideToggle(remediation)}
        <p style="color:var(--faint);font-size:12px;margin:10px 0 0">
          보고서 본문(1~3절)은 LLM 을 쓰지 않습니다. 같은 스캔에 항상 같은 보고서가 나와야
          근거 대조가 가능하므로 문장까지 전부 사전 정의값입니다. LLM 은 선택했을 때
          4절 조치 상세 가이드에만 쓰입니다.
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
    </div>`;
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
        <h3>조치 상세 가이드 (4절)</h3>
        ${report.llm_remediation_guide ? `
          <p style="margin:0">LLM 생성 가이드가 첨부되어 있습니다 ·
            <span class="mono">${esc(dash(report.llm_remediation_guide.model))}</span></p>
          <p style="color:var(--faint);font-size:12px;margin:6px 0 0">
            해당 절에는 LLM 이 작성한 내용이라는 사실과, 조치 수행과 그 결과의 책임이
            사용자에게 있다는 고지가 함께 실립니다. 본문 1~3절은 영향받지 않습니다.
          </p>` : `
          <p style="margin:0;color:var(--muted)">첨부되지 않았습니다.
            절은 안내 문구로 남습니다.</p>
          <div class="actions">
            <button class="sm" data-go="remediation">조치 가이드로 이동</button>
          </div>`}
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
      const guideBox = document.getElementById("rpt-guide");
      let withGuide = Boolean(guideBox?.checked && !guideBox.disabled);
      let status = null;
      if (withGuide) {
        status = await api.remediationStatus();
        // 외부 전송 직전 확인 1회. 취소하면 조치 가이드 없이 보고서만 만듦
        withGuide = await confirmDialog({
          title: "보고서 생성 + LLM 조치 가이드",
          body: `${sendConfirmBody(status, "보고서로 만든 프롬프트를")}<br><br>`
              + "취소하면 조치 가이드 없이 보고서만 만듭니다.",
          confirmLabel: "전송하고 생성",
        });
      }

      const created = await tasks.track(
        "보고서 생성", scanId,
        () => api.createReport(scanId, {
          include_evidence: document.getElementById("rpt-evidence").checked,
        }),
      );
      if (!withGuide) {
        toast(`보고서를 만들었습니다 · ${created.files.join(", ")}`);
        await viewReport();
        return true;
      }

      try {
        await generateAndAttachGuide(created.report_id, status);
        toast("보고서를 만들고 조치 가이드를 4절에 첨부했습니다.");
      } catch (error) {
        // 보고서는 이미 완성품. 4절은 '미생성' 으로 남음 (절대규칙 2)
        toast(`조치 가이드를 만들지 못했습니다 (${error?.code || "오류"}). `
          + "보고서는 생성되었으니 조치 가이드 메뉴에서 다시 시도하세요.", "err");
      }
      await viewReport();
      return true;
    }
    case "close":
      document.querySelector(".drawer")?.remove();
      return true;
    default:
      return false;
  }
}
