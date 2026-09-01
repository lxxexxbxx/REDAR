/* LLM 조치 가이드 화면.
 *
 * 보고서 -> 프롬프트(로컬 생성) -> 대화 -> 조치 가이드(Markdown)
 * 프롬프트 생성은 통신이 없어 오프라인에서도 됨. 복사해 외부 LLM 에 붙여도 됨
 * 채팅 전송은 보내기 직전에 사용자 확인을 받음 (docs/01 §7.1)
 */
import { api, ApiError } from "./api.js";
import { confirmDialog, esc, fmtTime, scanTargets, toast } from "./ui.js";
import * as tasks from "./tasks.js";

const state = {
  status: null, reports: [], reportId: null, prompt: "", chat: [], pending: false,
};

export function remediationEnabled(status) {
  return Boolean(status?.feature_enabled);
}

export async function viewRemediation(view) {
  state.status = await api.remediationStatus();
  const listed = await api.listReports({ size: 50 });
  state.reports = listed.items.filter((r) => r.status === "completed");

  view.innerHTML = `
    <div class="view-head">
      <div class="eyebrow">LLM 활용</div>
      <h1>조치 가이드</h1>
      <p>보고서를 골라 프롬프트를 만들고, 그 프롬프트로 조치 절차를 받아 봄.
         보고서 본문은 이 기능의 결과에 영향받지 않음 — 보고서는 LLM 을 쓰지 않음</p>
    </div>

    ${state.status.blocked_reason ? `
      <div class="coverage" style="border-left-color:var(--warn)">
        <strong>일부 기능 제한</strong> ${esc(state.status.blocked_reason)}
        <div style="margin-top:6px;color:var(--faint)">
          프롬프트 생성은 통신이 없어 지금도 가능. 앱 안에서 대화하려면 위 항목 필요
        </div>
        <div class="cta"><button class="sm" data-go="settings">설정으로 이동</button></div>
      </div>` : ""}

    <div class="panel">
      <div class="panel-head">
        <div class="eyebrow">1단계</div>
        <h2>보고서 선택</h2>
      </div>
      ${state.reports.length ? `
        <label class="field">
          <span>완성된 보고서</span>
          <select id="rem-report">
            ${state.reports.map((r) => `
              <option value="${esc(r.report_id)}">${esc(scanTargets(r))} · ${
                esc(fmtTime(r.generated_at || r.created_at))
              }</option>`).join("")}
          </select>
        </label>
        <div class="actions">
          <button class="primary" data-rem="prompt">프롬프트 만들기</button>
          <span style="color:var(--faint);font-size:12px">통신 없음 · 즉시 생성</span>
        </div>` : `
        <div class="hintbox">
          <b>완성된 보고서 없음</b>
          <small>보고서 화면에서 먼저 생성 필요</small>
          <div class="cta"><button class="sm" data-go="report">보고서로 이동</button></div>
        </div>`}
    </div>

    <div id="rem-prompt"></div>
    <div id="rem-chat"></div>`;

  if (state.prompt) renderPrompt();
  if (state.chat.length) renderChat();
}

function renderPrompt() {
  document.getElementById("rem-prompt").innerHTML = `
    <div class="panel">
      <div class="panel-head spread">
        <div>
          <div class="eyebrow">2단계 · 통신 없이 로컬 생성</div>
          <h2>프롬프트</h2>
        </div>
        <div class="row">
          <button class="sm" data-rem="copy">복사</button>
        </div>
      </div>
      <p class="lede">이 프롬프트를 그대로 아래 대화창에 보내거나, 복사해서 외부 LLM 에
         붙여도 됨. 같은 보고서면 항상 같은 프롬프트가 나옴</p>
      <pre class="promptbox" id="rem-prompt-text">${esc(state.prompt)}</pre>
      <div class="actions">
        <button class="primary" data-rem="send">이 프롬프트로 가이드 받기</button>
        <span style="color:var(--faint);font-size:12px">보내기 전 확인창 표시</span>
      </div>
    </div>`;
}

function renderChat() {
  const host = document.getElementById("rem-chat");
  host.innerHTML = `
    <div class="panel chatpanel">
      <div class="panel-head spread">
        <div><h2>조치 가이드</h2></div>
        <div class="row">
          <span class="chip">${esc(state.status?.model || "-")}</span>
          <button class="sm ghost" data-rem="copy-guide">가이드 복사</button>
          <button class="sm ghost" data-rem="reset">대화 지우기</button>
        </div>
      </div>

      <div class="chatlog" id="rem-log">
        ${state.chat.map(bubble).join("")}
        ${state.pending ? `
          <div class="bubble-row from-them">
            <div class="bubble typing"><span></span><span></span><span></span></div>
          </div>` : ""}
      </div>

      <div class="chatbar">
        <textarea id="rem-input" rows="1"
          placeholder="추가 질문 · Enter 전송, Shift+Enter 줄바꿈"></textarea>
        <button class="primary" data-rem="ask"${state.pending ? " disabled" : ""}>전송</button>
      </div>
    </div>`;

  const log = document.getElementById("rem-log");
  log.scrollTop = log.scrollHeight;          // 항상 마지막 말풍선이 보이도록

  const input = document.getElementById("rem-input");
  input.addEventListener("keydown", onChatKey);
  input.addEventListener("input", autoGrow);
  if (!state.pending) input.focus();
}

/* 말풍선. 보낸 쪽은 오른쪽, 받은 쪽은 왼쪽 */
function bubble(message) {
  const mine = message.role === "user";
  return `<div class="bubble-row ${mine ? "from-me" : "from-them"}">
    <div class="bubble">${
      mine ? `<pre>${esc(message.content)}</pre>`
           : `<div class="guide">${markdown(message.content)}</div>`
    }</div>
  </div>`;
}

function onChatKey(event) {
  // Enter 전송이 대화형의 기본. 줄바꿈은 Shift 조합
  if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
  event.preventDefault();
  document.querySelector('[data-rem="ask"]')?.click();
}

function autoGrow(event) {
  const box = event.target;
  box.style.height = "auto";
  box.style.height = `${Math.min(box.scrollHeight, 180)}px`;
}

/* 최소 Markdown 렌더. 라이브러리를 넣지 않는다 (빌드 도구 없음 · 외부 참조 0).
 * 입력은 LLM 응답이라 신뢰할 수 없으므로 먼저 전부 이스케이프한 뒤 서식만 되살림 */
export function markdown(text) {
  const lines = esc(text || "").split("\n");
  const out = [];
  let inCode = false;
  let listOpen = false;

  const closeList = () => {
    if (listOpen) { out.push("</ul>"); listOpen = false; }
  };

  for (const line of lines) {
    if (line.trim().startsWith("```")) {
      closeList();
      out.push(inCode ? "</code></pre>" : '<pre class="codeblock"><code>');
      inCode = !inCode;
      continue;
    }
    if (inCode) { out.push(line); continue; }

    const heading = /^(#{1,4})\s+(.*)$/.exec(line);
    if (heading) {
      closeList();
      const level = Math.min(heading[1].length + 1, 5);
      out.push(`<h${level}>${inline(heading[2])}</h${level}>`);
      continue;
    }
    const item = /^\s*(?:[-*]|\d+\.)\s+(.*)$/.exec(line);
    if (item) {
      if (!listOpen) { out.push("<ul>"); listOpen = true; }
      out.push(`<li>${inline(item[1])}</li>`);
      continue;
    }
    if (!line.trim()) { closeList(); continue; }
    closeList();
    out.push(`<p>${inline(line)}</p>`);
  }
  if (inCode) out.push("</code></pre>");
  closeList();
  return out.join("\n");
}

function inline(text) {
  return text
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
}

async function copy(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${label} 복사됨`);
  } catch {
    // Tauri WebView 에서 클립보드가 막힐 수 있음. 선택 상태로 만들어 수동 복사 유도
    const box = document.getElementById("rem-prompt-text");
    if (box) {
      const range = document.createRange();
      range.selectNodeContents(box);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
    }
    toast("복사 권한 없음. 선택된 영역을 직접 복사", "err");
  }
}

async function send(content) {
  const ok = await confirmDialog({
    title: "LLM 에 전송",
    body: "아래 내용이 MonoGPT API 로 전송됨 — <b>외부 통신 발생</b>.<br>"
        + `${state.status?.masked ? "호스트·IP·경로는 <b>치환</b>되어 나가고 응답에서 되돌려짐. "
            : "<b>치환이 꺼져 있어 실제 호스트·경로가 그대로 전송됨.</b> "}`
        + "요청·응답 원문과 추출값은 포함되지 않음",
    confirmLabel: "전송",
  });
  if (!ok) { toast("전송 취소됨"); return; }

  state.chat.push({ role: "user", content });
  state.pending = true;                     // 응답 대기 표시 (말풍선 애니메이션)
  renderChat();
  try {
    const reply = await tasks.track(
      "조치 가이드 생성", state.status?.model || "LLM",
      () => api.remediationChat(state.chat, true),
    );
    state.chat.push({ role: "assistant", content: reply.content });
  } catch (error) {
    // 실패한 질문은 대화에 남기지 않음. 다음 전송에 그대로 재전송됨
    state.chat.pop();
    if (error instanceof ApiError) toast(`${error.code}: ${error.message}`, "err");
    else toast("전송 실패", "err");
  } finally {
    state.pending = false;
  }
  renderChat();
}

export async function handleRemediationClick(target, rerender) {
  const action = target.closest("[data-rem]")?.dataset.rem;
  if (!action) return false;

  if (action === "prompt") {
    state.reportId = document.getElementById("rem-report").value;
    const built = await tasks.track(
      "프롬프트 생성", state.reportId, () => api.remediationPrompt(state.reportId),
    );
    state.prompt = built.prompt;
    state.chat = [];
    renderPrompt();
    document.getElementById("rem-chat").innerHTML = "";
    return true;
  }
  if (action === "copy") { await copy(state.prompt, "프롬프트"); return true; }
  if (action === "send") { await send(state.prompt); return true; }
  if (action === "ask") {
    const box = document.getElementById("rem-input");
    const text = box.value.trim();
    if (!text) { toast("보낼 내용 입력 필요", "err"); return true; }
    box.value = "";
    await send(text);
    return true;
  }
  if (action === "copy-guide") {
    const last = [...state.chat].reverse().find((m) => m.role === "assistant");
    if (last) await copy(last.content, "가이드");
    return true;
  }
  if (action === "reset") {
    state.chat = [];
    document.getElementById("rem-chat").innerHTML = "";
    return true;
  }
  return false;
}
