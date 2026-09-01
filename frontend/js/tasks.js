/* 진행 중 작업 표시 도크.
 *
 * 오래 걸리는 작업(템플릿 갱신·스캔·의존성 설치)이 화면 전환에 묻혀 멈춘 것처럼
 * 보인다는 피드백. 화면과 무관하게 하단에 남아 무엇이 돌고 있는지 항상 보여줌
 * 접기 상태는 사용자가 고른 대로 유지
 */
import { esc } from "./ui.js";

const tasks = new Map();
let seq = 0;
let collapsed = false;
let sweepTimer = null;

/* 끝난 작업을 남겨두는 시간. 결과를 볼 틈 없이 사라지면 토스트와 다를 바 없음 */
const KEEP_DONE_MS = 20000;

export function begin(label, detail = "", { onCancel } = {}) {
  const id = `task-${++seq}`;
  tasks.set(id, {
    id, label, detail, state: "run", percent: null, at: Date.now(), onCancel,
  });
  collapsed = false;                  // 새 작업이 시작되면 펼쳐서 보여줌
  render();
  return id;
}

/* 로그 보기·저장은 도크 공통 동작. app.js 가 구현을 넣어준다
 * (tasks -> app 방향 import 를 만들지 않기 위함) */
const hooks = { onShowLog: null, onSaveLog: null };

export function setLogHooks({ onShowLog, onSaveLog }) {
  hooks.onShowLog = onShowLog;
  hooks.onSaveLog = onSaveLog;
}

export function update(id, patch) {
  const task = tasks.get(id);
  if (!task) return;
  Object.assign(task, patch);
  render();
}

export function done(id, detail = "완료") {
  finish(id, "done", detail);
}

export function fail(id, detail = "실패") {
  finish(id, "fail", detail);
}

function finish(id, state, detail) {
  const task = tasks.get(id);
  if (!task) return;
  Object.assign(task, { state, detail, percent: null, at: Date.now() });
  render();
  scheduleSweep();
}

function scheduleSweep() {
  clearTimeout(sweepTimer);
  sweepTimer = setTimeout(() => {
    const cutoff = Date.now() - KEEP_DONE_MS;
    for (const [id, task] of tasks) {
      if (task.state !== "run" && task.at < cutoff) tasks.delete(id);
    }
    render();
    if ([...tasks.values()].some((t) => t.state !== "run")) scheduleSweep();
  }, 2000);
}

const running = () => [...tasks.values()].filter((t) => t.state === "run");

function row(task) {
  const mark = { run: "…", done: "완료", fail: "실패" }[task.state];
  const cancellable = task.state === "run" && task.onCancel;
  return `<div class="task task-${task.state}">
    <div class="task-head">
      <b>${esc(task.label)}</b>
      ${cancellable
        ? `<button class="task-cancel" data-dock="cancel"
                   data-task="${esc(task.id)}">중단</button>`
        : ""}
      <span class="task-mark">${esc(mark)}</span>
    </div>
    ${task.detail ? `<small>${esc(task.detail)}</small>` : ""}
    ${task.state === "run" ? `<div class="task-bar${
      task.percent === null || task.percent === undefined ? " sweep" : ""
    }"><div style="width:${task.percent ?? 0}%"></div></div>` : ""}
  </div>`;
}

function render() {
  const host = document.getElementById("taskdock");
  if (!host) return;

  if (!tasks.size) {
    host.innerHTML = "";
    host.hidden = true;
    return;
  }
  host.hidden = false;

  const runCount = running().length;
  const summary = runCount
    ? `진행 중 ${runCount}건`
    : `최근 작업 ${tasks.size}건`;

  host.innerHTML = `
    <button class="dock-toggle" data-dock="toggle"
            aria-expanded="${collapsed ? "false" : "true"}">
      <span class="dock-dot${runCount ? " on" : ""}"></span>
      <span>${esc(summary)}</span>
      <span class="dock-caret">${collapsed ? "▲" : "▼"}</span>
    </button>
    ${collapsed ? "" : `<div class="dock-body">${
      [...tasks.values()].reverse().map(row).join("")
    }</div>
    <div class="dock-foot">
      <button class="sm ghost" data-dock="log">로그 보기</button>
      <button class="sm ghost" data-dock="save">로그 저장</button>
    </div>`}`;
}

/* 도크 클릭 처리. app.js 의 전역 핸들러가 호출 */
export function handleDockClick(target) {
  const action = target.closest("[data-dock]")?.dataset.dock;
  if (!action) return false;

  if (action === "toggle") {
    collapsed = !collapsed;
    render();
    return true;
  }
  if (action === "log") { hooks.onShowLog?.(); return true; }
  if (action === "save") { hooks.onSaveLog?.(); return true; }
  if (action === "cancel") {
    const id = target.closest("[data-task]")?.dataset.task;
    const task = tasks.get(id);
    if (task?.onCancel) {
      update(id, { detail: "중단 요청됨" });
      Promise.resolve(task.onCancel()).catch(() => fail(id, "중단 실패"));
    }
    return true;
  }
  return false;
}

/* 작업으로 감싸 실행. 성공·실패 표시를 빠뜨리지 않게 함 */
export async function track(label, detail, fn) {
  const id = begin(label, detail);
  try {
    const result = await fn(id);
    done(id, typeof result === "string" ? result : "완료");
    return result;
  } catch (error) {
    fail(id, error?.message || "실패");
    throw error;
  }
}
