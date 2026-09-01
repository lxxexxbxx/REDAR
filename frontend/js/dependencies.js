/* 의존성 관리 화면 조각.
 *
 * 세 경로를 모두 제공. 폐쇄망에서도 도구를 쓸 수 있어야 함
 *   자동 설치  외부 통신 4번. 기본 비활성 + 사용자 확인 필요
 *   파일 반입  통신 없음. 오프라인에서도 동작
 *   경로 지정  통신 없음. 특정 버전을 고정할 때 */
import { api } from "./api.js";
import { confirmDialog, esc, dash, toast } from "./ui.js";
import * as tasks from "./tasks.js";

const SOURCE_LABEL = {
  configured: "설정에서 지정",
  installed: "설치·반입됨",
  detected: "자동 탐색",
  path: "PATH",
};

/* 설정 화면의 의존성 패널 */
export function dependencyPanel(state) {
  if (!state) {
    return `<p class="empty" style="margin:0">의존성 정보를 불러오지 못했습니다.</p>`;
  }
  return `
    ${state.items.map(dependencyRow).join("")}
    <p style="color:var(--faint);font-size:12px;margin:12px 0 0">
      자동 설치는 Go 툴체인을 내려받아 직접 빌드합니다. 외부 통신이 발생하므로
      설정에서 <strong>의존성 자동 설치</strong> 를 켜야 하고, 오프라인 모드에서는 막힙니다.
      인터넷이 없는 환경이면 <strong>파일 반입</strong> 을 쓰세요.
    </p>`;
}

function dependencyRow(item) {
  return `
    <div style="border-left:2px solid ${item.available ? "var(--ok)" : "var(--warn)"};
                padding-left:14px;margin-bottom:16px">
      <div class="row" style="justify-content:space-between">
        <div>
          <b>${esc(item.label)}</b>
          ${item.available
            ? `<span class="chip strong">${esc(dash(item.version))}</span>`
            : '<span class="chip">미설치</span>'}
        </div>
      </div>
      <p style="color:var(--muted);font-size:12.5px;margin:4px 0 6px">
        ${esc(item.required_for)}</p>
      <dl class="kv" style="margin:0 0 8px">
        <dt>경로</dt><dd class="mono">${esc(dash(item.path))}</dd>
        <dt>출처</dt><dd>${esc(SOURCE_LABEL[item.source] || "없음")}</dd>
      </dl>

      <label class="field">
        <span>경로 직접 지정 · 특정 버전 고정</span>
        <input type="text" data-dep-path="${esc(item.key)}"
               value="${esc(item.source === "configured" ? item.path : "")}"
               placeholder="${esc(item.import_dir)}/${esc(item.label)}">
      </label>
      <div class="actions">
        <button class="sm" data-dep-save="${esc(item.key)}">경로 저장</button>
        <button class="sm ghost" data-dep-clear="${esc(item.key)}">지정 해제</button>
        <button class="sm" data-dep-import="${esc(item.key)}">파일 반입</button>
        ${item.installable ? `
          <button class="sm" data-dep-install="${esc(item.key)}">자동 설치</button>` : ""}
        <input type="file" data-dep-file="${esc(item.key)}" class="sr-only">
      </div>
      <p style="color:var(--faint);font-size:12px;margin:6px 0 0">
        직접 받으려면 <span class="mono">${esc(item.manual_url)}</span> 에서 내려받아
        <span class="mono">${esc(item.import_dir)}</span> 에 두거나 위에서 반입하세요.
      </p>
    </div>`;
}

/* nuclei 가 없을 때 대시보드 상단에 띄우는 안내 */
export function missingDependencyNotice(state) {
  if (!state) return "";
  const missing = state.items.filter((i) => !i.available);
  if (!missing.length) return "";

  return `
    <div class="coverage" style="border-left-color:var(--brand)">
      <strong>${esc(missing.map((m) => m.label).join(", "))} 없음</strong>
      탐지에 반드시 필요하므로 먼저 준비 필요
      <div style="margin-top:8px;color:var(--faint)">
        ${state.install_allowed
          ? "자동 설치 또는 직접 내려받아 반입 가능"
          : esc(state.blocked_reason || "")}
      </div>
      <div class="actions">
        ${missing.map((m) => m.installable ? `
          <button class="sm" data-dep-install="${esc(m.key)}">${esc(m.label)} 자동 설치</button>
        ` : "").join("")}
        <button class="sm ghost" data-go="settings">설정에서 직접 지정</button>
      </div>
    </div>`;
}

/* ------------------------------------------------------------ 동작 */

export async function handleDependencyClick(target, refresh) {
  const save = target.closest("[data-dep-save]")?.dataset.depSave;
  const clear = target.closest("[data-dep-clear]")?.dataset.depClear;
  const pick = target.closest("[data-dep-import]")?.dataset.depImport;
  const install = target.closest("[data-dep-install]")?.dataset.depInstall;

  if (save) {
    const value = document.querySelector(`[data-dep-path="${save}"]`).value.trim();
    await api.setDependencyPath(save, value || null);
    toast(value ? "경로를 지정했습니다." : "지정을 해제했습니다.");
    await refresh();
    return true;
  }
  if (clear) {
    await api.setDependencyPath(clear, null);
    toast("지정을 해제했습니다.");
    await refresh();
    return true;
  }
  if (pick) {
    document.querySelector(`[data-dep-file="${pick}"]`).click();
    return true;
  }
  if (install) {
    // 설정만으로 자동 실행되지 않음. 사용자가 매번 동의함
    const agreed = await confirmDialog({
      title: `${install} 자동 설치`,
      body: "Go 툴체인을 내려받아 직접 빌드합니다. <b>외부 통신이 발생</b>하고 수 분 걸립니다.<br><br>"
          + "인터넷이 없는 환경이면 대신 <b>파일 반입</b> 을 쓰세요.",
      confirmLabel: "설치",
    });
    if (!agreed) return true;
    toast("설치를 시작했습니다. 수 분 걸립니다.");
    await tasks.track(
      `${install} 자동 설치`, "Go 툴체인 확보 후 빌드 · 수 분 소요",
      () => api.installDependency(install, true),
    );
    toast(`${install} 설치를 완료했습니다.`);
    await refresh();
    return true;
  }
  return false;
}

export async function handleDependencyChange(node, refresh) {
  const key = node.dataset?.depFile;
  if (!key) return false;
  const file = node.files?.[0];
  if (!file) return true;
  await tasks.track(
    `${key} 파일 반입`, `${file.name} 검증 중`,
    () => api.importDependency(key, file),
  );
  toast("반입을 완료했습니다.");
  await refresh();
  return true;
}
