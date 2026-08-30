/* 백엔드 호출 래퍼.
 *
 * GUI 는 SQLite 직접 조회 없음. 모든 요청이 이 파일 경유 (docs/01 §2.1).
 * 오류는 전부 docs/00 §0.2 형식이므로 한 곳에서 해석
 */

const BASE = "/api/v1";

export class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message || `요청 실패 (${status})`);
    this.status = status;
    this.code = code || "INTERNAL_ERROR";
    this.details = details || [];
  }
}

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(BASE + path, {
      headers: options.body ? { "Content-Type": "application/json" } : {},
      ...options,
    });
  } catch (cause) {
    throw new ApiError(0, "OFFLINE", "백엔드 연결 실패");
  }

  if (response.status === 204) return null;

  const text = await response.text();
  const body = text ? JSON.parse(text) : null;

  if (!response.ok) {
    const error = (body && body.error) || {};
    throw new ApiError(response.status, error.code, error.message, error.details);
  }
  return body;
}

const query = (params) => {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, value);
  }
  const text = search.toString();
  return text ? `?${text}` : "";
};

export const api = {
  health: () => request("/health"),
  guideStatus: () => request("/guide/status"),

  settings: () => request("/settings"),
  saveSettings: (patch) =>
    request("/settings", { method: "PUT", body: JSON.stringify(patch) }),

  listScans: (params = {}) => request("/scans" + query(params)),
  getScan: (id) => request(`/scans/${encodeURIComponent(id)}`),
  createScan: (payload) =>
    request("/scans", { method: "POST", body: JSON.stringify(payload) }),
  cancelScan: (id) => request(`/scans/${encodeURIComponent(id)}/cancel`, { method: "POST" }),
  deleteScan: (id) => request(`/scans/${encodeURIComponent(id)}`, { method: "DELETE" }),

  scanEnvironment: (id) => request(`/scans/${encodeURIComponent(id)}/environment`),
  collectors: () => request("/collectors"),

  listFindings: (scanId, params = {}) =>
    request(`/scans/${encodeURIComponent(scanId)}/findings` + query(params)),
  getFinding: (id) => request(`/findings/${encodeURIComponent(id)}`),
  patchFinding: (id, payload) =>
    request(`/findings/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),

  dependencies: () => request("/dependencies"),
  setDependencyPath: (key, path) =>
    request(`/dependencies/${encodeURIComponent(key)}/path`, {
      method: "PUT", body: JSON.stringify({ path }),
    }),
  installDependency: (key, confirm) =>
    request(`/dependencies/${encodeURIComponent(key)}/install`, {
      method: "POST", body: JSON.stringify({ confirm }),
    }),
  importDependency: (key, file) => {
    const form = new FormData();
    form.append("file", file);
    return request(`/dependencies/${encodeURIComponent(key)}/import`, {
      method: "POST", body: form,
    });
  },

  listReports: (params = {}) => request("/reports" + query(params)),
  getReport: (id) => request(`/reports/${encodeURIComponent(id)}`),
  createReport: (scanId, options) =>
    request("/reports", {
      method: "POST",
      body: JSON.stringify({ scan_id: scanId, options }),
    }),
  deleteReport: (id) =>
    request(`/reports/${encodeURIComponent(id)}`, { method: "DELETE" }),
  downloadReport: async (id, format) => {
    // 파일 본문은 JSON 이 아니라 원문. request() 를 쓰지 않고 직접 읽음
    const response = await fetch(
      `${BASE}/reports/${encodeURIComponent(id)}/download?format=${format}`
    );
    if (!response.ok) throw new ApiError(response.status, "DOWNLOAD_FAILED",
      "보고서 내려받기 실패");
    const disposition = response.headers.get("content-disposition") || "";
    const match = disposition.match(/filename="([^"]+)"/);
    return { text: await response.text(), filename: match?.[1] || `report.${format}` };
  },

  compareScans: (base, target) =>
    request(`/scans/compare${query({ base, target })}`),

  templateSchema: () => request("/templates/schema"),
  listTemplates: (params = {}) => request("/templates" + query(params)),
  getTemplate: (id) => request(`/templates/${encodeURIComponent(id)}`),
  createTemplate: (form) =>
    request("/templates", { method: "POST", body: JSON.stringify({ form }) }),
  updateTemplate: (id, form) =>
    request(`/templates/${encodeURIComponent(id)}`, {
      method: "PUT", body: JSON.stringify({ form }),
    }),
  deleteTemplate: (id) =>
    request(`/templates/${encodeURIComponent(id)}`, { method: "DELETE" }),
  forkTemplate: (id, newId) =>
    request(`/templates/${encodeURIComponent(id)}/fork`, {
      method: "POST", body: JSON.stringify({ template_id: newId }),
    }),
  parseTemplate: (payload) =>
    request("/templates/parse", { method: "POST", body: JSON.stringify(payload) }),
  validateTemplate: (payload) =>
    request("/templates/validate", { method: "POST", body: JSON.stringify(payload) }),
  dryrunTemplate: (payload) =>
    request("/templates/dryrun", { method: "POST", body: JSON.stringify(payload) }),
  syncTemplates: () => request("/templates/sync", { method: "POST" }),
  reindexTemplates: () => request("/templates/reindex", { method: "POST" }),

  importTargets: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request("/targets/import", { method: "POST", body: form });
  },
};

/* 스캔 진행률 구독. progress / finding / done 이벤트를 넘긴다 */
export function subscribeScan(scanId, handlers) {
  const source = new EventSource(`${BASE}/scans/${encodeURIComponent(scanId)}/stream`);
  for (const name of ["progress", "finding", "done"]) {
    source.addEventListener(name, (event) => {
      let payload = {};
      try {
        payload = JSON.parse(event.data);
      } catch {
        return;
      }
      handlers[name]?.(payload);
      // done 이후 서버가 스트림 종료. 재연결 시도 차단
      if (name === "done") source.close();
    });
  }
  source.onerror = () => source.close();
  return () => source.close();
}
