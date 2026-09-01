"""스캔 실행 흐름 제어. HTTP 객체 참조 없음 (docs/01 §2.1)."""
from __future__ import annotations

import logging
import queue
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from app import __version__
from app.adapters import logbuffer, portprobe
from app.adapters.nuclei import parser, progress, runner
from app.adapters.nuclei import version as nuclei_version
from app.config import settings
from app.domain import url as urlmod
from app.domain import target_range
from app.domain.allowlist import rejected_targets
from app.domain.enums import ScanStatus
from app.domain.ids import new_id
from app.repository import scans as scan_repo
from app.repository import settings_repo
from app.repository import templates as template_repo
from app.repository.db import session
from app.repository.findings import FindingBatchWriter
from app.repository.rules import load_vuln_type_rules
from app.services import environment_service, guide_service

logger = logging.getLogger(__name__)

TOOL_VERSION = __version__

# SSE finding 이벤트 상한. 초과분은 이벤트만 생략되며 DB 저장은 그대로 (docs/00 §2)
_FINDING_EVENTS_PER_SEC = 10
_EVENT_QUEUE_MAX = 2000
# 무활동 마감. nuclei 가 템플릿 1만 개를 로딩하는 동안은 아무 이벤트도 없음
_IDLE_TIMEOUT_SEC = 180.0
# 연결 유지 신호 주기. 프록시·브라우저가 조용한 연결을 끊지 않게 함
_HEARTBEAT_SEC = 10.0


def _stats_line(stats, found: int) -> str:
    """nuclei 진행 통계를 한 줄로. 원문 JSON 은 길어서 읽히지 않음"""
    parts = []
    if stats.percent is not None:
        parts.append(f"{stats.percent:g}%")
    if stats.requests_total:
        parts.append(f"요청 {stats.requests_done or 0}/{stats.requests_total}")
    elif stats.requests_done:
        parts.append(f"요청 {stats.requests_done}")
    parts.append(f"탐지 {found}건")
    if stats.errors:
        parts.append(f"오류 {stats.errors}건")
    return " · ".join(parts)


def preflight(conn) -> dict[str, Any]:
    """스캔 성립 조건 점검. 실행 전에 '왜 안 되는지' 를 미리 알려주기 위함.

    템플릿 0개인 상태로 스캔하면 nuclei 가 아무것도 실행하지 않고 정상 종료해
    '탐지 0건 = 안전' 으로 오독됨 (절대규칙 10)
    """
    official = template_repo.search(conn, source="official", size=1)[1]
    custom = template_repo.search(conn, source="custom", size=1)[1]
    store = settings.nuclei_template_store()

    blockers: list[dict[str, str]] = []
    if not settings.nuclei_bin():
        blockers.append({
            "code": "NUCLEI_MISSING",
            "message": "nuclei 없음. 탐지 실행 불가",
            "action": "설정 → 의존성에서 설치하거나 파일 반입",
            "goto": "settings",
        })
    # 허용 목록이 비어 있어도 막지 않는다. 스캔 화면 입력이 곧 등록이므로
    # 여기서 막으면 첫 스캔을 시작할 방법이 없음 (절대규칙 6 개정)
    if not official and not custom and not store:
        blockers.append({
            "code": "NO_TEMPLATES",
            "message": "실행할 템플릿 0개. 스캔해도 항상 탐지 0건",
            "action": "템플릿 화면에서 공식 템플릿 갱신, 또는 직접 작성",
            "goto": "templates",
        })

    return {
        "ready": not blockers,
        "blockers": blockers,
        "templates": {
            "official": official,
            "custom": custom,
            # REDAR 색인 밖의 nuclei 기본 저장소. 개수는 세지 않고 존재만 확인
            "nuclei_store": store,
            # 사용자가 파일을 직접 넣을 위치. 개발·번들에서 경로가 달라 화면에 실제 값 표기
            "official_dir": str(settings.OFFICIAL_DIR),
            "custom_dir": str(settings.CUSTOM_DIR),
        },
        # 갱신은 외부 통신 지점. 막혀 있으면 버튼이 403 으로만 끝나 이유를 알 수 없음
        "sync_allowed": not settings_repo.offline_mode(conn) and settings_repo.as_bool(
            settings_repo.get_all(conn).get("ext_template_sync_enabled")
        ),
    }


def template_paths() -> list[str]:
    """스캔이 로드할 템플릿 트리.

    REDAR 는 템플릿을 자체 경로로 내려받는다 (sync 의 -ud). 이 경로를 -t 로
    넘기지 않으면 nuclei 가 자기 기본 경로만 보므로 받아둔 템플릿도, 사용자가
    만든 custom 템플릿도 실행되지 않음. -id·-tags 는 '로드된 것 중' 고르는 필터
    존재하는 디렉터리만 넘김. 둘 다 없으면 nuclei 기본 경로로 넘어감
    """
    return [
        str(path) for path in (settings.OFFICIAL_DIR, settings.CUSTOM_DIR)
        if path.is_dir() and any(path.iterdir())
    ]


class ScanError(Exception):
    """서비스 계층 오류. API 가 §0.2 형식으로 변환."""

    def __init__(self, code: str, message: str, status_code: int = 400,
                 details: list[dict[str, Any]] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or []


@dataclass
class ScanRequest:
    targets: list[str]
    mode: str = "filter"
    template_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    collect_environment: bool = True
    threads: int = 20
    timeout_sec: int = 10
    retries: int = 1
    rate_limit: int | None = None
    # 포트 범위 전개가 상한을 넘을 때의 사용자 동의. 기본값은 되묻기
    confirm_expanded: bool = False


@dataclass
class _Run:
    scan_id: str
    cancel: threading.Event
    events: queue.Queue
    thread: threading.Thread | None = None
    findings_so_far: int = 0


class ScanService:
    """동시 1건만 실행. DB 쓰기 직렬화 목적 (docs/02 §5.3)."""

    def __init__(
        self,
        db_path: Path | None = None,
        *,
        command_builder: Callable[[runner.RunOptions], list[str]] = runner.build_command,
        command_runner: Callable[..., int] = runner.run,
        prober: Callable[[Sequence[str]], list[str]] = portprobe.reachable,
    ) -> None:
        self._db_path = db_path
        # 실제 소켓 연결을 여는 단계. 테스트에서 대체 가능해야 함
        self._prober = prober
        # 테스트는 실제 nuclei 대신 JSONL 을 흘리는 함수를 주입.
        # 조립도 주입 대상 - build_command 가 바이너리 존재를 요구하므로
        # 이것까지 열지 않으면 nuclei 없이 API 테스트가 불가 (CLAUDE.md 테스트 규칙)
        self._command_builder = command_builder
        self._command_runner = command_runner
        self._lock = threading.Lock()
        self._active: _Run | None = None

    # -------------------------------------------------------------- 생성

    def create(self, req: ScanRequest) -> dict[str, Any]:
        if not req.targets:
            raise ScanError("INVALID_REQUEST", "스캔 대상 비어 있음")
        if req.mode == "environment_driven" and not req.collect_environment:
            # 환경 조사 없이 환경 기반 선별은 성립하지 않음. 조용히 filter 로
            # 대체하면 보고서의 선별 근거가 사라짐
            raise ScanError(
                "INVALID_REQUEST",
                "environment_driven 모드는 환경 조사(collect_environment) 필요",
                details=[{"field": "collect_environment", "reason": "required"}],
            )
        if req.mode not in ("explicit", "filter", "environment_driven"):
            raise ScanError("INVALID_REQUEST", f"알 수 없는 모드: {req.mode}")

        # 'host:33-4444' 를 개별 대상으로 전개. nuclei 에는 포트 범위 옵션이 없음
        try:
            expansion = target_range.expand(req.targets)
        except target_range.RangeError as exc:
            raise ScanError(
                "INVALID_REQUEST", str(exc),
                details=[{"field": "targets", "reason": "range"}],
            ) from exc

        if (
            expansion.expanded
            and len(expansion.targets) > target_range.CONFIRM_THRESHOLD
            and not req.confirm_expanded
        ):
            # 대상이 곱으로 늘어 스캔 시간·대상 부하가 함께 커짐. 사용자에게 되물음
            raise ScanError(
                "LARGE_TARGET_EXPANSION",
                f"포트 범위를 펼치면 대상 {len(expansion.targets)}건. "
                "스캔이 오래 걸리고 대상 서버 부하가 큼",
                details=[
                    {"field": "targets", "reason": f"expanded={len(expansion.targets)}"}
                ],
            )

        with session(self._db_path) as conn:
            allowlist = settings_repo.target_allowlist(conn)
            # 판정은 호스트 기준. 전개 결과 전체를 검사하면 같은 호스트를 수천 번 봄
            hosts = target_range.hosts(req.targets)
            rejected = rejected_targets(hosts, allowlist)
            if rejected:
                # 사용자가 방금 직접 입력한 대상이므로 그 입력이 곧 동의다.
                # 같은 값을 설정에 한 번 더 적게 하는 것은 통제가 아니라 반복 작업이며,
                # 등록 결과는 허용 목록에 남아 무엇을 스캔했는지 추적 가능
                # (절대규칙 6 개정. 임포트·드라이런·API 직접 호출에는 게이트 유지)
                auto_allowed = settings_repo.add_allowlist(conn, rejected)
                logger.info("허용 목록 자동 등록 %s", auto_allowed)
            else:
                auto_allowed = []

            # 템플릿 0개면 nuclei 가 아무것도 실행하지 않고 성공으로 끝남.
            # 그대로 두면 '탐지 0건' 이 '양호' 로 오독됨 (절대규칙 10)
            ready = preflight(conn)
            no_templates = [
                b for b in ready["blockers"] if b["code"] == "NO_TEMPLATES"
            ]
            if no_templates:
                raise ScanError(
                    "NO_TEMPLATES",
                    f"{no_templates[0]['message']}. {no_templates[0]['action']}",
                    details=[{"field": "templates", "reason": "empty"}],
                )

            with self._lock:
                if self._active is not None and self._active.thread is not None \
                        and self._active.thread.is_alive():
                    raise ScanError(
                        "SCAN_ALREADY_RUNNING",
                        "이미 실행 중인 스캔 있음",
                        status_code=409,
                    )

                scan_id = new_id("scn")
                scan_repo.insert_scan(
                    conn,
                    scan_id=scan_id,
                    selection_mode=req.mode,
                    selection_detail=_selection_detail(req),
                    collect_environment=req.collect_environment,
                    threads=req.threads,
                    timeout_sec=req.timeout_sec,
                    retries=req.retries,
                    rate_limit=req.rate_limit,
                    # 실행·탐지 결과는 실제 포트 기준. 조치 대상이 특정되어야 함
                    targets=expansion.targets,
                    target_input=expansion.raw,
                    tool_version=TOOL_VERSION,
                    nuclei_version=nuclei_version(),
                )
                run = _Run(
                    scan_id=scan_id,
                    cancel=threading.Event(),
                    events=queue.Queue(maxsize=_EVENT_QUEUE_MAX),
                )
                # 실행부터는 전개된 대상만 다룸. 원문은 이미 DB 에 남김
                run.thread = threading.Thread(
                    target=self._execute,
                    args=(run, replace(req, targets=expansion.targets)),
                    daemon=True,
                )
                self._active = run
                run.thread.start()

            view = scan_repo.get_scan(conn, scan_id) or {"scan_id": scan_id}
            # 자동 등록한 호스트. 화면이 '허용 목록에 추가됨' 을 알려줄 근거
            view["auto_allowed"] = auto_allowed
            return view

    # -------------------------------------------------------------- 실행

    def _execute(self, run: _Run, req: ScanRequest) -> None:
        """백그라운드 스레드. 커넥션은 스레드마다 새로 연다."""
        status = ScanStatus.COMPLETED
        error: tuple[str, str] | None = None
        try:
            with session(self._db_path) as conn:
                rules = load_vuln_type_rules(conn)
                scan_repo.set_status(conn, run.scan_id, ScanStatus.RUNNING)
                self._emit(run, "progress", {
                    # percent 는 None. 이 단계는 총량을 알 수 없음.
                    # 0 을 보내면 화면이 '0% 에서 멈춤' 으로 표시됨
                    "scan_id": run.scan_id, "percent": None,
                    "phase": "selecting_templates",
                    "templates_done": 0, "templates_total": None, "findings_so_far": 0,
                })

                req = replace(req, targets=self._probe_targets(run, req, conn))

                template_ids, tags = list(req.template_ids), list(req.tags)
                if req.collect_environment:
                    selection = self._collect_environment(run, req, conn)
                    if selection is not None:
                        template_ids, tags = selection.template_ids, selection.tags

                command = self._command_builder(
                    runner.RunOptions(
                        targets=list(req.targets),
                        template_ids=template_ids,
                        template_paths=template_paths(),
                        tags=tags,
                        severities=list(req.severities),
                        threads=req.threads,
                        timeout_sec=req.timeout_sec,
                        retries=req.retries,
                        rate_limit=req.rate_limit,
                    )
                )
                # 실행 명령을 남긴다. '왜 안 잡혔나' 는 무엇을 실행했는지 모르면
                # 답할 수 없다. 실제로 -id 와 -tags 가 함께 나가 대부분이
                # 실행되지 않던 문제를 이 기록 없이 한참 뒤에야 찾았음
                logger.info("nuclei 실행: %s", " ".join(command))

                with FindingBatchWriter(conn) as writer:
                    self._stream(run, command, rules, writer, conn)

                if run.cancel.is_set():
                    status = ScanStatus.CANCELED

                # 가이드 매핑. 본문 미탑재여도 매핑은 저장됨 (절대규칙 3)
                try:
                    guide_service.map_scan(conn, run.scan_id)
                except Exception:  # noqa: BLE001 - 매핑 실패가 스캔 실패는 아니다
                    logger.warning("가이드 매핑 실패 %s", run.scan_id, exc_info=True)
        except ScanError as exc:                       # 대상 전부 무응답 등
            status, error = ScanStatus.FAILED, (exc.code, exc.message)
            logger.warning("스캔 중단 %s: %s", run.scan_id, exc.message)
        except RuntimeError as exc:                    # nuclei 미설치 등
            status, error = ScanStatus.FAILED, ("NUCLEI_UNAVAILABLE", str(exc))
            logger.warning("스캔 실패 %s: %s", run.scan_id, exc)
        except Exception as exc:                       # noqa: BLE001
            status, error = ScanStatus.FAILED, ("INTERNAL_ERROR", str(exc))
            logger.exception("스캔 실패 %s", run.scan_id)

        with session(self._db_path) as conn:
            scan_repo.set_status(
                conn, run.scan_id, status,
                error_code=error[0] if error else None,
                error_message=error[1] if error else None,
            )
            view = scan_repo.get_scan(conn, run.scan_id) or {}

        self._emit(run, "done", {
            "scan_id": run.scan_id,
            "status": status.value,
            "duration_sec": view.get("duration_sec"),
            "findings_total": run.findings_so_far,
            "error": view.get("error"),
        })
        # 스트림 종료 신호
        self._emit(run, None, None)

    def _probe_targets(self, run: _Run, req: ScanRequest, conn) -> list[str]:
        """응답하는 대상만 추려 실제 스캔 대상으로 삼음.

        포트 범위는 대부분이 닫힌 포트다. 전부에 템플릿을 돌리면 시간만 쓴다.
        무엇을 건너뛰었는지는 DB 에 남겨 보고서가 점검 범위를 밝힐 수 있게 함
        """
        self._emit(run, "progress", {
            "scan_id": run.scan_id, "percent": None, "phase": "probing_targets",
            "templates_done": 0, "templates_total": None,
            "findings_so_far": run.findings_so_far,
        })
        logger.info("대상 응답 확인 시작: %d건", len(req.targets))
        try:
            alive = self._prober(req.targets)
        except Exception:  # noqa: BLE001 - 사전 확인 실패가 스캔을 막지 않음
            logger.warning("대상 응답 확인 실패. 전부 스캔", exc_info=True)
            return list(req.targets)

        logger.info(
            "대상 응답 확인 완료: 응답 %d건 · 무응답 %d건",
            len(alive), len(req.targets) - len(alive),
        )
        scan_repo.mark_reachable(conn, run.scan_id, alive)
        if not alive:
            # 하나도 응답하지 않으면 0건으로 끝내지 않고 이유를 밝힘 (절대규칙 10)
            raise ScanError(
                "NO_REACHABLE_TARGET",
                f"대상 {len(req.targets)}개 전부 무응답. 주소·포트 확인 필요",
            )
        return alive

    def _collect_environment(self, run: _Run, req: ScanRequest, conn):
        """수집 -> 선별. 실패해도 스캔을 중단하지 않음 (M4 규칙 2).

        environment_driven 이 아니면 선별 결과를 쓰지 않고 조사 기록만 남김
        """
        self._emit(run, "progress", {
            "scan_id": run.scan_id, "percent": None,
            "phase": "collecting_environment",
            "templates_done": 0, "templates_total": None,
            "findings_so_far": run.findings_so_far,
        })
        results = []
        for target in req.targets:
            try:
                results.append(environment_service.collect_target(
                    conn, run.scan_id, target, timeout_sec=req.timeout_sec
                ))
            except Exception:  # noqa: BLE001 - 조사 실패가 스캔 실패는 아니다
                logger.warning("환경 조사 실패: %s", target, exc_info=True)

        if req.mode != "environment_driven":
            return None

        selection = environment_service.select_templates(conn, results)
        scan_repo.set_selection_basis(conn, run.scan_id, selection.basis)
        return selection

    def _stream(self, run: _Run, command, rules, writer, conn) -> None:
        last_event = 0.0
        emitted_this_sec = 0

        def on_stdout(line: str) -> None:
            nonlocal last_event, emitted_this_sec
            finding = parser.parse_line(line, scan_id=run.scan_id, rules=rules)
            if finding is None:
                return
            writer.add(finding)
            run.findings_so_far += 1

            # 탐지 결과는 stdout 으로 온다. 로그에 넣지 않으면 stats 만 찍혀
            # '무엇이 잡혔는지' 를 로그에서 볼 수 없음
            cve = ", ".join(finding.cve_ids) if finding.cve_ids else finding.template_id
            logbuffer.append(
                "탐지",
                f"[{finding.severity.value.upper()}] {cve} · {finding.name}"
                f" → {finding.target.raw}",
                level="WARN" if finding.severity.value in ("critical", "high")
                else "INFO",
            )

            now = time.monotonic()
            if now - last_event >= 1.0:
                last_event, emitted_this_sec = now, 0
            if emitted_this_sec >= _FINDING_EVENTS_PER_SEC:
                return                                  # 이벤트만 생략. 저장은 완료
            emitted_this_sec += 1
            self._emit(run, "finding", {
                "finding_id": finding.finding_id,
                "name": finding.name,
                "severity": finding.severity.value,
                "vuln_type": finding.vuln_type.value,
                "target": {"host": finding.target.host, "port": finding.target.port},
            })

        def on_stderr(line: str) -> None:
            stats = progress.parse_stats_line(line)
            if stats is None:
                # stats 가 아닌 줄은 nuclei 가 남긴 경고·오류다. 버리지 않고
                # 로그 버퍼에 넣어 화면에서 그대로 볼 수 있게 함
                logbuffer.append("nuclei", line)
                return
            # 원문 JSON 은 한 줄이 길어 읽을 수 없다. 필요한 값만 추려 남김
            logbuffer.append("진행", _stats_line(stats, run.findings_so_far))
            scan_repo.set_status(
                conn, run.scan_id, ScanStatus.RUNNING,
                templates_total=stats.requests_total,
                templates_done=stats.requests_done,
            )
            self._emit(run, "progress", {
                "scan_id": run.scan_id,
                "percent": stats.percent,
                "phase": "scanning",
                "templates_done": stats.requests_done,
                "templates_total": stats.requests_total,
                "findings_so_far": run.findings_so_far,
            })

        self._command_runner(
            command,
            on_stdout_line=on_stdout,
            on_stderr_line=on_stderr,
            cancel=run.cancel,
        )

    # -------------------------------------------------------------- 이벤트

    def _emit(self, run: _Run, event: str | None, data: dict | None) -> None:
        try:
            run.events.put_nowait((event, data))
        except queue.Full:
            # 진행률·탐지는 버려도 되지만 종료 신호는 버리면 화면이 영원히
            # '스캔 중' 으로 남는다. 자리를 만들어서라도 반드시 넣음
            if event in (None, "done"):
                self._force_emit(run, event, data)
            else:
                logger.debug("이벤트 큐 가득 참, 이벤트 폐기")

    def _force_emit(self, run: _Run, event: str | None, data: dict | None) -> None:
        for _ in range(_EVENT_QUEUE_MAX):
            try:
                run.events.put_nowait((event, data))
                return
            except queue.Full:
                try:
                    run.events.get_nowait()      # 가장 오래된 진행률을 버림
                except queue.Empty:
                    continue
        logger.warning("종료 신호를 큐에 넣지 못함 %s", run.scan_id)

    def events(self, scan_id: str, timeout: float = _IDLE_TIMEOUT_SEC
               ) -> Iterator[tuple[str, dict]]:
        """SSE 구독. 스트림 종료 신호를 받으면 종료.

        timeout 은 **무활동** 기준이다. 구독 시작 기준 절대 시간으로 두면
        템플릿 1만 개 로딩처럼 조용한 구간이 있는 실제 스캔에서 스트림이 먼저
        끊기고, 화면은 done 을 못 받아 영원히 '스캔 중' 으로 남는다
        """
        run = self._active
        if run is None or run.scan_id != scan_id:
            # 구독 시점에 이미 끝난 스캔. 클라이언트가 무한 대기하지 않도록 done 1건만
            yield "done", self._final_state(scan_id)
            return
        idle_until = time.monotonic() + timeout
        next_beat = time.monotonic() + _HEARTBEAT_SEC
        while True:
            try:
                event, data = run.events.get(timeout=0.5)
            except queue.Empty:
                now = time.monotonic()
                if now > idle_until:
                    # 무활동으로 끊기 전에 최종 상태를 알려줌
                    yield "done", self._final_state(scan_id)
                    return
                if now >= next_beat:
                    next_beat = now + _HEARTBEAT_SEC
                    # 연결 유지용. 클라이언트는 무시하고 프록시는 끊지 않음
                    yield "ping", {"scan_id": scan_id}
                continue
            idle_until = time.monotonic() + timeout
            if event is None:
                return
            yield event, data

    def _final_state(self, scan_id: str) -> dict[str, Any]:
        with session(self._db_path) as conn:
            view = scan_repo.get_scan(conn, scan_id) or {}
        return {
            "scan_id": scan_id,
            "status": view.get("status", "failed"),
            "duration_sec": view.get("duration_sec"),
            "error": view.get("error"),
        }

    # -------------------------------------------------------------- 제어

    def cancel(self, scan_id: str) -> bool:
        run = self._active
        if run is None or run.scan_id != scan_id:
            return False
        run.cancel.set()
        return True

    def is_running(self, scan_id: str) -> bool:
        run = self._active
        return (
            run is not None
            and run.scan_id == scan_id
            and run.thread is not None
            and run.thread.is_alive()
        )


def _selection_detail(req: ScanRequest) -> dict[str, Any] | None:
    if req.mode == "explicit":
        return {"template_ids": req.template_ids}
    detail: dict[str, Any] = {}
    if req.tags:
        detail["tags"] = req.tags
    if req.severities:
        detail["severity"] = req.severities
    return detail or None


def parse_target_file(content: bytes) -> tuple[list[str], list[int]]:
    """TXT(줄바꿈) / CSV(첫 열) 파싱. 스캔은 시작하지 않음 (docs/00 §2)."""
    targets: list[str] = []
    invalid: list[int] = []
    text = content.decode("utf-8", errors="replace")
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        candidate = line.split(",")[0].strip().strip('"')
        if not candidate:
            invalid.append(number)
            continue
        try:
            urlmod.parse(candidate)
        except ValueError:
            invalid.append(number)
            continue
        targets.append(candidate)
    return targets, invalid


_service: ScanService | None = None


def get_service() -> ScanService:
    global _service
    if _service is None:
        _service = ScanService()
    return _service


def set_service(service: ScanService | None) -> None:
    """테스트에서 주입."""
    global _service
    _service = service
