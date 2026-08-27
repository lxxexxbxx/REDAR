"""스캔 실행 흐름 제어. HTTP 객체 참조 없음 (docs/01 §2.1)."""
from __future__ import annotations

import logging
import queue
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.adapters.nuclei import parser, progress, runner
from app.adapters.nuclei import version as nuclei_version
from app.domain import url as urlmod
from app.domain.allowlist import rejected_targets
from app.domain.enums import ScanStatus
from app.domain.ids import new_id
from app.repository import scans as scan_repo
from app.repository import settings_repo
from app.repository.db import session
from app.repository.findings import FindingBatchWriter
from app.repository.rules import load_vuln_type_rules

logger = logging.getLogger(__name__)

TOOL_VERSION = "0.3.0"

# SSE finding 이벤트 상한. 초과분은 이벤트만 생략되며 DB 저장은 그대로 (docs/00 §2)
_FINDING_EVENTS_PER_SEC = 10
_EVENT_QUEUE_MAX = 2000


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
    ) -> None:
        self._db_path = db_path
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
            raise ScanError("INVALID_REQUEST", "스캔 대상이 비어 있습니다.")
        if req.mode == "environment_driven":
            # M4 에서 구현. 지금은 명시적으로 거부 (조용히 filter 로 대체하면 근거가 사라짐)
            raise ScanError(
                "INVALID_REQUEST", "environment_driven 모드는 아직 지원하지 않습니다."
            )
        if req.mode not in ("explicit", "filter"):
            raise ScanError("INVALID_REQUEST", f"알 수 없는 모드: {req.mode}")

        with session(self._db_path) as conn:
            allowlist = settings_repo.target_allowlist(conn)
            rejected = rejected_targets(req.targets, allowlist)
            if rejected:
                raise ScanError(
                    "INVALID_REQUEST",
                    "allowlist 에 없는 대상입니다. 설정에서 대상을 먼저 등록하세요.",
                    details=[
                        {"field": "targets", "reason": f"not allowed: {t}"}
                        for t in rejected
                    ],
                )

            with self._lock:
                if self._active is not None and self._active.thread is not None \
                        and self._active.thread.is_alive():
                    raise ScanError(
                        "SCAN_ALREADY_RUNNING",
                        "이미 실행 중인 스캔이 있습니다.",
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
                    targets=req.targets,
                    tool_version=TOOL_VERSION,
                    nuclei_version=nuclei_version(),
                )
                run = _Run(
                    scan_id=scan_id,
                    cancel=threading.Event(),
                    events=queue.Queue(maxsize=_EVENT_QUEUE_MAX),
                )
                run.thread = threading.Thread(
                    target=self._execute, args=(run, req), daemon=True
                )
                self._active = run
                run.thread.start()

            return scan_repo.get_scan(conn, scan_id) or {"scan_id": scan_id}

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
                    "scan_id": run.scan_id, "percent": 0, "phase": "selecting_templates",
                    "templates_done": 0, "templates_total": None, "findings_so_far": 0,
                })

                command = self._command_builder(
                    runner.RunOptions(
                        targets=list(req.targets),
                        template_ids=list(req.template_ids),
                        tags=list(req.tags),
                        severities=list(req.severities),
                        threads=req.threads,
                        timeout_sec=req.timeout_sec,
                        retries=req.retries,
                        rate_limit=req.rate_limit,
                    )
                )

                with FindingBatchWriter(conn) as writer:
                    self._stream(run, command, rules, writer, conn)

                if run.cancel.is_set():
                    status = ScanStatus.CANCELED
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
                return
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
            # 구독자가 없거나 느린 경우. 스캔을 막지 않음
            logger.debug("이벤트 큐 가득 참, 이벤트 폐기")

    def events(self, scan_id: str, timeout: float = 30.0) -> Iterator[tuple[str, dict]]:
        """SSE 구독. 스트림 종료 신호를 받으면 종료."""
        run = self._active
        if run is None or run.scan_id != scan_id:
            # 구독 시점에 이미 끝난 스캔. 클라이언트가 무한 대기하지 않도록 done 1건만
            yield "done", self._final_state(scan_id)
            return
        deadline = time.monotonic() + timeout
        while True:
            try:
                event, data = run.events.get(timeout=0.5)
            except queue.Empty:
                if time.monotonic() > deadline:
                    return
                continue
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
