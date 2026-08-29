"""nuclei 프로세스 실행 · 중단.

stdout(JSONL) 은 라인 단위 스트림 처리. 파일 완성 후 읽기 방식은 진행 중 결과 표시 불가,
중단 시 전체 소실 (docs/01 §3.1)
"""
from __future__ import annotations

import logging
import subprocess
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from app.config import settings

logger = logging.getLogger(__name__)

_CANCEL_POLL_SEC = 0.2
_TERMINATE_GRACE_SEC = 5


@dataclass(frozen=True)
class RunOptions:
    targets: Sequence[str]
    template_ids: Sequence[str] = field(default_factory=tuple)
    # 템플릿 파일·디렉터리 경로. custom 템플릿은 로드되어야 -id 로 걸릴 수 있음
    template_paths: Sequence[str] = field(default_factory=tuple)
    tags: Sequence[str] = field(default_factory=tuple)
    severities: Sequence[str] = field(default_factory=tuple)
    threads: int = 20
    timeout_sec: int = 10
    retries: int = 1
    rate_limit: int | None = None
    stats_interval_sec: int = 5


def build_command(opts: RunOptions, exe: str | None = None) -> list[str]:
    """실행 인자 조립. nuclei 미설치 시 RuntimeError."""
    binary = exe or settings.nuclei_bin()
    if not binary:
        raise RuntimeError("nuclei 실행 파일을 찾을 수 없음. PATH 또는 REDAR_NUCLEI 확인")
    if not opts.targets:
        raise ValueError("스캔 대상 없음")

    cmd = [
        binary,
        "-jsonl",                                  # stdout 을 JSONL 로
        "-silent",                                 # 배너·진행 로그 억제
        "-nc",                                     # 색상 코드 제거. stats 파싱 방해 요소
        "-stats",
        "-si", str(opts.stats_interval_sec),
        # 기동 시 템플릿 갱신 확인을 위한 아웃바운드 통신 차단.
        # 허용된 외부 통신 3곳에 '스캔 시 자동 갱신'은 없음 (절대규칙 5)
        "-duc",
    ]
    for target in opts.targets:
        cmd += ["-target", target]
    # -t 는 경로, -id 는 템플릿 id 필터. id 를 -t 로 넘기면 경로로 해석되어 실패
    for path in opts.template_paths:
        cmd += ["-t", path]
    if opts.template_ids:
        cmd += ["-id", ",".join(opts.template_ids)]
    if opts.tags:
        cmd += ["-tags", ",".join(opts.tags)]
    if opts.severities:
        cmd += ["-severity", ",".join(opts.severities)]
    cmd += [
        "-c", str(opts.threads),
        "-timeout", str(opts.timeout_sec),
        "-retries", str(opts.retries),
    ]
    if opts.rate_limit:
        cmd += ["-rl", str(opts.rate_limit)]
    return cmd


def _drain(stream, handler: Callable[[str], None], label: str) -> None:
    try:
        for line in stream:
            handler(line.rstrip("\n"))
    except Exception:  # noqa: BLE001 - 리더 스레드 예외가 스캔을 죽이면 안 됨
        logger.warning("%s 리더 중단", label, exc_info=True)


def run(
    command: Sequence[str],
    *,
    on_stdout_line: Callable[[str], None],
    on_stderr_line: Callable[[str], None] | None = None,
    cancel: threading.Event | None = None,
) -> int:
    """프로세스 실행. 종료 코드 반환.

    cancel 이 set 되면 프로세스를 종료. 콜백이 예외를 던지거나 취소되더라도
    이미 처리된 라인은 되돌리지 않음 (저장 보존은 호출자의 배치 커밋이 담당)
    """
    proc = subprocess.Popen(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        # -target 으로 대상을 넘기므로 stdin 은 쓰지 않음. 열어두면 대기 위험
        stdin=subprocess.DEVNULL,
        text=True,
        bufsize=1,
        encoding="utf-8",
        # 응답 본문에 유효하지 않은 바이트 혼입 가능. 디코딩 실패로 스캔이 죽으면 안 됨
        errors="replace",
    )

    workers: list[threading.Thread] = []
    if on_stderr_line is not None:
        workers.append(
            threading.Thread(
                target=_drain, args=(proc.stderr, on_stderr_line, "stderr"), daemon=True
            )
        )
    if cancel is not None:
        workers.append(
            threading.Thread(target=_watch_cancel, args=(proc, cancel), daemon=True)
        )
    for worker in workers:
        worker.start()

    try:
        for line in proc.stdout:
            on_stdout_line(line.rstrip("\n"))
    finally:
        _shutdown(proc)
        for worker in workers:
            worker.join(timeout=_TERMINATE_GRACE_SEC)

    return proc.returncode


def _watch_cancel(proc: subprocess.Popen, cancel: threading.Event) -> None:
    """취소 감시.

    stdout 읽기가 블로킹이라 메인 루프에서 이벤트를 볼 수 없어 별도 스레드로 폴링.
    ponytail: 0.2초 폴링. 즉시성이 필요해지면 프로세스 그룹 시그널로 교체
    """
    while proc.poll() is None:
        if cancel.wait(_CANCEL_POLL_SEC):
            logger.info("스캔 취소 요청, nuclei 종료")
            _shutdown(proc)
            return


def _shutdown(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=_TERMINATE_GRACE_SEC)
    except subprocess.TimeoutExpired:
        logger.warning("nuclei 정상 종료 실패, 강제 종료")
        proc.kill()
        proc.wait(timeout=_TERMINATE_GRACE_SEC)
