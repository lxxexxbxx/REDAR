"""외부 도구 의존성 관리 (nuclei 등).

세 가지 확보 경로를 제공. 폐쇄망에서도 도구를 쓸 수 있어야 함

    탐지   이미 설치된 것을 찾음 (경로 지정 > 번들 > 사용자 홈 > PATH)
    반입   사용자가 바이너리 파일을 직접 넣음. 외부 통신 없음
    설치   Go 툴체인을 받아 go install 로 빌드. 외부 통신 발생

**설치는 외부 통신 지점 4번** (docs/01 §7.1). 기본 비활성이며
오프라인 모드에서 차단되고, 요청마다 명시적 동의가 필요
반입·경로 지정은 통신이 없으므로 오프라인에서도 동작함
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.adapters.nuclei import version_check
from app.config import settings
from app.repository import settings_repo
from app.services.scan_service import ScanError

logger = logging.getLogger(__name__)

WINDOWS = sys.platform == "win32"
EXE = ".exe" if WINDOWS else ""

# 설치가 쓰는 외부 주소. 통신 지점 4번의 실제 대상
GO_INDEX_URL = "https://go.dev/dl/?mode=json"
GO_DOWNLOAD_BASE = "https://go.dev/dl/"
NUCLEI_PKG = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

_NET_TIMEOUT = 60
_BUILD_TIMEOUT = 900
_MAX_IMPORT_BYTES = 512 * 1024 * 1024      # nuclei 는 180MB 대


def bin_dir() -> Path:
    return settings.platform_home() / "bin"


def toolchain_dir() -> Path:
    return settings.platform_home() / "toolchain"


@dataclass(frozen=True)
class Dependency:
    key: str
    label: str
    filename: str
    required_for: str
    version_args: tuple[str, ...]
    # 자동 설치 지원 여부. 지원하지 않는 도구는 반입·경로 지정만 가능
    installable: bool = True
    manual_url: str = ""


# 확장 지점. 항목을 추가하면 설정 화면·API 가 자동으로 따라감
REGISTRY: tuple[Dependency, ...] = (
    Dependency(
        key="nuclei",
        label="nuclei",
        filename=f"nuclei{EXE}",
        required_for="취약점 탐지. 없으면 스캔을 실행할 수 없다",
        version_args=("-version",),
        installable=True,
        manual_url="https://github.com/projectdiscovery/nuclei/releases",
    ),
)


def get(key: str) -> Dependency:
    found = next((d for d in REGISTRY if d.key == key), None)
    if found is None:
        raise ScanError(
            "INVALID_REQUEST", f"알 수 없는 의존성: {key}",
            details=[{"field": "key", "reason": key}],
        )
    return found


# ────────────────────────────────────────────── 탐지

def sync_configured_paths(conn: sqlite3.Connection) -> None:
    """DB 의 지정 경로를 settings 모듈에 밀어넣음. 기동 시·변경 시 호출.

    settings 가 DB 를 직접 읽으면 계층 방향이 뒤집힘 (docs/01 §2.1)
    """
    raw = settings_repo.get_all(conn)
    settings.set_configured_nuclei(raw.get("dep_nuclei_path") or None)
    version_check.version.cache_clear()


def resolve(conn: sqlite3.Connection, dependency: Dependency) -> dict[str, Any]:
    """(경로, 출처).

    탐색 순서를 여기서 다시 구현하지 않음. 실행에 쓰이는 경로와 화면에 보이는
    경로가 갈라지면 '표시된 것과 다른 바이너리로 스캔' 이 됨
    """
    if dependency.key == "nuclei":
        found = settings.nuclei_bin()
    else:
        configured = settings_repo.get_all(conn).get(f"dep_{dependency.key}_path")
        found = configured or shutil.which(dependency.key)

    # 지정만 되어 있고 실제로 없는 경로를 '사용 가능' 으로 보고하지 않음
    if not found or not Path(found).is_file():
        return {"path": found, "source": None}
    return {"path": found, "source": _source_of(conn, dependency, found)}


def _source_of(
    conn: sqlite3.Connection, dependency: Dependency, path: str
) -> str:
    configured = settings_repo.get_all(conn).get(f"dep_{dependency.key}_path")
    if configured and Path(configured) == Path(path):
        return "configured"
    if os.environ.get("REDAR_NUCLEI") == path:
        return "env"
    if Path(path).parent == bin_dir():
        return "installed"
    return "detected"


def _version_of(dependency: Dependency, path: str | None) -> str | None:
    if not path:
        return None
    if dependency.key == "nuclei":
        return version_check.version()
    try:
        out = subprocess.run(
            [path, *dependency.version_args], capture_output=True, text=True,
            timeout=30, stdin=subprocess.DEVNULL, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return ((out.stdout or "") + (out.stderr or "")).strip().splitlines()[0] or None


def status(conn: sqlite3.Connection) -> dict[str, Any]:
    """설정 화면·기동 확인이 쓰는 단일 조회"""
    raw = settings_repo.get_all(conn)
    offline = settings_repo.offline_mode(conn)
    install_enabled = settings_repo.as_bool(raw.get("ext_dependency_install_enabled"))

    items = []
    for dependency in REGISTRY:
        found = resolve(conn, dependency)
        items.append({
            "key": dependency.key,
            "label": dependency.label,
            "required_for": dependency.required_for,
            "installable": dependency.installable,
            "manual_url": dependency.manual_url,
            "available": found["source"] is not None,
            "path": found["path"],
            "source": found["source"],
            # 실행 불가한 경로에 버전을 붙이면 available=False 와 모순됨
            "version": (
                _version_of(dependency, found["path"]) if found["source"] else None
            ),
            "import_dir": str(bin_dir()),
        })
    return {
        "items": items,
        # 자동 설치 가능 조건. 화면이 버튼 활성 여부를 판단함
        "install_allowed": install_enabled and not offline,
        "offline_mode": offline,
        "install_endpoint_enabled": install_enabled,
        "blocked_reason": _blocked_reason(offline, install_enabled),
    }


def _blocked_reason(offline: bool, enabled: bool) -> str | None:
    if offline:
        return "오프라인 모드. 자동 설치 대신 파일 반입으로 등록"
    if not enabled:
        return "설정에서 '의존성 자동 설치' 통신 지점 허용 필요"
    return None


# ────────────────────────────────────────────── 경로 지정 · 반입

def set_path(conn: sqlite3.Connection, key: str, path: str | None) -> dict[str, Any]:
    """특정 버전을 쓰도록 경로를 고정. 통신 없음"""
    dependency = get(key)
    if path:
        target = Path(path).expanduser()
        if not target.is_file():
            raise ScanError(
                "INVALID_REQUEST", f"파일 없음: {target}",
                details=[{"field": "path", "reason": str(target)}],
            )
        if not os.access(target, os.X_OK):
            raise ScanError(
                "INVALID_REQUEST", f"실행 권한 없음: {target}",
                details=[{"field": "path", "reason": "not executable"}],
            )
        settings_repo.put_many(conn, {f"dep_{dependency.key}_path": str(target)})
    else:
        settings_repo.put_many(conn, {f"dep_{dependency.key}_path": ""})
    sync_configured_paths(conn)
    return status(conn)


def import_binary(
    conn: sqlite3.Connection, key: str, payload: bytes
) -> dict[str, Any]:
    """폐쇄망 반입 경로. 사용자가 가져온 바이너리를 등록. 통신 없음"""
    dependency = get(key)
    if not payload:
        raise ScanError("INVALID_REQUEST", "빈 파일입니다.")
    if len(payload) > _MAX_IMPORT_BYTES:
        raise ScanError("INVALID_REQUEST", "파일이 너무 큽니다.")

    target = bin_dir() / dependency.filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    if not WINDOWS:
        target.chmod(0o755)

    digest = hashlib.sha256(payload).hexdigest()
    logger.info("의존성 반입: %s (%s바이트, sha256 %s)", key, len(payload), digest[:16])

    settings_repo.put_many(conn, {f"dep_{dependency.key}_path": str(target)})
    sync_configured_paths(conn)

    result = status(conn)
    entry = next(i for i in result["items"] if i["key"] == key)
    if not entry["version"]:
        # 실행되지 않는 파일을 등록한 채로 두지 않음
        settings_repo.put_many(conn, {f"dep_{dependency.key}_path": ""})
        target.unlink(missing_ok=True)
        sync_configured_paths(conn)
        raise ScanError(
            "INVALID_REQUEST",
            "반입한 파일 실행 불가. 플랫폼 일치 여부 확인 필요",
        )
    result["sha256"] = digest
    return result


# ────────────────────────────────────────────── 자동 설치 (외부 통신)

def install(conn: sqlite3.Connection, key: str, *, confirmed: bool) -> dict[str, Any]:
    """Go 툴체인 확보 후 go install. 외부 통신 지점 4번 (docs/01 §7.1)"""
    dependency = get(key)
    if not dependency.installable:
        raise ScanError("INVALID_REQUEST", f"{dependency.label} 자동 설치 미지원")
    if not confirmed:
        # 사용자가 매번 명시적으로 동의해야 한다. 설정만으로 자동 실행되지 않음
        raise ScanError(
            "INVALID_REQUEST",
            "자동 설치에는 명시적 동의 필요 (confirm=true)",
            details=[{"field": "confirm", "reason": "required"}],
        )

    raw = settings_repo.get_all(conn)
    if settings_repo.offline_mode(conn):
        raise ScanError(
            "OFFLINE_MODE_BLOCKED",
            "오프라인 모드. 자동 설치 불가. 파일 반입 사용",
            status_code=403,
        )
    if not settings_repo.as_bool(raw.get("ext_dependency_install_enabled")):
        raise ScanError(
            "OFFLINE_MODE_BLOCKED",
            "의존성 자동 설치 통신 지점이 비활성 상태입니다.",
            status_code=403,
        )

    go_binary = _ensure_go()
    binary = _go_install(go_binary, dependency)
    settings_repo.put_many(conn, {f"dep_{dependency.key}_path": str(binary)})
    sync_configured_paths(conn)
    return status(conn)


def find_go() -> Path | None:
    on_path = shutil.which("go")
    if on_path:
        return Path(on_path)
    local = toolchain_dir() / "go" / "bin" / f"go{EXE}"
    return local if local.is_file() else None


def _ensure_go() -> Path:
    existing = find_go()
    if existing:
        return existing
    return _install_go()


def go_asset() -> tuple[str, str]:
    """(파일명, sha256). 현재 OS·아키텍처에 맞는 안정판 최신"""
    machine = platform.machine().lower()
    arch = {
        "x86_64": "amd64", "amd64": "amd64",
        "arm64": "arm64", "aarch64": "arm64",
    }.get(machine)
    if arch is None:
        raise ScanError("INTERNAL_ERROR", f"지원하지 않는 아키텍처: {machine}")
    goos = {"win32": "windows", "darwin": "darwin"}.get(sys.platform, "linux")
    kind = "zip" if goos == "windows" else "tar.gz"

    with urllib.request.urlopen(GO_INDEX_URL, timeout=_NET_TIMEOUT) as response:
        releases = json.loads(response.read())
    for release in releases:
        if not release.get("stable"):
            continue
        for entry in release.get("files", []):
            if (entry.get("os") == goos and entry.get("arch") == arch
                    and entry.get("kind") == "archive"
                    and entry.get("filename", "").endswith(kind)):
                return entry["filename"], entry.get("sha256", "")
    raise ScanError("INTERNAL_ERROR", f"Go 배포본 없음: {goos}/{arch}")


def _install_go() -> Path:
    filename, expected = go_asset()
    destination = toolchain_dir() / "go"
    logger.info("Go 툴체인 설치: %s", filename)

    with tempfile.TemporaryDirectory(prefix="redar-go-") as tmp:
        archive = Path(tmp) / filename
        digest = hashlib.sha256()
        with urllib.request.urlopen(
            GO_DOWNLOAD_BASE + filename, timeout=_NET_TIMEOUT
        ) as response, archive.open("wb") as out:
            while chunk := response.read(1 << 20):
                digest.update(chunk)
                out.write(chunk)
        if expected and digest.hexdigest() != expected:
            # 검증 실패한 아카이브를 풀지 않음
            raise ScanError(
                "INTERNAL_ERROR",
                f"Go 아카이브 체크섬 불일치 (기대 {expected[:16]}…)",
            )
        _extract(archive, destination)

    binary = destination / "bin" / f"go{EXE}"
    if not binary.is_file():
        raise ScanError("INTERNAL_ERROR", f"Go 설치 실패: {binary} 없음")
    if not WINDOWS:
        binary.chmod(0o755)
    return binary


def _extract(archive: Path, destination: Path) -> None:
    """아카이브 최상위가 go/ 이므로 상위 디렉터리에 풀어냄"""
    shutil.rmtree(destination, ignore_errors=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(destination.parent)
    else:
        with tarfile.open(archive) as tf:
            # filter='data' 로 경로 이탈·특수 파일 차단
            tf.extractall(destination.parent, filter="data")


def _go_install(go_binary: Path, dependency: Dependency) -> Path:
    target_dir = bin_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    gopath = toolchain_dir() / "gopath"
    gopath.mkdir(parents=True, exist_ok=True)

    env = {
        **os.environ,
        # 산출물 위치를 확정. 기본 GOPATH/bin 은 환경마다 다름
        "GOBIN": str(target_dir),
        "GOPATH": str(gopath),
        "GOTOOLCHAIN": "local",
    }
    logger.info("go install %s", NUCLEI_PKG)
    result = subprocess.run(
        [str(go_binary), "install", "-v", NUCLEI_PKG],
        env=env, timeout=_BUILD_TIMEOUT, capture_output=True, text=True,
        stdin=subprocess.DEVNULL, check=False,
    )
    if result.returncode != 0:
        tail = (result.stderr or "").strip().splitlines()[-3:]
        raise ScanError("INTERNAL_ERROR", "설치 실패: " + " / ".join(tail))

    binary = target_dir / dependency.filename
    if not binary.is_file():
        raise ScanError("INTERNAL_ERROR", f"설치 산출물 없음: {binary}")
    return binary
