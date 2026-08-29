#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nuclei 설치 도우미 (Windows / macOS / Linux).

    python3 tools/install_nuclei.py             # 확인 후 없으면 설치
    python3 tools/install_nuclei.py --check     # 확인만
    python3 tools/install_nuclei.py --force     # 이미 있어도 재설치

Go 툴체인을 확인하고 없으면 공식 배포본을 사용자 경로에 설치한 뒤
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
로 nuclei 를 빌드한다. 저장소·번들에 바이너리를 포함하지 않는다

**앱에서 호출하지 않는다.** API·GUI 버튼으로 노출하면 아웃바운드 통신 지점이
4개가 되어 절대규칙 5(외부 통신은 3곳뿐)를 깬다. 손으로 실행하는 설치 스크립트다.
tools/ 는 런타임 코드가 아니며 app/ 에서 import 하지 않는다
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

NUCLEI_PKG = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
GO_INDEX_URL = "https://go.dev/dl/?mode=json"
GO_DOWNLOAD_BASE = "https://go.dev/dl/"

WINDOWS = platform.system() == "Windows"
EXE = ".exe" if WINDOWS else ""

# 설치 위치. 사용자 홈 아래라 관리자 권한이 필요 없다.
# app/config/settings.py 의 nuclei_bin() 이 REDAR_HOME/bin 을 탐색한다
HOME = Path(os.environ.get("REDAR_HOME") or (
    Path(os.environ.get("LOCALAPPDATA", Path.home())) / "REDAR" if WINDOWS
    else Path.home() / ".redar"
))
TOOLCHAIN = HOME / "toolchain"
GO_ROOT = TOOLCHAIN / "go"
GO_PATH = TOOLCHAIN / "gopath"
BIN_DIR = HOME / "bin"

_TIMEOUT = 60
_BUILD_TIMEOUT = 900          # nuclei 빌드는 의존성이 많아 수 분 걸린다


def log(message: str) -> None:
    print(message, flush=True)


# ────────────────────────────────────────────── 탐색

def find_nuclei() -> Path | None:
    candidates = [
        Path(os.environ["REDAR_NUCLEI"]) if os.environ.get("REDAR_NUCLEI") else None,
        BIN_DIR / f"nuclei{EXE}",
        Path(shutil.which("nuclei")) if shutil.which("nuclei") else None,
    ]
    return next((p for p in candidates if p and p.is_file()), None)


def find_go() -> Path | None:
    """PATH 우선. 없으면 이 스크립트가 전에 설치한 툴체인을 본다"""
    on_path = shutil.which("go")
    if on_path:
        return Path(on_path)
    local = GO_ROOT / "bin" / f"go{EXE}"
    return local if local.is_file() else None


# ANSI 색상 코드. nuclei 는 -version 출력에도 색을 넣는다
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_VERSION_LINE = re.compile(r"\bv?\d+\.\d+(\.\d+)?\b")


def version_of(binary: Path, *args: str) -> str:
    """버전 문자열. 첫 줄이 아니라 버전이 담긴 줄을 고른다.

    nuclei 는 환경에 따라 sonic/ast 경고를 먼저 출력한다. 첫 줄만 보면
    버전 대신 경고가 표시된다
    """
    try:
        out = subprocess.run(
            [str(binary), *args], capture_output=True, text=True,
            timeout=_TIMEOUT, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"확인 실패 ({type(exc).__name__})"

    lines = [
        _ANSI.sub("", line).strip()
        for line in ((out.stdout or "") + "\n" + (out.stderr or "")).splitlines()
        if line.strip()
    ]
    for line in lines:
        if line.upper().startswith("WARNING"):
            continue
        if _VERSION_LINE.search(line):
            return line
    return lines[0] if lines else "확인 실패"


# ────────────────────────────────────────────── Go 설치

def go_asset() -> tuple[str, str]:
    """(파일명, sha256). 현재 OS·아키텍처에 맞는 안정판 최신"""
    machine = platform.machine().lower()
    arch = {
        "x86_64": "amd64", "amd64": "amd64",
        "arm64": "arm64", "aarch64": "arm64",
    }.get(machine)
    if arch is None:
        sys.exit(f"지원하지 않는 아키텍처: {machine}")
    goos = {"Windows": "windows", "Darwin": "darwin", "Linux": "linux"}[
        platform.system()
    ]
    kind = "zip" if goos == "windows" else "tar.gz"

    log(f"  Go 배포 목록 조회: {GO_INDEX_URL}")
    with urllib.request.urlopen(GO_INDEX_URL, timeout=_TIMEOUT) as response:
        releases = json.loads(response.read())

    for release in releases:
        if not release.get("stable"):
            continue
        for entry in release.get("files", []):
            if (entry.get("os") == goos and entry.get("arch") == arch
                    and entry.get("kind") == "archive"
                    and entry.get("filename", "").endswith(kind)):
                return entry["filename"], entry.get("sha256", "")
    sys.exit(f"설치 가능한 Go 배포본을 찾지 못했습니다: {goos}/{arch}")


def download(url: str, target: Path, expected_sha256: str) -> None:
    log(f"  내려받는 중: {url}")
    digest = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=_TIMEOUT) as response, \
            target.open("wb") as out:
        while chunk := response.read(1 << 20):
            digest.update(chunk)
            out.write(chunk)
    actual = digest.hexdigest()
    if expected_sha256 and actual != expected_sha256:
        # 검증 실패한 아카이브를 풀지 않는다
        target.unlink(missing_ok=True)
        sys.exit(f"체크섬 불일치\n  기대: {expected_sha256}\n  실제: {actual}")
    log(f"  체크섬 확인: {actual[:16]}…")


def extract(archive: Path, destination: Path) -> None:
    """아카이브 최상위가 go/ 이므로 상위 디렉터리에 푼다"""
    shutil.rmtree(destination, ignore_errors=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    log(f"  푸는 중: {destination}")
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(destination.parent)
    else:
        with tarfile.open(archive) as tf:
            # filter='data' 로 경로 이탈·특수 파일 차단
            tf.extractall(destination.parent, filter="data")


def install_go() -> Path:
    filename, sha256 = go_asset()
    log(f"  대상: {filename}")
    with tempfile.TemporaryDirectory(prefix="redar-go-") as tmp:
        archive = Path(tmp) / filename
        download(GO_DOWNLOAD_BASE + filename, archive, sha256)
        extract(archive, GO_ROOT)

    binary = GO_ROOT / "bin" / f"go{EXE}"
    if not binary.is_file():
        sys.exit(f"Go 설치 실패: {binary} 없음")
    if not WINDOWS:
        binary.chmod(0o755)
    return binary


# ────────────────────────────────────────────── nuclei 설치

def install_nuclei(go_binary: Path) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    GO_PATH.mkdir(parents=True, exist_ok=True)

    env = {
        **os.environ,
        # GOBIN 을 지정해 산출물 위치를 확정한다. 기본 GOPATH/bin 은 환경마다 다르다
        "GOBIN": str(BIN_DIR),
        "GOPATH": str(GO_PATH),
        "GOTOOLCHAIN": "local",
    }
    log(f"  go install {NUCLEI_PKG}")
    log("  (의존성이 많아 수 분 걸린다)")
    result = subprocess.run(
        [str(go_binary), "install", "-v", NUCLEI_PKG],
        env=env, timeout=_BUILD_TIMEOUT, check=False,
    )
    if result.returncode != 0:
        sys.exit(f"nuclei 설치 실패 (exit {result.returncode})")

    binary = BIN_DIR / f"nuclei{EXE}"
    if not binary.is_file():
        sys.exit(f"설치 산출물이 없습니다: {binary}")
    return binary


# ────────────────────────────────────────────── 진입점

def report(nuclei: Path | None, go_binary: Path | None) -> None:
    log("")
    log("현재 상태")
    log(f"  Go     : {version_of(go_binary, 'version') if go_binary else '없음'}")
    if go_binary:
        log(f"           {go_binary}")
    log(f"  nuclei : {version_of(nuclei, '-version') if nuclei else '없음'}")
    if nuclei:
        log(f"           {nuclei}")


def main() -> None:
    parser = argparse.ArgumentParser(description="nuclei 설치 (Go 툴체인 포함)")
    parser.add_argument("--check", action="store_true", help="확인만 하고 설치하지 않음")
    parser.add_argument("--force", action="store_true", help="이미 있어도 재설치")
    args = parser.parse_args()

    log(f"설치 경로: {HOME}")
    nuclei = find_nuclei()
    go_binary = find_go()

    if args.check:
        report(nuclei, go_binary)
        sys.exit(0 if nuclei else 1)

    if nuclei and not args.force:
        log(f"nuclei 가 이미 있습니다: {nuclei}")
        report(nuclei, go_binary)
        return

    log("[1] Go 툴체인 확인")
    if go_binary:
        log(f"  이미 설치됨: {go_binary}")
    else:
        log("  없음. 공식 배포본을 사용자 경로에 설치한다")
        go_binary = install_go()
        log(f"  설치 완료: {go_binary}")

    log("[2] nuclei 빌드·설치")
    nuclei = install_nuclei(go_binary)
    log(f"  설치 완료: {nuclei}")

    report(nuclei, go_binary)
    log("")
    log("REDAR 은 이 경로를 자동으로 찾는다. 환경변수 설정은 필요 없다.")
    log(f"다른 경로의 nuclei 를 쓰려면 REDAR_NUCLEI 를 지정한다.")


if __name__ == "__main__":
    main()
