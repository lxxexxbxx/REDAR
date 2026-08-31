#!/usr/bin/env python3
"""빌드 오케스트레이션 (IMPLEMENTATION_BRIEF M10).

    python3 packaging/build.py                    # 전 과정 자동 + 앱 실행
    python3 packaging/build.py --backend-only     # 백엔드 번들까지만
    python3 packaging/build.py --no-auto-install  # 툴체인 설치 없이 안내만
    python3 packaging/build.py --no-launch        # 빌드만 하고 실행 안 함

전 과정 = 가상환경 · 의존성 · 툴체인(Node · Rust · nuclei) · 번들 · 실행.
시스템 파이썬으로 실행해도 됨. 가상환경 준비 후 그 파이썬으로 자기 자신을 재실행


순서 고정. [2] 가 [4] 보다 어려움 - Tauri 는 만들어진 실행 파일을 감쌀 뿐이고,
Python 을 실행 파일로 묶는 과정에서 리소스 경로·동적 import 가 터짐

[1] 가상환경 · 의존성
[2] PyInstaller --onedir 백엔드 번들
[3] 산출물 스테이징
[4] Tauri 번들
[5] 앱 실행
"""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
BUILD = ROOT / "build"
BACKEND_NAME = "redar-backend"
# Tauri 리소스로 들어가는 복사본. 심볼릭 링크가 풀린 상태
STAGE_DIR = ROOT / "src-tauri" / "backend"


def run(command: list[str], **kwargs) -> None:
    print("  $", " ".join(command))
    subprocess.run(command, check=True, cwd=kwargs.pop("cwd", ROOT), **kwargs)


def build_backend(clean: bool) -> Path:
    """[1] PyInstaller. --onedir 고정 - onefile 은 매 실행 압축 해제로 5~15초 지연"""
    if shutil.which("pyinstaller") is None and not _module_exists("PyInstaller"):
        sys.exit(
            "PyInstaller 가 없습니다. pip install pyinstaller 를 먼저 실행하세요."
        )
    if clean:
        for path in (DIST / BACKEND_NAME, BUILD / BACKEND_NAME):
            shutil.rmtree(path, ignore_errors=True)

    run([
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
        str(ROOT / "packaging" / "backend.spec"),
    ])
    out = DIST / BACKEND_NAME
    if not out.is_dir():
        sys.exit(f"빌드 산출물이 없습니다: {out}")
    return out


def _module_exists(name: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(name) is not None


def stage_backend(bundle: Path) -> Path:
    """[2] Tauri 리소스로 넣을 복사본 생성. 심볼릭 링크를 풀어냄

    externalBin(sidecar)을 쓰지 않는 이유: 파일 하나만 복사되어 --onedir 의
    _internal 이 빠짐. onefile 로 바꾸면 실행마다 9~18초가 걸림 (실측)

    링크를 푸는 이유: Python.framework 안의 심볼릭 링크에서 Tauri 리소스 복사가
    'Not a directory' 로 실패. 해제 비용은 약 +6MB
    """
    suffix = ".exe" if platform.system() == "Windows" else ""
    executable = bundle / f"{BACKEND_NAME}{suffix}"
    if not executable.is_file():
        sys.exit(f"실행 파일을 찾을 수 없습니다: {executable}")
    if not (bundle / "_internal").is_dir():
        sys.exit(f"의존 파일 디렉터리가 없습니다: {bundle / '_internal'}")

    shutil.rmtree(STAGE_DIR, ignore_errors=True)
    shutil.copytree(bundle, STAGE_DIR, symlinks=False)
    staged = STAGE_DIR / f"{BACKEND_NAME}{suffix}"
    staged.chmod(0o755)
    print(f"  staged: {STAGE_DIR}")
    return staged


MANUAL_NODE_GUIDE = """Node.js 가 없습니다. 아래 중 하나로 설치하세요.

  Windows   winget install OpenJS.NodeJS.LTS
  macOS     brew install node
  Linux     sudo apt install nodejs npm   (또는 배포판 패키지 관리자)
            https://nodejs.org 에서 LTS 내려받기

자동 설치는 기본 동작. --no-auto-install 를 뺀 채 실행하면 됨 (외부 통신 발생)."""


RUSTUP_UNIX = "https://sh.rustup.rs"
RUSTUP_WINDOWS = "https://win.rustup.rs/x86_64"

MANUAL_RUST_GUIDE = """Rust 툴체인이 없음. 아래 중 하나로 설치하세요.

  Windows   winget install Rustlang.Rustup
            또는 https://rustup.rs 에서 rustup-init.exe 실행
  macOS     brew install rustup && rustup-init
            또는 curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  Linux     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

설치 후 새 터미널에서 다시 실행하세요.
자동 설치는 기본 동작. --no-auto-install 를 뺀 채 실행하면 됨 (외부 통신 발생)."""


MANUAL_MSVC_GUIDE = """MSVC 링커(link.exe)가 없음. Rust 의 Windows 기본 타깃이 요구함.

  winget install --id Microsoft.VisualStudio.2022.BuildTools ^
    --override "--wait --quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"

  또는 https://visualstudio.microsoft.com/downloads/ 에서
  'Visual Studio Build Tools' 를 받아 **C++ 데스크톱 개발** 워크로드 선택

VS Code 는 해당하지 않음. 설치 후 새 터미널에서 다시 실행.
관리자 권한과 수 GB 다운로드가 필요해 자동 설치하지 않음."""


def msvc_linker() -> str | None:
    """MSVC 링커 존재 확인.

    없으면 크레이트 수백 개를 받아 컴파일한 뒤 'link.exe not found' 로 끝난다.
    16초 다운로드 + 컴파일을 버리기 전에 미리 잡음
    link.exe 는 개발자 명령 프롬프트 밖에서는 PATH 에 없으므로 vswhere 로도 찾음
    """
    found = shutil.which("link")
    if found:
        return found

    base = os.environ.get("ProgramFiles(x86)") or os.environ.get("ProgramFiles")
    if not base:
        return None
    vswhere = Path(base) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        return None                     # VS 설치 관리자 자체가 없음

    completed = subprocess.run(
        [str(vswhere), "-products", "*", "-latest",
         "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
         "-property", "installationPath"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    path = completed.stdout.strip()
    return path or None


def cargo_path() -> str | None:
    """PATH 우선. rustup 이 방금 설치한 경우 PATH 갱신 전이라 홈도 봄"""
    found = shutil.which("cargo")
    if found:
        return found
    home = Path.home() / ".cargo" / "bin" / ("cargo.exe" if _windows() else "cargo")
    return str(home) if home.is_file() else None


def _windows() -> bool:
    return platform.system() == "Windows"


def install_rust() -> str:
    """rustup 으로 Rust 설치. --no-auto-install 이 아닌 경우만"""
    import tempfile
    import urllib.request

    print("  Rust 툴체인 설치 (rustup)")
    with tempfile.TemporaryDirectory(prefix="redar-rustup-") as tmp:
        if _windows():
            installer = Path(tmp) / "rustup-init.exe"
            urllib.request.urlretrieve(RUSTUP_WINDOWS, installer)
            run([str(installer), "-y", "--profile", "minimal"])
        else:
            script = Path(tmp) / "rustup-init.sh"
            urllib.request.urlretrieve(RUSTUP_UNIX, script)
            script.chmod(0o755)
            run(["sh", str(script), "-y", "--no-modify-path", "--profile", "minimal"])

    found = cargo_path()
    if not found:
        sys.exit("Rust 설치 후에도 cargo 를 찾지 못했습니다. 새 터미널에서 재시도하세요.")
    print(f"  설치 완료: {found}")
    return found


def build_tauri(auto_install_rust: bool) -> None:
    """[3] Tauri 번들. Rust 툴체인이 필요"""
    cargo = cargo_path()
    if cargo is None:
        if not auto_install_rust:
            sys.exit(MANUAL_RUST_GUIDE)
        cargo = install_rust()

    # Rust 는 있어도 링커가 없으면 컴파일 끝에서 실패한다. 시작 전에 확인
    if _windows() and msvc_linker() is None:
        sys.exit(MANUAL_MSVC_GUIDE)

    npx = ensure_node(auto_install_rust)

    # rustup 직후에는 PATH 에 없을 수 있어 cargo 위치를 직접 넣어줌
    env = {**os.environ}
    for extra in (str(Path(cargo).parent), str(Path(npx).parent)):
        if extra not in env.get("PATH", ""):
            env["PATH"] = extra + os.pathsep + env.get("PATH", "")
    run([npx, "-y", "@tauri-apps/cli@^2", "build"], cwd=ROOT, env=env)


def report_size(path: Path) -> None:
    total = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
    print(f"  크기: {total / 1024 / 1024:.1f}MB ({path})")


VENV_DIR = ROOT / ".venv"
REQUIREMENTS = ROOT / "requirements.txt"
APP_NAME = "REDAR"


def venv_python() -> Path:
    return VENV_DIR / ("Scripts/python.exe" if _windows() else "bin/python")


def in_target_venv() -> bool:
    try:
        return Path(sys.executable).resolve() == venv_python().resolve()
    except OSError:
        return False


def ensure_deps(python: str) -> None:
    """의존성 설치. 가상환경 안팎을 가리지 않고 항상 확인.

    in_target_venv() 로 건너뛰면 사용자가 가상환경을 활성화한 뒤 실행했을 때
    설치가 통째로 빠져 'PyInstaller 가 없습니다' 로 끝남
    """
    print("  의존성 확인")
    run([python, "-m", "pip", "install", "-q", "--upgrade", "pip"])
    run([python, "-m", "pip", "install", "-q", "-r", str(REQUIREMENTS)])


def ensure_venv() -> None:
    """[1] 가상환경 준비 후 그 파이썬으로 재실행.

    시스템 파이썬으로 PyInstaller 를 돌리면 의존성이 번들에서 빠짐
    """
    if in_target_venv():
        # 이미 대상 가상환경 안. 의존성만 확인하고 진행
        ensure_deps(sys.executable)
        return

    if not venv_python().is_file():
        print("  가상환경 생성")
        run([sys.executable, "-m", "venv", str(VENV_DIR)])
    else:
        print("  가상환경 확인")

    python = str(venv_python())
    ensure_deps(python)

    print("  가상환경 파이썬으로 재실행")
    # 재귀 방지. 자식은 in_target_venv() 가 참이라 생성·재실행 분기를 건너뜀
    completed = subprocess.run([python, __file__, *sys.argv[1:]], cwd=ROOT)
    sys.exit(completed.returncode)


# ────────────────────────────────────────────── 툴체인 (Node · Rust · nuclei)

NODE_INDEX_URL = "https://nodejs.org/dist/index.json"
NODE_DIST_BASE = "https://nodejs.org/dist"


def toolchain_home() -> Path:
    """사용자 홈. app/config/settings.py 의 platform_home() 과 같은 규칙"""
    if _windows():
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        return Path(base) / "REDAR"
    return Path.home() / ".redar"


def node_root() -> Path:
    return toolchain_home() / "toolchain" / "node"


def npx_path() -> str | None:
    """PATH 우선. 없으면 이 스크립트가 설치한 툴체인"""
    found = shutil.which("npx")
    if found:
        return found
    local = node_root() / ("npx.cmd" if _windows() else "bin/npx")
    return str(local) if local.is_file() else None


def _arch() -> str:
    machine = platform.machine().lower()
    mapped = {"x86_64": "x64", "amd64": "x64", "arm64": "arm64", "aarch64": "arm64"}
    if machine not in mapped:
        sys.exit(f"지원하지 않는 아키텍처: {machine}")
    return mapped[machine]


def install_node() -> str:
    """공식 배포본을 사용자 홈에 설치. 관리자 권한 불필요"""
    import json
    import urllib.request

    system = platform.system()
    goos = {"Windows": "win", "Darwin": "darwin", "Linux": "linux"}[system]
    suffix = "zip" if goos == "win" else "tar.gz"

    print("  Node.js 배포 목록 조회")
    with urllib.request.urlopen(NODE_INDEX_URL, timeout=60) as response:
        releases = json.loads(response.read())
    release = next((r for r in releases if r.get("lts")), releases[0])
    version = release["version"]
    name = f"node-{version}-{goos}-{_arch()}"
    url = f"{NODE_DIST_BASE}/{version}/{name}.{suffix}"

    print(f"  내려받는 중: {url}")
    with tempfile.TemporaryDirectory(prefix="redar-node-") as tmp:
        archive = Path(tmp) / f"{name}.{suffix}"
        digest = hashlib.sha256()
        with urllib.request.urlopen(url, timeout=120) as response, \
                archive.open("wb") as out:
            while chunk := response.read(1 << 20):
                digest.update(chunk)
                out.write(chunk)

        # 공식 SHASUMS256.txt 와 대조. 검증 실패한 아카이브는 풀지 않음
        with urllib.request.urlopen(
            f"{NODE_DIST_BASE}/{version}/SHASUMS256.txt", timeout=60
        ) as response:
            sums = response.read().decode("utf-8", errors="replace")
        expected = next(
            (line.split()[0] for line in sums.splitlines()
             if line.strip().endswith(f"{name}.{suffix}")),
            None,
        )
        if expected and digest.hexdigest() != expected:
            sys.exit(f"Node.js 체크섬 불일치\n  기대: {expected}\n  실제: {digest.hexdigest()}")
        print(f"  체크섬 확인: {digest.hexdigest()[:16]}…")

        destination = node_root()
        shutil.rmtree(destination, ignore_errors=True)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if suffix == "zip":
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(destination.parent)
        else:
            with tarfile.open(archive) as tf:
                tf.extractall(destination.parent, filter="data")
        (destination.parent / name).rename(destination)

    found = npx_path()
    if not found:
        sys.exit(f"Node.js 설치 후에도 npx 를 찾지 못함: {destination}")
    print(f"  설치 완료: {found}")
    return found


def ensure_node(auto: bool) -> str:
    found = npx_path()
    if found:
        return found
    if not auto:
        sys.exit(MANUAL_NODE_GUIDE)
    print("  Node.js 없음. 공식 배포본 설치")
    return install_node()


def ensure_nuclei(auto: bool) -> None:
    """탐지의 전제 조건. 빌드 단계에서 함께 확보"""
    installer = ROOT / "tools" / "install_nuclei.py"
    check = subprocess.run(
        [sys.executable, str(installer), "--check"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if check.returncode == 0:
        print("  nuclei 확인")
        return
    if not auto:
        print("  [건너뜀] nuclei 없음. python3 tools/install_nuclei.py 로 설치")
        return
    print("  nuclei 없음. Go 툴체인 확인 후 설치 (수 분 소요)")
    subprocess.run([sys.executable, str(installer)], cwd=ROOT, check=False)


def launch() -> None:
    """[5] 빌드된 데스크톱 앱 실행. 실패해도 빌드 결과는 남음"""
    release = ROOT / "src-tauri" / "target" / "release"
    command = None
    if _windows():
        for candidate in (release / f"{APP_NAME}.exe", release / "redar.exe"):
            if candidate.is_file():
                command = [str(candidate)]
                break
    elif platform.system() == "Darwin":
        bundle = release / "bundle" / "macos" / f"{APP_NAME}.app"
        if bundle.is_dir():
            command = ["open", str(bundle)]
        elif (release / "redar").is_file():
            command = [str(release / "redar")]
    elif (release / "redar").is_file():
        command = [str(release / "redar")]

    if command is None:
        print("  [경고] 실행 파일을 찾지 못함. 빌드 산출물만 남김")
        return
    print(f"  $ {' '.join(command)}")
    subprocess.Popen(command, cwd=ROOT)
    print(f"  {APP_NAME} 실행")
    report_artifacts()


def report_artifacts() -> None:
    """산출물 위치 출력. 플랫폼마다 경로가 달라 어디를 봐야 할지 알기 어려움"""
    release = ROOT / "src-tauri" / "target" / "release"
    if _windows():
        candidates = [
            release / f"{APP_NAME}.exe",
            release / "redar.exe",
            *sorted((release / "bundle" / "msi").glob("*.msi")),
            *sorted((release / "bundle" / "nsis").glob("*.exe")),
        ]
    elif platform.system() == "Darwin":
        candidates = [
            release / "bundle" / "macos" / f"{APP_NAME}.app",
            *sorted((release / "bundle" / "dmg").glob("*.dmg")),
        ]
    else:
        candidates = [release / "redar", *sorted(
            (release / "bundle").glob("*/*.AppImage")
        )]

    found = [p for p in candidates if p.exists()]
    if not found:
        return
    print("")
    print("  산출물")
    for path in found:
        print(f"    {path}")


def main() -> None:
    # 로그 리다이렉션 시 부모 출력이 버퍼에 묶여 자식 로그 뒤로 밀림
    sys.stdout.reconfigure(line_buffering=True)

    parser = argparse.ArgumentParser(description="REDAR 빌드")
    parser.add_argument(
        "--backend-only", action="store_true", help="백엔드 번들까지만",
    )
    parser.add_argument("--no-clean", action="store_true", help="이전 산출물 유지")
    parser.add_argument("--no-launch", action="store_true", help="빌드 후 실행 안 함")
    parser.add_argument(
        "--no-auto-install", action="store_true",
        help="누락된 툴체인을 설치하지 않고 안내만 (외부 통신 없음)",
    )
    args = parser.parse_args()
    auto = not args.no_auto_install

    print("[1] 툴체인 확인")
    ensure_venv()
    ensure_nuclei(auto)

    print("[2] 백엔드 번들 (PyInstaller --onedir)")
    bundle = build_backend(clean=not args.no_clean)
    report_size(bundle)

    print("[3] 산출물 스테이징")
    stage_backend(bundle)

    if args.backend_only:
        print("[4] 생략 (--backend-only)")
    else:
        print("[4] 데스크톱 셸 (Tauri)")
        build_tauri(auto)
        bundles = ROOT / "src-tauri" / "target" / "release" / "bundle"
        if bundles.is_dir():
            report_size(bundles)

    if args.no_launch:
        print("[5] 생략 (--no-launch)")
    elif args.backend_only:
        print("[5] 생략 (--backend-only)")
    else:
        print("[5] 앱 실행")
        launch()
    print("빌드 완료")


if __name__ == "__main__":
    main()
