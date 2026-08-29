#!/usr/bin/env python3
"""빌드 오케스트레이션 (IMPLEMENTATION_BRIEF M10).

    python3 packaging/build.py                 # 전 과정 자동 + 앱 실행
    python3 packaging/build.py --backend-only  # 백엔드 번들까지만
    python3 packaging/build.py --install-rust  # Rust 없으면 설치까지
    python3 packaging/build.py --no-launch     # 빌드만 하고 실행 안 함

전 과정 = 가상환경 생성 · 의존성 설치 · 백엔드 번들 · 데스크톱 셸 · 실행.
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
import os
import platform
import shutil
import subprocess
import sys
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


RUSTUP_UNIX = "https://sh.rustup.rs"
RUSTUP_WINDOWS = "https://win.rustup.rs/x86_64"

MANUAL_RUST_GUIDE = """Rust 툴체인이 없음. 아래 중 하나로 설치하세요.

  Windows   winget install Rustlang.Rustup
            또는 https://rustup.rs 에서 rustup-init.exe 실행
  macOS     brew install rustup && rustup-init
            또는 curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  Linux     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

설치 후 새 터미널에서 다시 실행하세요.
자동으로 설치하려면 --install-rust 를 붙임 (외부 통신 발생)."""


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
    """rustup 으로 Rust 설치. 사용자가 --install-rust 로 명시 동의한 경우만"""
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

    npx = shutil.which("npx")
    if npx is None:
        sys.exit("npx 가 없습니다. Node.js 를 설치하세요 (https://nodejs.org).")

    # rustup 직후에는 PATH 에 없을 수 있어 cargo 위치를 직접 넣어줌
    env = {**os.environ}
    cargo_bin = str(Path(cargo).parent)
    if cargo_bin not in env.get("PATH", ""):
        env["PATH"] = cargo_bin + os.pathsep + env.get("PATH", "")
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


def ensure_venv() -> None:
    """[1] 가상환경 준비 후 그 파이썬으로 재실행.

    시스템 파이썬으로 PyInstaller 를 돌리면 의존성이 번들에서 빠짐
    """
    if in_target_venv():
        return

    if not venv_python().is_file():
        print("[1] 가상환경 생성")
        run([sys.executable, "-m", "venv", str(VENV_DIR)])
    else:
        print("[1] 가상환경 확인")

    print("  의존성 설치")
    python = str(venv_python())
    run([python, "-m", "pip", "install", "-q", "--upgrade", "pip"])
    run([python, "-m", "pip", "install", "-q", "-r", str(REQUIREMENTS)])

    print("  가상환경 파이썬으로 재실행")
    # 재귀 방지. 자식은 in_target_venv() 가 참이라 이 분기를 건너뜀
    completed = subprocess.run([python, __file__, *sys.argv[1:]], cwd=ROOT)
    sys.exit(completed.returncode)


def launch() -> None:
    """[5] 빌드된 앱 실행. 실패해도 빌드 결과는 남음"""
    release = ROOT / "src-tauri" / "target" / "release"
    if _windows():
        candidates = [release / f"{APP_NAME}.exe", release / "redar.exe"]
        command = None
        for candidate in candidates:
            if candidate.is_file():
                command = [str(candidate)]
                break
    elif platform.system() == "Darwin":
        bundle = release / "bundle" / "macos" / f"{APP_NAME}.app"
        command = ["open", str(bundle)] if bundle.is_dir() else None
        if command is None and (release / "redar").is_file():
            command = [str(release / "redar")]
    else:
        binary = release / "redar"
        command = [str(binary)] if binary.is_file() else None

    if command is None:
        print("  [경고] 실행 파일을 찾지 못함. 빌드 산출물만 남김")
        return
    print(f"  $ {' '.join(command)}")
    subprocess.Popen(command, cwd=ROOT)
    print(f"  {APP_NAME} 실행")


def main() -> None:
    parser = argparse.ArgumentParser(description="REDAR 빌드")
    parser.add_argument(
        "--backend-only", action="store_true", help="백엔드 번들까지만",
    )
    parser.add_argument("--no-clean", action="store_true", help="이전 산출물 유지")
    parser.add_argument("--no-launch", action="store_true", help="빌드 후 실행 안 함")
    parser.add_argument(
        "--install-rust", action="store_true",
        help="Rust 가 없으면 rustup 으로 설치 (외부 통신 발생)",
    )
    args = parser.parse_args()

    ensure_venv()

    print("[2] 백엔드 번들 (PyInstaller --onedir)")
    bundle = build_backend(clean=not args.no_clean)
    report_size(bundle)

    print("[3] 산출물 스테이징")
    stage_backend(bundle)

    if args.backend_only:
        print("[4] 생략 (--backend-only)")
        print("빌드 완료")
        return

    print("[4] 데스크톱 셸 (Tauri)")
    build_tauri(args.install_rust)
    bundles = ROOT / "src-tauri" / "target" / "release" / "bundle"
    if bundles.is_dir():
        report_size(bundles)

    if args.no_launch:
        print("[5] 생략 (--no-launch)")
    else:
        print("[5] 앱 실행")
        launch()
    print("빌드 완료")


if __name__ == "__main__":
    main()
