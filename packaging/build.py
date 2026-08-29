#!/usr/bin/env python3
"""2단계 빌드 오케스트레이션 (IMPLEMENTATION_BRIEF M10).

    python3 packaging/build.py              # 백엔드만
    python3 packaging/build.py --tauri      # 백엔드 + 데스크톱 셸

순서를 지킨다. [1] 이 [3] 보다 어렵다 - Tauri 는 이미 만들어진 실행 파일을
감싸는 것뿐이고, Python 을 실행 파일로 묶는 과정에서 리소스 경로·동적 import 가 터진다

[1] PyInstaller --onedir 로 백엔드 빌드
[2] 산출물 구조 확인
[3] Tauri 번들
"""
from __future__ import annotations

import argparse
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
    """[2] Tauri 리소스로 넣을 복사본 생성. 심볼릭 링크를 푼다.

    externalBin(sidecar)을 쓰지 않는 이유: 파일 하나만 복사되어 --onedir 의
    _internal 이 빠진다. onefile 로 바꾸면 실행마다 9~18초가 걸린다 (실측)

    링크를 푸는 이유: Python.framework 안의 심볼릭 링크에서 Tauri 리소스 복사가
    'Not a directory' 로 실패한다. 해제 비용은 약 +6MB
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


def build_tauri() -> None:
    """[3] Tauri 번들. Rust 툴체인이 필요하다"""
    if shutil.which("cargo") is None:
        sys.exit(
            "cargo 가 없습니다. Rust 툴체인을 설치한 뒤 다시 실행하세요"
            " (https://rustup.rs)."
        )
    npx = shutil.which("npx")
    if npx is None:
        sys.exit("npx 가 없습니다. Node.js 를 설치하세요.")
    run([npx, "-y", "@tauri-apps/cli@^2", "build"], cwd=ROOT)


def report_size(path: Path) -> None:
    total = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
    print(f"  크기: {total / 1024 / 1024:.1f}MB ({path})")


def main() -> None:
    parser = argparse.ArgumentParser(description="REDAR 빌드")
    parser.add_argument("--tauri", action="store_true", help="데스크톱 셸까지 빌드")
    parser.add_argument("--no-clean", action="store_true", help="이전 산출물 유지")
    args = parser.parse_args()

    print("[1] 백엔드 빌드 (PyInstaller --onedir)")
    bundle = build_backend(clean=not args.no_clean)
    report_size(bundle)

    print("[2] 백엔드 산출물 확인")
    stage_backend(bundle)

    if args.tauri:
        print("[3] 데스크톱 셸 빌드 (Tauri)")
        build_tauri()
        bundles = ROOT / "src-tauri" / "target" / "release" / "bundle"
        if bundles.is_dir():
            report_size(bundles)
    else:
        print("[3] 생략 (--tauri 로 활성화)")

    print("빌드 완료")


if __name__ == "__main__":
    main()
