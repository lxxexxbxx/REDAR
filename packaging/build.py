#!/usr/bin/env python3
"""2단계 빌드 오케스트레이션 (IMPLEMENTATION_BRIEF M10).

    python3 packaging/build.py              # 백엔드만
    python3 packaging/build.py --tauri      # 백엔드 + 데스크톱 셸

순서를 지킨다. [1] 이 [3] 보다 어렵다 - Tauri 는 이미 만들어진 실행 파일을
감싸는 것뿐이고, Python 을 실행 파일로 묶는 과정에서 리소스 경로·동적 import 가 터진다

[1] PyInstaller --onedir 로 백엔드 빌드
[2] sidecar 파일명에 타깃 트리플 부여
[3] Tauri 번들
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
SIDECAR_DIR = ROOT / "src-tauri" / "binaries"
BACKEND_NAME = "redar-backend"


def target_triple() -> str:
    """sidecar 파일명에 붙는 타깃 트리플. 없으면 Tauri 가 sidecar 를 못 찾는다"""
    probe = shutil.which("rustc")
    if probe:
        out = subprocess.run(
            [probe, "-vV"], capture_output=True, text=True, check=False
        ).stdout
        for line in out.splitlines():
            if line.startswith("host:"):
                return line.split(":", 1)[1].strip()
    # rustc 가 없을 때의 대체값. 정확도가 낮으므로 경고를 남긴다
    machine = {"x86_64": "x86_64", "AMD64": "x86_64", "arm64": "aarch64"}.get(
        platform.machine(), platform.machine()
    )
    system = {
        "Darwin": "apple-darwin",
        "Windows": "pc-windows-msvc",
        "Linux": "unknown-linux-gnu",
    }[platform.system()]
    print(f"  [경고] rustc 없음. 트리플 추정: {machine}-{system}")
    return f"{machine}-{system}"


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


def stage_sidecar(bundle: Path) -> Path:
    """[2] Tauri 가 찾는 이름으로 실행 파일을 복사한다.

    --onedir 산출물은 디렉터리이므로 실행 파일과 의존 파일을 함께 옮긴다
    """
    triple = target_triple()
    suffix = ".exe" if platform.system() == "Windows" else ""
    SIDECAR_DIR.mkdir(parents=True, exist_ok=True)

    source = bundle / f"{BACKEND_NAME}{suffix}"
    if not source.is_file():
        sys.exit(f"실행 파일을 찾을 수 없습니다: {source}")

    # _internal 디렉터리(의존 파일)를 sidecar 옆에 둔다
    internal = bundle / "_internal"
    if internal.is_dir():
        destination = SIDECAR_DIR / "_internal"
        shutil.rmtree(destination, ignore_errors=True)
        shutil.copytree(internal, destination)

    target = SIDECAR_DIR / f"{BACKEND_NAME}-{triple}{suffix}"
    shutil.copy2(source, target)
    os.chmod(target, 0o755)
    print(f"  sidecar: {target.name}")
    return target


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

    print("[2] sidecar 배치")
    stage_sidecar(bundle)

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
