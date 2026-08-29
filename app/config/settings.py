"""파일·환경 수준 설정.

런타임 플래그(offline_mode / llm_enabled / target_allowlist)의 원본은
DB settings 테이블. 여기에는 DB 접속 전 필요한 값만.

패키징(M10) 대응: 읽기 전용 번들 리소스와 쓰기 가능 사용자 경로를 분리함
PyInstaller 는 번들을 임시 디렉터리에 풀기 때문에 그 안에 쓰면 재시작 시 소실됨
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

# 번들 실행 여부. PyInstaller 가 _MEIPASS 를 넣음
FROZEN = getattr(sys, "frozen", False)
_BUNDLE = Path(getattr(sys, "_MEIPASS", "")) if FROZEN else None

ROOT = _BUNDLE or Path(__file__).resolve().parents[2]


def resource_path(rel: str) -> Path:
    """읽기 전용 번들 리소스. 스키마·CSV·폰트·프론트엔드"""
    return ROOT / rel


def platform_home() -> Path:
    """OS 표준 사용자 경로. 개발·번들 무관하게 같은 위치를 가리킴

    tools/install_nuclei.py 가 여기에 설치하므로 개발 실행에서도 찾아야 함
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        return Path(base) / "REDAR"
    return Path.home() / ".redar"


def user_data_dir() -> Path:
    """쓰기 가능 경로. DB·보고서·로그.

    개발 중에는 저장소 루트를 그대로 사용 - 경로가 갈리면 개발과 배포 동작이 달라짐
    """
    override = os.environ.get("REDAR_HOME")
    if override:
        return Path(override).expanduser().resolve()
    if not FROZEN:
        return Path(__file__).resolve().parents[2]
    return platform_home()


HOME = user_data_dir()


def _path(env: str, default: Path) -> Path:
    override = os.environ.get(env)
    return Path(override).expanduser().resolve() if override else default


DB_PATH = _path("REDAR_DB", HOME / "redar.db")
DATA_DIR = _path("REDAR_DATA_DIR", resource_path("data"))
SCHEMA_PATH = resource_path("db/schema.sql")
# 템플릿 트리. official 은 사용자가 넣거나 sync 로 내려받고, custom 은 저장소 포함
TEMPLATES_DIR = _path("REDAR_TEMPLATES_DIR", HOME / "templates")
OFFICIAL_DIR = TEMPLATES_DIR / "official"
CUSTOM_DIR = TEMPLATES_DIR / "custom"
MIGRATIONS_DIR = resource_path("db/migrations")
FONTS_DIR = resource_path("assets/fonts")
FRONTEND_DIR = resource_path("frontend")
REPORTS_DIR = _path("REDAR_REPORTS_DIR", HOME / "reports")


# 설정에 지정된 nuclei 경로. repository 계층이 DB 에서 읽어 넣음
# settings 모듈이 DB 를 조회하면 계층 방향이 뒤집힘 (docs/01 §2.1)
_CONFIGURED_NUCLEI: dict[str, str | None] = {"path": None}


def set_configured_nuclei(path: str | None) -> None:
    _CONFIGURED_NUCLEI["path"] = path or None


def nuclei_bin() -> str | None:
    """nuclei 실행 파일 경로. 미설치 시 None (docs/01 §5.5).

    번들에 동봉된 경우 그쪽을 먼저 봄
    """
    override = os.environ.get("REDAR_NUCLEI")
    if override:
        return override
    # 설정에서 지정·반입한 경로. DB 를 여기서 읽지 않기 위해 서비스가 넣어줌
    configured = _CONFIGURED_NUCLEI.get("path")
    if configured and Path(configured).is_file():
        return configured

    name = "nuclei.exe" if sys.platform == "win32" else "nuclei"
    # 탐색 순서: 명시 지정 -> 번들 -> 사용자 홈 -> PATH.
    # 번들이 앞서는 이유: 패키지된 앱은 동봉본이 함께 검증된 조합임
    # 사용자 홈은 tools/install_nuclei.py 가 설치하는 위치이며, 개발 실행에서는
    # HOME 이 저장소 루트라 OS 표준 경로도 함께 봄
    if FROZEN:
        bundled = resource_path(f"bin/{name}")
        if bundled.is_file():
            return str(bundled)
    for candidate in (HOME / "bin" / name, platform_home() / "bin" / name):
        if candidate.is_file():
            return str(candidate)
    return shutil.which("nuclei")
