# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 스펙. --onedir 로 빌드한다.

onefile 은 매 실행마다 압축을 풀어 5~15초 지연이 생긴다. 시연에서 문제가 된다
(IMPLEMENTATION_BRIEF M10 [3])

번들에 넣는 것은 읽기 전용 리소스만이다. DB·보고서는 사용자 경로에 만든다
(app/config/settings.py user_data_dir)
"""
from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent

# 읽기 전용 번들 리소스. 경로 구조를 런타임과 동일하게 유지한다
datas = [
    (str(ROOT / "db" / "schema.sql"), "db"),
    (str(ROOT / "db" / "migrations"), "db/migrations"),
    # data/ 를 통째로 넣지 않는다. guide_images/ 는 미채택이라 번들 대상이 아니다
    *[
        (str(ROOT / "data" / name), "data")
        for name in (
            "vuln_type_rules.csv",
            "guide_mappings.csv",
            "guide_mappings.templates.csv",
            "component_advisories.csv",
            "settings_defaults.csv",
            # 가이드 본문. init-db 가 자동 적재해 배포물에서 Part B 가 바로 동작
            "guide_items_2026.csv",
        )
    ],
    (str(ROOT / "assets" / "fonts"), "assets/fonts"),
    (str(ROOT / "frontend"), "frontend"),
    (str(ROOT / "app" / "report" / "templates"), "app/report/templates"),
    (str(ROOT / "app" / "config" / "severity_map.yaml"), "app/config"),
]

# 동적 import 되는 모듈. PyInstaller 의 정적 분석이 놓친다
hiddenimports = [
    "app.collectors.generic_http",
    "app.collectors.wordpress",
    "app.collectors.apache",
    "app.adapters.llm.monogpt",
    "app.services.narrative_service",
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
]

a = Analysis(
    [str(ROOT / "packaging" / "entrypoint.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "pytest", "fontTools"],
    noarchive=False,
)
pyz = PYZ(a.pure)

# onefile 은 실행마다 압축을 풀어 9~18초가 걸린다 (onedir 0.3초. 2026-08-29 실측).
# Tauri 에는 externalBin 대신 디렉터리 리소스로 넣는다 (src-tauri/tauri.conf.json)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="redar-backend",
    debug=False,
    strip=False,
    upx=False,          # UPX 압축은 백신 오탐을 늘린다
    console=True,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="redar-backend",
)
