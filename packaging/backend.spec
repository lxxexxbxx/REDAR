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
    (str(ROOT / "data"), "data"),
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

# Tauri sidecar 는 파일 하나만 번들된다 (externalBin). onedir 의 _internal 이
# .app 에 들어가지 않으므로 셸 빌드용으로는 onefile 이 필요하다.
# REDAR_ONEFILE=1 로 전환한다
import os

ONEFILE = os.environ.get("REDAR_ONEFILE") == "1"

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

if ONEFILE:
    exe = EXE(
        pyz, a.scripts, a.binaries, a.datas, [],
        name="redar-backend",
        debug=False,
        strip=False,
        upx=False,      # UPX 압축은 백신 오탐을 늘린다
        console=True,
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name="redar-backend",
        debug=False,
        strip=False,
        upx=False,
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
