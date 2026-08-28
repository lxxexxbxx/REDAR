"""번들 실행 진입점. 포트를 동적으로 잡고 stdout 으로 알린다.

고정 포트는 점유 시 기동 실패하거나 타 프로세스에 접속한다 (M10 [3]).
Tauri 셸이 이 stdout 한 줄을 읽어 WebView 를 띄운다
"""
from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

# 번들 루트를 import 경로에 넣는다. PyInstaller 는 _MEIPASS 를 sys.path 에 넣지만
# --onedir 의 하위 디렉터리 구조까지 보장하지 않는다
# 개발 실행에서는 저장소 루트가 packaging/ 의 상위다
sys.path.insert(
    0, str(Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1])))
)

READY_PREFIX = "REDAR_READY "


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> None:
    import uvicorn

    from app.cli import init_db
    from app.config import settings

    settings.HOME.mkdir(parents=True, exist_ok=True)
    # 첫 실행 시 사용자 데이터 경로에 DB 를 만든다. init-db 를 따로 돌리지 않아도 된다
    init_db(settings.DB_PATH)

    port = int(sys.argv[1]) if len(sys.argv) > 1 else free_port()
    print(
        READY_PREFIX
        + json.dumps({"port": port, "home": str(settings.HOME)}, ensure_ascii=False),
        flush=True,
    )
    # import 문자열이 아니라 앱 객체를 넘긴다. 번들에서는 uvicorn 이 모듈을
    # 이름으로 다시 import 하지 못해 'Could not import module' 로 죽는다
    from app.main import app as asgi_app

    uvicorn.run(
        asgi_app, host="127.0.0.1", port=port, log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":
    main()
