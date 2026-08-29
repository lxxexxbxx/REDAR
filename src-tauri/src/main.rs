// REDAR 데스크톱 셸. 하는 일은 sidecar 기동과 창 띄우기뿐이다.
//
// 포트는 백엔드가 동적으로 잡고 stdout 한 줄로 알려준다. 고정 포트는 점유 시
// 기동 실패하거나 타 프로세스에 접속한다 (IMPLEMENTATION_BRIEF M10 [3])
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_shell::process::{CommandEvent, CommandChild};
use tauri_plugin_shell::ShellExt;

const READY_PREFIX: &str = "REDAR_READY ";

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let handle = app.handle().clone();
            // sidecar 대신 리소스 경로로 실행한다. externalBin 은 파일 하나만 복사하므로
            // PyInstaller --onedir 의 _internal 이 빠진다. onedir 을 유지하는 이유는
            // onefile 이 실행마다 압축을 풀어 9~18초가 걸리기 때문 (실측)
            let exe = if cfg!(windows) { "redar-backend.exe" } else { "redar-backend" };
            let backend = app
                .path()
                .resource_dir()?
                // resources 배열이 상대 경로를 보존하므로 backend/ 그대로 들어간다
                .join("backend")
                .join(exe);
            let (mut rx, child) = app.shell().command(backend).spawn()?;
            // 앱 종료 시 sidecar 를 함께 내린다. 남기면 포트와 DB 락이 유지된다
            app.manage(SidecarGuard(std::sync::Mutex::new(Some(child))));

            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    if let CommandEvent::Stdout(line) = event {
                        let text = String::from_utf8_lossy(&line);
                        let Some(json) = text.trim().strip_prefix(READY_PREFIX) else {
                            continue;
                        };
                        let port = serde_json::from_str::<serde_json::Value>(json)
                            .ok()
                            .and_then(|v| v.get("port").and_then(|p| p.as_u64()));
                        if let Some(port) = port {
                            let url = format!("http://127.0.0.1:{port}");
                            let _ = WebviewWindowBuilder::new(
                                &handle,
                                "main",
                                WebviewUrl::External(url.parse().unwrap()),
                            )
                            .title("REDAR")
                            .inner_size(1280.0, 860.0)
                            .min_inner_size(960.0, 640.0)
                            .build();
                            break;
                        }
                    }
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                if let Some(guard) = window.app_handle().try_state::<SidecarGuard>() {
                    if let Some(child) = guard.0.lock().unwrap().take() {
                        let _ = child.kill();
                    }
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("REDAR 실행 실패")
        .run(|handle, event| {
            // 창 파괴 이벤트가 돌지 않는 종료 경로(Cmd+Q 등)도 여기서 정리한다
            if let tauri::RunEvent::Exit = event {
                if let Some(guard) = handle.try_state::<SidecarGuard>() {
                    if let Some(child) = guard.0.lock().unwrap().take() {
                        let _ = child.kill();
                    }
                }
            }
        });
}

struct SidecarGuard(std::sync::Mutex<Option<CommandChild>>);
