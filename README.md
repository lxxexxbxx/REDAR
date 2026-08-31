# REDAR

Nuclei 기반 웹 취약점 **진단** 도구. 스캔 실행, 결과 정리, 보고서 생성을 로컬에서 처리

- 모든 처리는 사용자 PC 안에서 완결. 외부 통신은 옵션이며 기본 비활성
- 다른 기기에서 실행한 nuclei 결과를 가져와 분석 가능
- 가이드 DB·LLM 없이도 정상 동작

---

## 구현 상태

| 단계 | 내용 | 상태 |
|---|---|---|
| M0 | DB 적재 파이프라인 · FastAPI 뼈대 | 완료 |
| M1 | 도메인 모델 · fingerprint · 심각도 환산 · 버전 비교 | 완료 |
| M2 | nuclei 실행 · JSONL 파싱 · 결과 저장 | 완료 |
| M3 | 스캔 API · SSE 진행률 · 결과 조회 · 설정 | 완료 |
| — | GUI (대시보드 · 스캔 · 결과 · 설정) | 완료 |
| M4 | 환경 수집기 (제품·버전·플러그인 식별 · 노출 11종) | 완료 |
| M5 | 템플릿 관리 · 폼 빌더 · 검증 · 드라이런 | 완료 |
| M6 | 가이드 매핑 엔진 (2트랙 · 판정) | 완료 |
| M7 | 보고서 생성 (자체 완결형 HTML) | 완료 |
| M8 | 스캔 비교 (재진단 차이 보고) | 완료 |
| M9 | LLM 서술 레이어 (기본 비활성) | 완료 |
| M10 | 데스크톱 패키징 (원클릭 빌드 · Tauri 번들) | 완료 |

화면 6종(대시보드 · 스캔 실행 · 탐지 결과 · 템플릿 · 보고서 · 설정) 전부 동작

**PDF 는 서버가 생성하지 않음.** 보고서 HTML 을 브라우저·앱에서 인쇄(Ctrl/Cmd+P)한 뒤
"PDF 로 저장" 선택. HTML 이 폰트를 포함한 자체 완결형 파일이라 그대로 공유 가능

가이드 본문(점검항목 382개)은 저작권상 저장소에 미포함. 파일 확보 후 임포트

```bash
python -m app.cli import-guide data/guide_items_2026.csv \
                   --images data/guide_items_2026_images.csv
```

---

## 빠른 시작

### 요구사항

| 항목 | 버전 | 비고 |
|---|---|---|
| Python | 3.11 이상 | 시스템 파이썬이면 충분. 가상환경은 빌드가 만듦 |
| Node.js | 18 이상 | 없으면 빌드가 공식 배포본 설치 |
| Rust | 최신 안정판 | 없으면 빌드가 rustup 으로 설치 |
| 플랫폼 링커 | Windows: **MSVC 빌드 도구** · macOS: Xcode CLT | 자동 설치 안 함. 아래 참조 |
| OS | Windows / macOS / Linux | |

**Windows 는 MSVC 링커가 따로 필요.** Rust 기본 타깃이 요구하며, 없으면 Tauri 빌드가
컴파일 끝에서 `link.exe not found` 로 실패. 관리자 권한과 수 GB 다운로드가 필요해
자동 설치하지 않음

```powershell
winget install --id Microsoft.VisualStudio.2022.BuildTools `
  --override "--wait --quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

VS Code 는 해당하지 않음. macOS 는 `xcode-select --install`

**Windows 빌드는 PowerShell 에서 실행.** WSL 은 리눅스라 리눅스 실행 파일이 나오고
Windows 앱이 만들어지지 않음

### 한 줄 빌드

```bash
git clone https://github.com/lxxexxbxx/REDAR.git
cd REDAR
python3 packaging/build.py
```

아래가 순서대로 자동 진행되고 **마지막에 앱이 실행됨.**

```
[1] 가상환경(.venv) · 의존성 · 툴체인 (Node · nuclei)
[2] 백엔드 번들 (PyInstaller --onedir)
[3] 산출물 스테이징
[4] 데스크톱 셸 빌드 (Tauri. 없으면 Rust 설치)
[5] 앱 실행
```

DB 초기화도 앱 첫 실행이 알아서 처리. `init-db` 를 따로 돌릴 필요 없음.
Node · Rust · nuclei 가 없으면 **같은 실행 안에서** 확보. 두 번 실행할 필요 없음

| 옵션 | 동작 |
|---|---|
| `--no-auto-install` | 툴체인을 설치하지 않고 OS 별 설치 방법만 출력 (외부 통신 없음) |
| `--backend-only` | 백엔드 번들까지만 |
| `--no-launch` | 빌드만 하고 실행 안 함 |
| `--no-clean` | 이전 산출물 유지 |

자동 설치는 외부 통신을 발생시킴. 폐쇄망이나 직접 설치를 원하면 `--no-auto-install`.
Rust 직접 설치는 아래 참조.

```bash
# Windows (PowerShell)
winget install Rustlang.Rustup

# macOS
brew install rustup && rustup-init

# Linux / macOS 공통
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### nuclei 준비

nuclei 는 탐지의 전제 조건. 없으면 결과 조회·보고서는 되지만 스캔 불가.
**앱을 열면 없을 때 안내가 표시되며**, 설정 → **의존성** 에서 세 방법 중 선택

| 방법 | 통신 | 쓰는 경우 |
|---|---|---|
| 자동 설치 | 발생 | 일반 환경. 설정에서 지점을 켠 뒤 확인 |
| 파일 반입 | 없음 | **폐쇄망.** 다른 PC 에서 받아온 바이너리를 업로드 |
| 경로 지정 | 없음 | 이미 설치된 특정 버전을 고정 |

터미널에서 준비하려면 스크립트 사용. Go 툴체인 확인 → 없으면 설치 →
nuclei 빌드까지 수행하며 **관리자 권한 불필요**

```bash
python3 tools/install_nuclei.py
```

| 옵션 | 동작 |
|---|---|
| (없음) | 확인 후 없으면 설치 |
| `--check` | 확인만. 설치되어 있으면 종료 코드 0 |
| `--force` | 이미 있어도 재설치 |

설치 위치는 사용자 홈이며 REDAR 이 자동 탐색. **환경변수 설정 불필요**

```
macOS / Linux   ~/.redar/bin/nuclei          툴체인: ~/.redar/toolchain/go
Windows         %LOCALAPPDATA%\REDAR\bin\nuclei.exe
```

내부 동작은 아래와 같음. Go 는 [공식 배포 목록](https://go.dev/dl/)에서
현재 OS·아키텍처에 맞는 안정판을 받아 **sha256 검증 후** 설치

```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

직접 설치한 nuclei 를 쓰려면 경로 지정

```bash
export REDAR_NUCLEI=/path/to/nuclei      # Windows: set REDAR_NUCLEI=C:\tools\nuclei.exe
```

탐색 순서는 `REDAR_NUCLEI` → 번들 → 사용자 홈 `bin/` → `PATH`.
설치 여부는 화면 상단 상태 띠와 `GET /api/v1/health` 에서 확인.
**nuclei 가 없어도 결과 조회·임포트·설정은 정상 동작**

> **Windows 에서 nuclei 실행이 차단되는 경우**
> `[WinError 4551] 응용 프로그램 제어 정책에 의해 차단` 은
> Smart App Control 이 서명 없는 실행 파일을 막은 것.
> 직접 빌드한 바이너리에서 주로 발생하며 공식 릴리스 파일로 교체 시 대부분 해결

### 가이드 본문 임포트 (선택)

```bash
python -m app.cli import-guide data/guide_items_2026.csv \
                   --images data/guide_items_2026_images.csv
```

미탑재 상태에서도 보고서 Part A 는 정상 생성. Part B 만 안내 문구로 대체

---

## 빌드 상세

배포용 바이너리는 저장소에 미포함. 소스를 받아 직접 빌드

### 빌드가 자동으로 하는 일

`packaging/build.py` 가 아래를 전부 처리. **수동으로 할 필요 없음**

| 단계 | 내용 | 산출물 |
|---|---|---|
| [1] | 가상환경 · `pip install -r requirements.txt` · Node · nuclei | `.venv/` `~/.redar/` |
| [2] | PyInstaller `--onedir` 백엔드 번들 | `dist/redar-backend/` |
| [3] | Tauri 리소스로 스테이징 | `src-tauri/backend/` |
| [4] | Tauri 번들 | `src-tauri/target/release/bundle/` |
| [5] | 앱 실행 | |

시스템 파이썬으로 실행해도 됨. 가상환경을 만든 뒤 그 파이썬으로 자기 자신을 재실행

### 빌드 요구사항

| 항목 | 용도 | 비고 |
|---|---|---|
| Python 3.11+ | 백엔드 번들 | 가상환경은 빌드가 생성 |
| Rust (rustup) | Tauri 셸 | 없으면 빌드가 설치 |
| Node.js 18+ | Tauri CLI (`npx`) | 없으면 빌드가 공식 배포본 설치 |
| Xcode CLT / MSVC 빌드 도구 | 플랫폼 링커 | macOS `xcode-select --install` |

### 백엔드만 확인

```bash
python3 packaging/build.py --backend-only --no-launch
./dist/redar-backend/redar-backend
```

첫 줄에 `REDAR_READY {"port": …}` 가 출력되면 정상. 포트는 매 실행마다
비어 있는 것을 골라 잡으므로 두 번 실행해도 충돌 없음

### 산출물 위치

빌드 끝에 경로가 출력되지만 정리하면 아래와 같음. 전부
`src-tauri/target/release/` 하위

| OS | 실행 파일 | 설치본 |
|---|---|---|
| Windows | `redar.exe` | `bundle/msi/*.msi` · `bundle/nsis/*-setup.exe` |
| macOS | `bundle/macos/REDAR.app` | `bundle/dmg/*.dmg` |
| Linux | `redar` | `bundle/*/*.AppImage` |

Windows 는 `.app` 같은 앱 번들 개념이 없어 **`redar.exe` 를 그대로 실행**하거나
`.msi`·`setup.exe` 로 설치. 설치본은 시작 메뉴에 등록되고 다른 PC 배포에도 사용

### 크로스 컴파일 불가

PyInstaller 는 실행 중인 OS 용 바이너리만 생성.
**Windows 배포본은 Windows 에서, macOS 배포본은 macOS 에서 빌드 필요.**
WSL 에서 빌드하면 리눅스 실행 파일이 나오므로 Windows 배포본으로 쓸 수 없음

### 데이터 저장 위치

번들 실행 시 읽기 전용 리소스와 쓰기 경로가 분리됨

| 구분 | 위치 |
|---|---|
| 번들 리소스 (스키마·CSV·폰트·화면) | 실행 파일 내부 |
| DB·보고서·템플릿 | Windows `%LOCALAPPDATA%\REDAR` · 그 외 `~/.redar` |

`REDAR_HOME` 으로 쓰기 경로 변경 가능. 개발 실행에서는 저장소 루트를 그대로 사용

### nuclei 미동봉

플랫폼별 바이너리 관리 부담과 백신 오탐 때문에 번들에 미포함.
사용자가 직접 확보하며, 번들 옆 `bin/nuclei` 에 두면 그쪽을 우선 탐색

---

## 개발용 수동 설치

아래는 **빌드가 자동으로 수행하는 과정**. 백엔드만 손대거나 API 를 직접 확인할 때 사용

```bash
git clone https://github.com/lxxexxbxx/REDAR.git
cd REDAR

python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux

pip install -r requirements.txt
python -m app.cli init-db
```

`init-db` 는 `redar.db` 를 만들고 번들 데이터를 적재. 재실행해도 안전

```
vuln_type_rules       129행    nuclei 태그·CWE → 취약점 유형
guide_mappings         454행    CWE·노출항목 → 가이드 점검항목
component_advisories   951행    플러그인·테마별 패치 목표 버전
```

웹 서버로 직접 실행

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

브라우저에서 <http://127.0.0.1:8000> 접속.
**개발·디버깅용 경로이며 배포 형태는 데스크톱 앱**

---

## 첫 실행 후 반드시 할 것

**스캔 대상 허용 목록이 비어 있으면 모든 스캔이 거부됨.** 기본값이 전부 차단.

`설정` 화면 → `스캔 허용 대상` 에 대상을 등록.

```
localhost
192.168.1.0/24
```

- 호스트명은 **정확히 일치**해야 한다. DNS 로 해석하지 않음.
- IP 범위를 허용하려면 CIDR 로 등록.
- 등록하지 않은 대상은 `400` 으로 거부됨. 버그가 아니라 의도된 동작.

첫 실행 시 상태는 아래와 같다.

| 항목 | 초기값 |
|---|---|
| 오프라인 모드 | 활성 (외부 통신 4곳 전부 차단) |
| 스캔 허용 대상 | **비어 있음 = 전부 차단** |
| LLM | 비활성 |
| 가이드 본문 | 미탑재 (정상 상태) |
| 매핑 테이블 | 적재됨 (454행) |

---

## 사용 방법

### A. 이 PC 에서 직접 스캔

1. `설정` 에서 대상을 허용 목록에 등록
2. `스캔 실행` 에서 대상·선별 방식·옵션 지정
3. `스캔 시작` — 진행률과 탐지 결과가 실시간으로 표시됨
4. `탐지 결과` 에서 필터·상세 확인, 오탐 표시

선별 방식은 두 가지를 지원.

| 방식 | 내용 |
|---|---|
| 조건 필터 | 태그·심각도로 템플릿 선별 |
| 직접 지정 | 템플릿 ID 를 직접 입력 |

환경 기반 자동 선별은 M4 에서 제공.

### B. 다른 기기에서 실행한 결과 가져오기

REDAR 를 설치할 수 없는 서버·랩 환경에서는 nuclei 만 실행하고 결과 파일을 옮기면 된다.
JSONL 은 nuclei 의 표준 출력 형식이며 REDAR 전용 포맷이 아님.

대상 서버에서:

```bash
nuclei -u http://target.local:8080 -jsonl -o result.jsonl -duc
```

로컬 REDAR 에서:

```bash
python -m app.cli import-scan result.jsonl --target http://target.local:8080 --nuclei-version 3.11.1
```

파싱·저장 경로가 직접 실행과 완전히 동일하므로 결과 화면과 보고서가 그대로 동작.
`--nuclei-version` 은 재현성 기록용이며 생략할 수 있다. 화면에는 `외부 임포트` 로 표시됨.

### 대상 목록 파일 불러오기

`스캔 실행` → `파일에서 불러오기` 로 TXT(줄바꿈 구분) 또는 CSV(첫 열) 를 읽을 수 있다.
해석할 수 없는 줄은 번호로 알려줌.

---

## 화면 구성

| 화면 | 내용 |
|---|---|
| 대시보드 | 심각도·유형 분포, 실행 환경(재현성), 최근 스캔 이력 |
| 스캔 실행 | 대상·선별·옵션 설정, SSE 실시간 진행률과 탐지 피드 |
| 탐지 결과 | 집계, 필터 4종, 상세(요청·응답·재현 명령·오탐 판정) |
| 템플릿 | M5 예정 |
| 보고서 | M7 예정 |
| 설정 | 허용 대상, 오프라인 모드, 외부 통신 3토글, 스캔 기본값, LLM |

화면 상단 상태 띠는 **백엔드 · nuclei · 가이드 DB · 스캔 대상 · 외부 통신** 을 항상 표시.
다섯 항목 모두 도구의 동작 가능 범위를 바꾸는 값.

심각도 5종과 취약점 유형 14종은 **탐지 0건이어도 항상 전부 표시됨.**
원격 스캐너가 점검할 수 있는 범위는 제한적이며, 점검하지 않은 항목이 양호로 읽히면 안 된다.

---

## 외부 통신

REDAR 의 아웃바운드 통신은 아래 네 곳뿐이며 전부 기본 비활성.

| 지점 | 기본값 | 용도 |
|---|---|---|
| nuclei 템플릿 갱신 | 비활성 | 공식 템플릿 동기화. 수동 실행만 |
| LLM API | 비활성 | 보고서 서술문 생성 (선택) |
| CVE 정보 조회 | 비활성 | 부가 정보 (선택) |
| 의존성 자동 설치 | 비활성 | nuclei·Go 설치. 요청마다 확인을 받음 |

오프라인 모드를 켜면 개별 설정과 무관하게 네 곳이 전부 차단됨.
스캔 실행 시 nuclei 의 자동 업데이트 확인도 `-duc` 로 차단.

템플릿은 두 방법으로 준비할 수 있다.

- `templates/official/` 또는 `templates/custom/` 에 직접 파일을 넣음
- 설정에서 `nuclei 템플릿 갱신` 을 허용한 뒤 동기화 (M5)

---

## 환경변수

| 변수 | 기본값 | 용도 |
|---|---|---|
| `REDAR_DB` | `./redar.db` | DB 파일 경로 |
| `REDAR_DATA_DIR` | `./data` | 번들 CSV 위치 |
| `REDAR_NUCLEI` | PATH 탐색 | nuclei 실행 파일 경로 |

---

## 저장소 구조

```
app/
├─ api/            FastAPI 라우터
├─ services/       흐름 제어
├─ adapters/nuclei/ 실행 · JSONL 파싱 · 진행률
├─ domain/         모델 · Enum · fingerprint · 버전 비교
├─ repository/     SQL
├─ config/         설정 · 심각도 환산표
└─ cli.py          init-db · import-scan
frontend/          GUI (순수 HTML/CSS/JS, 빌드 도구 없음)
db/schema.sql      19 테이블 / 5 뷰
data/*.csv         번들 매핑 데이터
assets/fonts/      한글 폰트 (SIL OFL)
tests/             129개
```

의존 방향은 `api → services → repository/adapters → domain` 단방향이다.
GUI 는 SQLite 를 직접 읽지 않고 반드시 HTTP API 를 경유.

---

## 개발

```bash
python -m pytest tests -q
```

nuclei 실행 테스트는 실제 바이너리 대신 `tests/fixtures/nuclei_sample.jsonl` 로 대체.
외부 대상에 요청을 보내는 테스트는 포함하지 않음.

### 데이터 파일

| 파일 | 소유 | 저장소 | 규모 |
|---|---|---|---|
| `db/schema.sql` | 우리 | 포함 | 19 테이블 / 5 뷰 |
| `data/vuln_type_rules.csv` | 우리 산출물 | 포함 | 129행 |
| `data/guide_mappings.csv` | 우리 산출물 | 포함 | 135행 |
| `data/guide_mappings.templates.csv` | 우리 산출물 | 포함 | 319행 |
| `data/component_advisories.csv` | 우리 산출물 | 포함 | 951행 |
| `assets/fonts/*.woff2` | SIL OFL 1.1 | 포함 | 나눔고딕 400/700 + D2Coding. 860KB |
| KISA 가이드 본문 (382항목) | KISA | **미포함** | 저작권. 사용자 임포트 |
| KISA 가이드 캡처 (370장) | KISA | **미포함** | 저작권 |
| nuclei 공식 템플릿 | ProjectDiscovery | **미포함** | 용량 |
| nuclei 바이너리 | ProjectDiscovery | **미포함** | 플랫폼별 |

> 설계 문서(`docs/`, `CHANGELOG.md`, `HANDOFF.md`, `IMPLEMENTATION_BRIEF.md`)는
> 팀 내부 자료이며 이 저장소에 포함하지 않음.

---

## 설계 원칙

1. **로컬 우선** — 모든 처리는 사용자 로컬. 외부 통신은 옵션이며 기본 비활성
2. **clone 후 즉시 실행** — 외부 DB·서비스 의존 없음. SQLite 파일 1개
3. **가이드 DB / LLM 없이도 동작** — 두 요소 모두 선택적
4. **동일 형식 보장** — 어떤 대상으로 돌려도 같은 보고서 목차. 0건인 절도 사라지지 않음
5. **판정하지 않는 영역을 명확히** — 조치 성공 여부는 도구가 판단하지 않음.
   재스캔 결과는 차이만 보고하며, 미탐지가 조치 완료를 의미하지 않음
6. **사용자 코드를 실행하지 않음** — 진단 항목은 nuclei YAML 템플릿으로만 표현
7. **네이티브 의존성 최소화** — 보고서는 자체 완결형 HTML. PDF 렌더러를 별도 번들하지 않음

---

## 진단 대상

WordPress 기반 웹 환경. nuclei 공식 템플릿 중 WordPress 관련 **1,708개**를 사용.

실측 기준 `nuclei-templates` @ `2d5f9b5` (2026-08-26). 템플릿은 계속 갱신되므로 그 시점 스냅샷이다.

| | |
|---|---|
| 취약점 템플릿 | 1,457 |
| 가이드 항목 매핑 성공 | 1,448 (99.4%) |
| 자산 식별(플러그인·테마 탐지) | 251 |
| CVE 보유 | 1,087 |
| 패치 목표 버전 확보 | 1,013 |
| 대상 플러그인/테마 | 726종 (플러그인 667 + 테마 59) |

### 2트랙 매핑

WordPress 플러그인 CVE 는 CWE 유형이 명확해 가이드 10장(Web Application) 항목과 거의 1:1로 붙음.

```
탐지 1건
 ├─ 유형 트랙  CWE → WA-xx    근본 대책 (가이드 원문 인용)
 └─ 패치 트랙  CVE → 목표 버전  즉시 조치 (플러그인 업그레이드)
```

유형 트랙만 두면 "출력값을 인코딩하라" 는 원론만 남고, 패치 트랙만 두면 모든 CVE 가
패치 항목 하나로 수렴해 유형별 조치가 사라짐.

---

## 배포 스택 (예정)

| 영역 | 선택 |
|---|---|
| 백엔드 | Python 3.11+ / FastAPI / SQLite |
| GUI | 순수 HTML/CSS/JS (프레임워크·빌드 도구 없음) |
| 데스크톱 셸 | Tauri v2 + Python sidecar (M10) |
| 패키징 | PyInstaller `--onedir` → Tauri 번들 (M10) |
| 보고서 | Jinja2 → 자체 완결형 HTML → WebView 인쇄 → PDF (M7) |

예상 배포 크기 50~105MB.

---

## 라이선스

코드는 [LICENSE](LICENSE) 참조.
번들 폰트(나눔고딕 · D2Coding)는 SIL Open Font License 1.1 이며
`assets/fonts/LICENSE-OFL.txt` 를 함께 배포.
