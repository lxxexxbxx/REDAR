# CLAUDE.md

이 파일은 Claude Code가 이 저장소에서 작업할 때 항상 참조하는 프로젝트 규칙이다.
저장소 루트에 둔다.

---

## 프로젝트

**REDAR** — Nuclei 기반 웹 취약점 **진단** 도구.
스캔 실행, 대상 환경 조사, 보고서 자동 생성을 로컬에서 처리한다.

**단일 데스크톱 앱**이다. `frontend/`(바닐라 JS)가 같은 프로세스의 HTTP API를 호출하고,
Tauri v2 셸이 Python sidecar 를 기동해 WebView 로 감싼다. 웹 서버 실행은 개발용 경로다.

**주 진단 대상**: WordPress 기반 웹 환경 (AWS EC2 + Docker 랩)

---

## 설계 문서 (작업 전 반드시 확인)

| 문서 | 언제 읽는가 |
|---|---|
| `docs/00_API_SPEC.md` | 엔드포인트·데이터 모델·Enum 구현 시 |
| `docs/01_ARCHITECTURE.md` | 모듈 배치, 계층 경계, 확장 지점 |
| `docs/02_DB_SCHEMA.md` | DB 접근 코드 작성 시 |
| `docs/03_GUIDE_DATA.md` | 가이드 매핑·판정 로직 구현 시 |
| `docs/04_REPORT_SPEC.md` | 보고서 빌더·렌더러 구현 시 |
| `docs/05_DEV_GUIDE.md` | 규약, 확장 방법, 자주 하는 실수 |
| `CHANGELOG.md` | 버전별 변경 내역과 근거 (최신 v0.5, §22) |
| `HANDOFF.md` | 팀 인수인계. 미결 결정사항과 검증 방법 |

> **위 문서는 저장소에 없다.** `docs/`·`CHANGELOG.md`·`HANDOFF.md`·`IMPLEMENTATION_BRIEF.md`
> 는 저장소 밖에서 별도 관리하며 `.gitignore` 대상이다. 이 파일과 `README.md` 만 커밋한다.
> 문서 없이 작업해야 하는 상황이면 추측하지 말고 사용자에게 해당 문서를 요청한다.

**문서와 코드가 어긋나면 문서가 기준이다.** 설계를 바꿔야 한다고 판단되면 코드를 먼저 고치지 말고 사용자에게 확인을 요청한다.

**현재 문서 버전은 v0.5다** (`CHANGELOG.md` §22). v0.1 기준으로 적힌 숫자(`VulnType 11종`, `테이블 17개` 등)를
어딘가에서 발견하면 갱신 누락이므로 보고한다.

---

## 절대 규칙 (위반 금지)

아래는 제품 요구사항에서 나온 제약이다. 편의를 위해 우회하지 않는다.

### 1. 사용자 코드를 실행하지 않는다
- 스크립트 업로드/실행 기능을 만들지 않는다
- 커스텀 진단은 **YAML 템플릿으로만** 표현하며 nuclei가 실행한다
- `eval`, `exec`, 동적 import로 사용자 입력을 처리하지 않는다

### 2. LLM 없이 완전히 동작해야 한다 (v0.3 개정)
- LLM 호출은 **반드시** `try/except`로 감싸고 실패를 상위로 전파하지 않는다
- **보고서 본문은 LLM을 쓰지 않는다.** 심각도·버전·양호/취약 판정은 전부 결정론이며,
  같은 스캔에 항상 같은 보고서가 나와야 근거 대조가 성립한다
- LLM은 판정·구조 결정에 개입 금지
- 조치방법은 가이드 원문을 그대로 인용한다 (절대규칙 9). LLM이 이를 대체하지 않는다
- **예외로 조치 상세 가이드(보고서 Part D)만 LLM이 생성한다.**
  완성된 보고서를 입력으로 받으며 본문을 바꾸지 않고, 생성 출처를 명시한다
- Part D가 없어도 보고서는 완성품이다. Part A·B·부록이 전부 정상 생성된다 (Part C 재진단 비교는 v0.2 에서 제외)

### 3. 가이드 DB 없이 동작해야 한다
- `guide_items` 조회는 항상 실패 가능으로 처리한다
- 미탑재 상태에서 보고서 Part A(진단 결과)는 **정상 생성**되어야 한다
- `finding_guide_refs.item_code`에 FK를 걸지 않는다

### 4. 보고서 형식은 대상과 무관하게 동일하다
- 섹션을 조건부로 생성하지 않는다
- 0건인 섹션은 사라지지 않고 "해당 없음"으로 렌더링된다
- `VulnType` **14종**, 심각도 5종은 **항상 전부 표시**한다

### 4-1. 보고서 렌더링에 네이티브 의존성을 추가하지 않는다
- **WeasyPrint / wkhtmltopdf / Chromium 별도 번들 금지**
- 보고서는 자체 완결형 HTML 을 1차 산출물로 만들고, PDF 는 WebView 인쇄로 파생시킨다
- HTML 은 외부 CSS·폰트·이미지를 참조하지 않는다 (전부 인라인/base64)
- 이유: Tauri 의 WebView 가 이미 렌더링 엔진이다. 두 번 넣지 않는다

### 5. 외부 통신은 4곳뿐이다
- nuclei 템플릿 갱신 / LLM API / CVE 조회(선택) / **의존성 자동 설치(nuclei·Go)**
- 전부 기본 비활성이며 오프라인 모드에서 차단된다
- 의존성 설치는 3중 통제다: 요청마다 명시 동의 → 오프라인 검사 → 지점 활성 검사.
  세 검사 모두 네트워크에 닿기 전에 끝난다 (`docs/01` §7.1)
- 폐쇄망 대체 경로가 항상 있어야 한다. 파일 반입·경로 지정은 통신이 없다
- 스캔 실행 중에는 어떤 아웃바운드도 없다. nuclei 에 `-duc` 를 붙여 자동 갱신을 막는다.
  진단 대상으로 나가는 요청은 여기서 말하는 아웃바운드가 아니다 - 그것이 진단 자체다
- **이 외의 아웃바운드 통신을 코드에 추가하지 않는다**

### 6. 스캔 대상은 입력 즉시 실행한다 (v0.3 변경)
- **설정의 허용 목록 등록 절차를 없앴다.** 스캔 화면에 넣은 대상을 바로 실행한다
- 근거: 로컬 데스크톱 전용 도구다. 같은 대상을 설정과 스캔 화면에 두 번 입력하게 하면
  통제가 아니라 마찰만 남는다. 실제로 등록해 둔 대상이 거부되는 사고가 반복됐다
- 대신 **실행 전 확인**으로 통제한다
  - 포트 범위(`localhost:8000-8100`)는 개별 대상으로 전개하고, 전개 수가
    `CONFIRM_THRESHOLD` 를 넘으면 사용자 확인 없이는 시작하지 않는다
  - TCP 프로브로 응답 없는 대상을 먼저 걸러낸다. 전부 무응답이면 거부한다
  - 템플릿 0개면 거부한다. 스캔이 성립하지 않는데 0건으로 끝내지 않는다 (절대규칙 10)
- 대상 정규화는 유지한다. 호스트 단위로 정규화해 저장·표기 양쪽에서 같은 값을 쓴다
  (`http://localhost:8080/admin` -> `localhost:8080`)
- 조치 대상 표기는 뭉개지 않는다 (절대규칙 11)

### 7. 파생값은 계산이 아니라 저장한다
- `severity_guide`, `vuln_type`, `fingerprint`는 탐지 시점에 계산해 DB에 저장
- 렌더링 시점에 다시 계산하지 않는다
- 단, **가이드 원문 값은 파생값이 아니다.** 점검항목 중요도는 `guide_items.severity_guide`를
  그대로 쓴다. `findings.severity_guide`(탐지 심각도 환산값)로 덮어쓰지 않는다

### 8. clone 후 즉시 실행 가능해야 한다
- 외부 DB·서비스 의존 금지 (SQLite 파일 1개)
- `data/*.csv`는 저장소에 포함되며 `init-db`가 적재한다
- **KISA 가이드 본문(`data/guide_items*.csv`)은 이번 과제에 한해 저장소에 포함한다.**
  실서비스가 아닌 과제 산출물이라는 전제로 둔 예외이며, `init-db` 가 적재해 clone 후
  바로 Part B 가 동작한다. 외부 배포·상용 전환 시 최우선 제외 대상 (CHANGELOG §22.14)
- 가이드 캡처(`data/guide_images/`)와 원문 PDF 는 예외 없이 저장소에 넣지 않는다

### 9. 가이드 원문을 재작성하지 않는다
- `guide_items.remediation` / `case_text`는 **그대로 인용**한다. LLM이 다듬은 문장으로 대체 금지
- 보고서에 원문과 생성문을 시각적으로 분리하고 출처 페이지를 표기한다
- 근거: 조치 문구가 재작성되면 원문 대조가 불가능해져 보고서의 근거성이 사라진다

### 10. "탐지되지 않음"을 "양호"로 표기하지 않는다
- nuclei는 원격 스캐너다. 가이드 382개 항목 중 자동 점검 가능한 것은 36개뿐이다
- 보고서 Part B에 커버리지 고지를 **반드시** 넣는다 (`04_REPORT_SPEC.md` B-1)
- `safe`와 `not_applicable`을 구분한다 (`03_GUIDE_DATA.md` §5.1)
- **스캔이 성립하지 않는 상태를 0건으로 끝내지 않는다.** 템플릿 0개면 nuclei 가
  아무것도 실행하지 않고 정상 종료하므로, 사전 점검에서 이유를 밝히며 거부한다
  (`scan_service.preflight`)

### 11. 조치 대상은 뭉개지 않는다
- 포트 범위로 스캔해도 **개별 탐지 결과·조치 대상은 실제 포트**로 표기한다
- 범위 표기는 스캔 요약·보고서 개요에만 쓴다 (입력 원문 `scans.target_input`)
- 근거: `localhost:33-4444` 로 표기하면 어느 포트를 막아야 할지 알 수 없고 재현도 불가

---

## 기술 스택

| 영역 | 선택 | 비고 |
|---|---|---|
| Python | 3.11+ | |
| 웹 | FastAPI | SSE 사용 |
| 검증 | Pydantic v2 | Enum을 코드로 강제 |
| DB | SQLite | `PRAGMA foreign_keys=ON` 연결마다 필요 |
| 템플릿 | Jinja2 | 보고서 골격 |
| 보고서 출력 | **자체 완결형 HTML → WebView 인쇄 → PDF** | WeasyPrint 사용 금지. `docs/01` §5.2 |
| GUI | **바닐라 JS + 해시 라우팅** | 빌드 도구 없음. `frontend/` 를 그대로 서빙 |
| 데스크톱 셸 | **Tauri v2 + Python sidecar** | Rust 코드는 sidecar 기동뿐 (20~30줄) |
| 패키징 | **PyInstaller `--onedir`** | onefile 은 실행 지연 9~18초 (실측) |
| 빌드 툴체인 | Rust(rustup) · Node.js(npx) | 없으면 `packaging/build.py` 가 확보 |
| 스캐너 | nuclei 3.x | 외부 바이너리. 저장소 미포함 |

**임의로 라이브러리를 추가하지 않는다.** 필요하면 이유와 함께 먼저 제안한다.
`tools/install_nuclei.py` 는 배포 전 단계에서 도는 스크립트라 **stdlib 만** 쓴다.

### 빌드

```bash
python3 packaging/build.py        # venv·의존성·Node·Rust·nuclei·번들·실행 일괄
```

시스템 파이썬으로 실행해도 된다. 가상환경을 만든 뒤 그 파이썬으로 자기 자신을 재실행한다.
툴체인 자동 설치가 기본이며 `--no-auto-install` 로 끄면 OS별 설치 방법만 출력한다.
**로컬 데스크톱 전용이다.** 디스플레이 없는 서버용 경로는 제공하지 않는다.

---

## 저장소 구조

```
app/
├─ api/            FastAPI 라우터. HTTP 전용, 비즈니스 판단 금지
│                  scans · reports · templates · guide · settings_api · dependencies
│                  remediation · logs
├─ services/       흐름 제어. HTTP 객체 참조 금지
│                  scan · selection · environment · template(builder/validator)
│                  guide(importer) · report · remediation · dependency
├─ adapters/
│   ├─ nuclei/     실행 · JSONL 파싱 · 진행률
│   └─ llm/        Null / MonoGPT / masking
├─ collectors/     노출 점검 수집기 (generic-http · wordpress). pkgutil 자동 등록
├─ domain/         Pydantic 모델 · Enum · fingerprint · allowlist · target_range
│                  template_meta · template_exclusion · tech_profile (제외 계산·환경 해석)
├─ repository/     SQL 전용
├─ report/
│   ├─ builder.py  Report JSON 조립
│   ├─ fallback.py LLM 미사용 시 문장
│   └─ templates/  Jinja2 = 보고서 골격
├─ config/
└─ cli.py
db/
├─ schema.sql
└─ migrations/
    ├─ 003_scan_target_input.sql     # scans.target_input (포트 범위 원문)
    ├─ 004_scan_target_reachable.sql # scan_targets.reachable (TCP 프로브 결과)
    ├─ 005_template_platform.sql     # templates.platform (제품 표지)
    └─ 006_scan_mode_full_scan.sql   # scans.selection_mode 에 full_scan (테이블 재구성)
data/                            # 전부 저장소 포함 (우리 산출물)
├─ vuln_type_rules.csv           # 129행
├─ guide_mappings.csv            # 135행
├─ guide_mappings.templates.csv  # 319행
├─ component_advisories.csv      # 951행
├─ settings_defaults.csv         # 14행. 설정 기본값
├─ guide_items*.csv              # 저장소 포함 (과제 한정 예외). 가이드 본문
└─ guide_images/                 # gitignore. 가이드 캡처 370장
frontend/                        # 바닐라 JS GUI. 빌드 도구 없음 (해시 라우팅)
├─ index.html
├─ css/app.css
└─ js/                           # app · api · ui · templates · reports · remediation · tasks · dependencies
packaging/                       # 데스크톱 번들
├─ build.py                      # 원클릭 빌드 (venv~실행 일괄)
├─ backend.spec                  # PyInstaller --onedir
└─ entrypoint.py                 # 동적 포트 + REDAR_READY 알림
src-tauri/                       # Tauri v2 셸. sidecar 기동 · 아이콘
tools/                           # 오프라인 데이터 생성·검증 (런타임 아님)
├─ extract_guide.py              # 가이드 PDF -> 임포트 CSV
├─ verify_guide.py               # 추출 결과 원문 대조
├─ build_data_csv.py             # 번들 CSV 재생성
├─ install_nuclei.py             # Go 확인·설치 -> nuclei 빌드 (stdlib 전용)
└─ measure_vuln_type.py          # 분류 정확도 실측
assets/fonts/                    # 한글 폰트 (OFL). 보고서 base64 임베딩용
templates/                       # 사용자 데이터 경로 하위 (HOME/templates)
├─ official/                     # gitignore. sync 로 내려받음
└─ custom/                       # 사용자 작성
tests/
docs/                            # gitignore. 저장소 밖 관리
CHANGELOG.md                     # gitignore. 저장소 밖 관리
HANDOFF.md                       # gitignore. 저장소 밖 관리
```

`tools/`는 **런타임 코드가 아니다.** `app/`에서 import하지 않는다.
저장소 데이터를 만들거나 의존성을 확보할 때만 손으로 실행한다.

**의존 방향은 위→아래 단방향.** `services`가 `api`를 import하지 않는다.

**읽기 전용 리소스와 쓰기 경로를 분리한다** (`app/config/settings.py`).
번들 리소스는 `resource_path()`, DB·보고서·템플릿은 `HOME`(개발=저장소 루트,
번들=`~/.redar` 또는 `%LOCALAPPDATA%\REDAR`). PyInstaller 는 번들을 임시 디렉터리에
풀기 때문에 그 안에 쓰면 재시작 시 소실된다.

---

## 코딩 규약

- 타입 힌트 필수. Pydantic 모델로 경계를 강제한다
- Enum은 `app/domain/enums.py` 한 곳에 정의하고 문자열 리터럴을 흩뿌리지 않는다
- SQL은 `repository/`에만 둔다. 서비스 계층에 SQL 문자열이 등장하면 잘못된 것이다
- 로그에 응답 본문·자격증명을 남기지 않는다
- 주석은 "무엇"이 아니라 **"왜"**. 절대 규칙 관련 코드에는 근거 명시
- **문체: 간결한 명사형 종결.** 주석·독스트링·커밋 메시지·보고 전부 동일
  - `커넥션마다 설정이 필요하다` (X) -> `커넥션마다 설정 필요` (O)
  - `~한다`, `~이다`, `~해야 한다` 같은 서술체 금지
  - 한 줄로 끝낼 것. 설명이 길어지면 문서로 옮김

---

## 자주 하는 실수

| 증상 | 원인 | 조치 |
|---|---|---|
| FK가 동작하지 않음 | SQLite 기본 OFF | 연결마다 `PRAGMA foreign_keys=ON` |
| 심각도 정렬이 뒤죽박죽 | 문자열 정렬 | `ORDER BY CASE severity ...` |
| 재스캔 비교에서 전부 신규 | fingerprint에 쿼리스트링 포함 | 경로 정규화 확인 |
| 스캔 중 DB 잠김 | WAL 미설정 / 병렬 쓰기 | WAL + 단일 워커 + `busy_timeout` |
| 보고서 목차가 대상마다 다름 | 조건부 섹션 생성 | 골격 고정 + 빈 상태 렌더링 |
| 패치 목표 버전이 실제보다 낮음 | 버전 문자열 `MAX()` (`4.10.1` < `4.9.0`) | `fixed_version_key` 사용 |
| Part B 중요도가 가이드 원문과 다름 | `findings.severity_guide` 사용 | `guide_items.severity_guide` |
| 모든 CVE가 `WEB-25` 하나로 몰림 | `is_primary` 미설정 | 유형 트랙을 primary로 |
| 플러그인 탐지가 취약점으로 집계 | `templates.is_detection` 미확인 | 자산 식별 템플릿은 부록 |
| 템플릿 빌더가 공식 템플릿을 못 읽음 | 미지원 문법 | 실패 처리 대신 `unsupported_fields` 반환 |
| 스캔이 늘 0건 | 템플릿을 `-t` 로 안 넘김 | `-id`·`-tags` 는 **로드된 것 중** 고르는 필터. 트리 경로를 함께 전달 |
| 대상 포트에 아무 요청도 안 감 | 대상에 포트 누락 | nuclei 는 URL 의 포트만 봄. 포트 범위 옵션 없음 |
| 템플릿 색인이 통째로 실패 | 범위 밖 `severity` (`unknown`) | CHECK 통과값만 저장 + `executemany` 실패 시 행 단위 재시도 |
| 고정 경로 라우트가 404 | `/scans/{scan_id}` 가 먼저 매칭 | `/scans/preflight` 같은 고정 경로를 먼저 등록 |
| 번들에서 `Could not import module` | `uvicorn.run("app.main:app")` | 문자열 대신 앱 객체 전달 |
| 번들 아이콘 생성 실패 | PNG 만 등록 | macOS `.icns` · Windows `.ico` 를 함께 등록 |
| 테스트가 서로 오염 | `db_path` 가 session 스코프 | 픽스처가 넣은 행은 teardown 에서 반드시 제거 |
| `nuclei -validate` 가 60초 걸림 | 첫 실행 초기화 + stdin 대기 | 모든 호출에 `stdin=DEVNULL` |
| 환경 기반 선별 후 미탐지 | 표시명(`apache`)으로 표지(`http_server`) 대조 | 탐지 집합을 템플릿 표지에서 생성 (`template_exclusion`) |
| 스캔이 수 배 느림 | 전수 열거 템플릿 2개 (요청 76%) | 기본 `-eid` 제외 유지. 필요 시 설정 opt-in |
| 정상 종료한 nuclei 가 종료 코드 1 | stdout EOF 직후 terminate (Windows) | EOF 후 `wait` 로 자연 종료 대기 |
| 새 모드 값이 저장 안 됨 | `scans.selection_mode` CHECK | CHECK 변경 불가. FK 끄고 테이블 재구성 (006) |
| 실제 스캔에서 진행률이 멈춤 | nuclei 3.x stats 가 JSON 한 줄 | `progress.parse_stats_line` JSON 해석. 픽스처도 실측 형식으로 |
| 실제 스캔이 중간에 멈춤 | 리더 스레드 콜백이 스캔 스레드 sqlite 연결 사용 | 러너 출력은 큐로, DB 는 스캔 스레드만. 가짜 러너도 콜백을 별도 스레드에서 호출해 검증 |

---

## 테스트

- nuclei 실행 테스트는 **실제 바이너리 대신 JSONL 샘플 파일**로 대체한다
- 외부 대상에 요청을 보내는 테스트를 CI에 넣지 않는다
- 커맨드 **조립도 주입 대상**이다. `build_command` 가 바이너리 존재를 요구하므로
  이것까지 열지 않으면 nuclei 없이 API 테스트가 불가능하다
- 문구를 그대로 박아 단언하지 않는다. 표현이 바뀌면 깨진다.
  고지·메시지는 상수에서 끌어와 **존재 여부**를 검증한다
- 아래 케이스는 반드시 자동화한다:
  - `TC-R05` 탐지 0건 → 모든 섹션 "해당 없음", 목차 동일
  - `TC-R07` 서로 다른 두 대상 → 보고서 목차 구조 완전 일치
  - `TC-V01` 버전 비교: `4.10.1 > 4.9.0` 판정

```bash
.venv/bin/python -m pytest tests/ -q
```

---

## 작업 방식

- 한 번에 하나의 마일스톤만 진행한다 (`IMPLEMENTATION_BRIEF.md` 참조)
- 마일스톤 완료 시 **완료 조건을 스스로 검증**하고 결과를 보고한다
- 설계 문서에 없는 결정이 필요하면 **임의로 정하지 말고 질문한다**
- 커밋 메시지 형식: `<type>: <Mx> - <작업 내용 요약>`

  ```
  feat: M0 - DB, FastAPI, 세팅 관련 내용 구현 완료
  ```

  | type | 용도 |
  |---|---|
  | `feat` | 새로운 기능 추가 |
  | `fix` | 버그(오류) 수정 |
  | `docs` | 문서 수정 |
  | `style` | 코드 형식 수정 (로직 변경 없음) |
  | `refactor` | 코드 리팩토링 (구조 개선) |
  | `test` | 테스트 코드 추가·수정 |
  | `chore` | 빌드 설정, 패키지 수정 등 기타 |

  **한 문장으로 끝낸다. 본문을 붙이지 않는다.** 아래는 넣지 않는다.
  - 검증 결과·행 수·테스트 통과 수 (커밋 메시지 아님)
  - `Co-Authored-By` 등 생성 도구 트레일러
