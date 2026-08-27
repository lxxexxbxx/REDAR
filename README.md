# REDAR

Nuclei 기반 웹 취약점 **진단** 도구. 스캔 실행, 결과 정리, 보고서 생성을 로컬에서 처리한다.

- 모든 처리는 사용자 PC 안에서 끝난다. 외부 통신은 옵션이며 기본 비활성이다.
- 다른 기기에서 실행한 nuclei 결과를 가져와 분석할 수 있다.
- 가이드 DB 나 LLM 없이도 정상 동작한다.

---

## 구현 상태

| 단계 | 내용 | 상태 |
|---|---|---|
| M0 | DB 적재 파이프라인 · FastAPI 뼈대 | 완료 |
| M1 | 도메인 모델 · fingerprint · 심각도 환산 · 버전 비교 | 완료 |
| M2 | nuclei 실행 · JSONL 파싱 · 결과 저장 | 완료 |
| M3 | 스캔 API · SSE 진행률 · 결과 조회 · 설정 | 완료 |
| — | GUI (대시보드 · 스캔 · 결과 · 설정) | 완료 |
| M4 | 환경 수집기 (제품·버전·플러그인 식별) | 예정 |
| M5 | 템플릿 관리 · 폼 기반 빌더 | 예정 |
| M6 | 가이드 매핑 엔진 | 예정 |
| M7 | 보고서 생성 (HTML → PDF) | 예정 |
| M8~M10 | 스캔 비교 · LLM 서술 · 데스크톱 패키징 | 예정 |

GUI 의 **템플릿 · 보고서** 화면은 아직 안내 문구만 표시한다.

---

## 빠른 시작

### 1. 요구사항

| 항목 | 버전 | 비고 |
|---|---|---|
| Python | 3.11 이상 | |
| nuclei | 3.x | 별도 설치. 저장소에 포함하지 않는다 |
| OS | Windows / macOS / Linux | |

### 2. 설치

```bash
git clone https://github.com/lxxexxbxx/REDAR.git
cd REDAR
python -m venv .venv
```

가상환경 활성화 — Windows:

```bash
.venv\Scripts\activate
```

macOS / Linux:

```bash
source .venv/bin/activate
```

의존성 설치:

```bash
pip install -r requirements.txt
```

### 3. DB 초기화

```bash
python -m app.cli init-db
```

`redar.db` 파일 하나가 생기고 번들 데이터가 적재된다. 재실행해도 안전하다.

```
vuln_type_rules       129행    nuclei 태그·CWE → 취약점 유형
guide_mappings         454행    CWE·노출항목 → 가이드 점검항목
component_advisories   951행    플러그인·테마별 패치 목표 버전
```

### 4. 실행

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

브라우저에서 **http://127.0.0.1:8000** 을 연다. (데스크톱 앱 셸은 M10 에서 제공)

### 5. nuclei 설치

[ProjectDiscovery 릴리스](https://github.com/projectdiscovery/nuclei/releases)에서
플랫폼용 압축 파일을 받아 `PATH` 에 두거나, 경로를 환경변수로 지정한다.

```bash
export REDAR_NUCLEI=/path/to/nuclei      # Windows: set REDAR_NUCLEI=C:\tools\nuclei.exe
```

설치 여부는 화면 상단 상태 띠와 `GET /api/v1/health` 에서 확인할 수 있다.
**nuclei 가 없어도 결과 조회·임포트·설정은 정상 동작한다.**

> **Windows 에서 nuclei 실행이 차단되는 경우**
> `[WinError 4551] 응용 프로그램 제어 정책에 의해 차단` 이 나오면
> Smart App Control 이 서명 없는 실행 파일을 막은 것이다.
> 직접 빌드한 바이너리에서 주로 발생하며, 공식 릴리스 파일로 교체하면 대부분 해결된다.

---

## 첫 실행 후 반드시 할 것

**스캔 대상 허용 목록이 비어 있으면 모든 스캔이 거부된다.** 기본값이 전부 차단이다.

`설정` 화면 → `스캔 허용 대상` 에 대상을 등록한다.

```
localhost
192.168.1.0/24
```

- 호스트명은 **정확히 일치**해야 한다. DNS 로 해석하지 않는다.
- IP 범위를 허용하려면 CIDR 로 등록한다.
- 등록하지 않은 대상은 `400` 으로 거부된다. 버그가 아니라 의도된 동작이다.

첫 실행 시 상태는 아래와 같다.

| 항목 | 초기값 |
|---|---|
| 오프라인 모드 | 활성 (외부 통신 3곳 전부 차단) |
| 스캔 허용 대상 | **비어 있음 = 전부 차단** |
| LLM | 비활성 |
| 가이드 본문 | 미탑재 (정상 상태) |
| 매핑 테이블 | 적재됨 (454행) |

---

## 사용 방법

### A. 이 PC 에서 직접 스캔

1. `설정` 에서 대상을 허용 목록에 등록
2. `스캔 실행` 에서 대상·선별 방식·옵션 지정
3. `스캔 시작` — 진행률과 탐지 결과가 실시간으로 표시된다
4. `탐지 결과` 에서 필터·상세 확인, 오탐 표시

선별 방식은 두 가지를 지원한다.

| 방식 | 내용 |
|---|---|
| 조건 필터 | 태그·심각도로 템플릿 선별 |
| 직접 지정 | 템플릿 ID 를 직접 입력 |

환경 기반 자동 선별은 M4 에서 제공한다.

### B. 다른 기기에서 실행한 결과 가져오기

REDAR 를 설치할 수 없는 서버·랩 환경에서는 nuclei 만 실행하고 결과 파일을 옮기면 된다.
JSONL 은 nuclei 의 표준 출력 형식이며 REDAR 전용 포맷이 아니다.

대상 서버에서:

```bash
nuclei -u http://target.local:8080 -jsonl -o result.jsonl -duc
```

로컬 REDAR 에서:

```bash
python -m app.cli import-scan result.jsonl --target http://target.local:8080 --nuclei-version 3.11.1
```

파싱·저장 경로가 직접 실행과 완전히 동일하므로 결과 화면과 보고서가 그대로 동작한다.
`--nuclei-version` 은 재현성 기록용이며 생략할 수 있다. 화면에는 `외부 임포트` 로 표시된다.

### 대상 목록 파일 불러오기

`스캔 실행` → `파일에서 불러오기` 로 TXT(줄바꿈 구분) 또는 CSV(첫 열) 를 읽을 수 있다.
해석할 수 없는 줄은 번호로 알려준다.

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

화면 상단 상태 띠는 **백엔드 · nuclei · 가이드 DB · 스캔 대상 · 외부 통신** 을 항상 표시한다.
다섯 항목 모두 도구의 동작 가능 범위를 바꾸는 값이다.

심각도 5종과 취약점 유형 14종은 **탐지 0건이어도 항상 전부 표시된다.**
원격 스캐너가 점검할 수 있는 범위는 제한적이며, 점검하지 않은 항목이 양호로 읽히면 안 된다.

---

## 외부 통신

REDAR 의 아웃바운드 통신은 아래 세 곳뿐이며 전부 기본 비활성이다.

| 지점 | 기본값 | 용도 |
|---|---|---|
| nuclei 템플릿 갱신 | 비활성 | 공식 템플릿 동기화. 수동 실행만 |
| LLM API | 비활성 | 보고서 서술문 생성 (선택) |
| CVE 정보 조회 | 비활성 | 부가 정보 (선택) |

오프라인 모드를 켜면 개별 설정과 무관하게 세 곳이 전부 차단된다.
스캔 실행 시 nuclei 의 자동 업데이트 확인도 `-duc` 로 차단한다.

템플릿은 두 방법으로 준비할 수 있다.

- `templates/official/` 또는 `templates/custom/` 에 직접 파일을 넣는다
- 설정에서 `nuclei 템플릿 갱신` 을 허용한 뒤 동기화한다 (M5)

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
GUI 는 SQLite 를 직접 읽지 않고 반드시 HTTP API 를 경유한다.

---

## 개발

```bash
python -m pytest tests -q
```

nuclei 실행 테스트는 실제 바이너리 대신 `tests/fixtures/nuclei_sample.jsonl` 로 대체한다.
외부 대상에 요청을 보내는 테스트는 포함하지 않는다.

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
> 팀 내부 자료이며 이 저장소에 포함하지 않는다.

---

## 설계 원칙

1. **로컬 우선** — 모든 처리는 사용자 로컬. 외부 통신은 옵션이며 기본 비활성
2. **clone 후 즉시 실행** — 외부 DB·서비스 의존 없음. SQLite 파일 1개
3. **가이드 DB / LLM 없이도 동작** — 두 요소 모두 선택적
4. **동일 형식 보장** — 어떤 대상으로 돌려도 같은 보고서 목차. 0건인 절도 사라지지 않는다
5. **판정하지 않는 영역을 명확히** — 조치 성공 여부는 도구가 판단하지 않는다.
   재스캔 결과는 차이만 보고하며, 미탐지가 조치 완료를 의미하지 않는다
6. **사용자 코드를 실행하지 않는다** — 진단 항목은 nuclei YAML 템플릿으로만 표현한다
7. **네이티브 의존성 최소화** — 보고서는 자체 완결형 HTML. PDF 렌더러를 별도 번들하지 않는다

---

## 진단 대상

WordPress 기반 웹 환경. nuclei 공식 템플릿 중 WordPress 관련 **1,708개**를 사용한다.

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

WordPress 플러그인 CVE 는 CWE 유형이 명확해 가이드 10장(Web Application) 항목과 거의 1:1로 붙는다.

```
탐지 1건
 ├─ 유형 트랙  CWE → WA-xx    근본 대책 (가이드 원문 인용)
 └─ 패치 트랙  CVE → 목표 버전  즉시 조치 (플러그인 업그레이드)
```

유형 트랙만 두면 "출력값을 인코딩하라" 는 원론만 남고, 패치 트랙만 두면 모든 CVE 가
패치 항목 하나로 수렴해 유형별 조치가 사라진다.

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
`assets/fonts/LICENSE-OFL.txt` 를 함께 배포한다.
