# REDAR — 설계 문서

**REDAR**는 Nuclei 기반 웹 취약점 진단 도구다.
스캔 실행, 환경 조사, 보고서 자동 생성을 로컬에서 처리한다.

## 문서

| 순서 | 문서 | 내용 |
|---|---|---|
| 00 | [API 정의서](docs/00_API_SPEC.md) | 엔드포인트, 데이터 모델, Enum |
| 01 | [아키텍처 설계서](docs/01_ARCHITECTURE.md) | 구조, 데이터 흐름, 확장 지점, 보안 |
| 02 | [DB 스키마 설계서](docs/02_DB_SCHEMA.md) | 테이블 설명, 쿼리, 주의사항 |
| 03 | [가이드 데이터 설계서](docs/03_GUIDE_DATA.md) | 3층 구조, 매핑 규칙, 판정 로직 |
| 04 | [보고서 사양서](docs/04_REPORT_SPEC.md) | 섹션 구성, 저하 동작, LLM 서술 |
| 05 | [개발 가이드](docs/05_DEV_GUIDE.md) | 실행, 규약, 확장 방법 |

## 데이터 파일

| 파일 | 소유 | 저장소 | 규모 |
|---|---|---|---|
| `db/schema.sql` | 우리 | 포함 | 19 테이블 / 5 뷰 |
| `data/vuln_type_rules.csv` | 우리 산출물 | 포함 | 129행 |
| `data/guide_mappings.csv` | 우리 산출물 | 포함 | 135행 |
| `data/guide_mappings.templates.csv` | 우리 산출물 | 포함 | 319행 |
| `data/component_advisories.csv` | 우리 산출물 | 포함 | 951행 |
| `tools/extract_guide.py` | 우리 | 포함 | 가이드 PDF → CSV |
| `assets/fonts/*.woff2` | SIL OFL 1.1 | 포함 | 나눔고딕 400/700 + D2Coding. 860KB |
| KISA 가이드 본문 (382항목) | KISA | **미포함 · 별도 전달** | `guide_import/` |
| KISA 가이드 캡처 (370장) | KISA | **미포함 · 별도 전달** | 21MB |

## 설계 원칙

1. **로컬 우선** — 모든 처리는 사용자 로컬. 외부 통신은 옵션이며 기본 비활성
2. **clone 후 즉시 실행** — 외부 DB·서비스 의존 없음
3. **가이드 DB / LLM 없이도 동작** — 두 요소 모두 선택적
4. **동일 형식 보장** — 어떤 대상으로 돌려도 같은 보고서 목차
5. **판정하지 않는 영역을 명확히** — 조치 성공 여부는 도구가 판단하지 않음
6. **네이티브 의존성 최소화** — 보고서는 자체 완결형 HTML. PDF 렌더러를 별도 번들하지 않음

## 진단 대상

WordPress 기반 웹 환경. nuclei 공식 템플릿 중 WordPress 관련 **1,708개**를 사용한다.

실측 기준: `nuclei-templates` @ `2d5f9b5` (2026-08-26).
템플릿은 계속 갱신되므로 아래 수치는 **그 시점의 스냅샷**이다.

| | |
|---|---|
| 취약점 템플릿 | 1,457 |
| 가이드 항목 매핑 성공 | 1,448 (99.4%) |
| 자산 식별(플러그인·테마 탐지) | 251 |
| CVE 보유 | 1,087 |
| 패치 목표 버전 확보 | 1,013 |
| 대상 플러그인/테마 | 726종 |

> `대상 플러그인/테마`는 `data/component_advisories.csv`의 고유 slug 수다
> (951행 / 726종 = 플러그인 667 + 테마 59).
> 초판의 856종은 재현 근거가 없어 실측값으로 대체했다.
> 나머지 수치는 `python3 tools/measure_vuln_type.py --templates <nuclei-templates>`로 재현된다.

## 2트랙 매핑

WordPress 플러그인 CVE는 CWE 유형이 명확해 가이드 10장(Web Application) 항목과 거의 1:1로 붙는다.

```
탐지 1건
 ├─ 유형 트랙  CWE → WA-xx    근본 대책 (가이드 원문 인용)
 └─ 패치 트랙  CVE → 목표 버전  즉시 조치 (플러그인 업그레이드)
```

한쪽만 두면 보고서가 성립하지 않는다. `docs/03_GUIDE_DATA.md` §3.1.1 참조.

## 배포 스택

| 영역 | 선택 |
|---|---|
| 백엔드 | Python 3.11+ / FastAPI / SQLite |
| 데스크톱 셸 | **Tauri v2** + Python sidecar |
| 패키징 | **PyInstaller `--onedir`** → Tauri 번들 |
| 보고서 | Jinja2 → **자체 완결형 HTML** → (WebView 인쇄) → PDF |

예상 배포 크기 50~105MB. 자세한 근거는 `docs/01_ARCHITECTURE.md` §5.

> **용량은 차별점이 아니다.** nuclei CLI 단일 바이너리(30MB)를 크기로 이길 수 없다.
> REDAR 의 성능 차별점은 환경 기반 템플릿 선별로 **요청 수와 스캔 시간**을 줄이는 것이다.
> 시연 시 전량 실행(baseline)과 선별 실행을 함께 측정해 비교한다.

## 개발 순서

```
M0 → M1 → M2 → M3 ┬ M4 환경 수집기      S1 스파이크 → M7 보고서
                  ├ M5 템플릿 빌더            ↓
                  └ M6 가이드 매핑        M8 → M9 → M10 패키징
```

`IMPLEMENTATION_BRIEF.md` 참조. **S1(WebView 인쇄 검증)은 M7 착수 전 필수다.**

## 문서 버전

**v0.3.** 변경 내역과 근거는 [CHANGELOG.md](CHANGELOG.md).
팀 인수인계·미결 결정사항은 [HANDOFF.md](HANDOFF.md).

- v0.1 → v0.2 가이드 코드 체계 확정, 데이터 실적재 (병목 해소)
- v0.2 → v0.3 배포·패키징 스택 확정. **DB 스키마·데이터 무변경**
