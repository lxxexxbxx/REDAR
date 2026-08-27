# 한글 폰트

보고서 HTML 에 **base64 로 임베딩**할 폰트다.
보고서는 자체 완결형이어야 하므로 외부 폰트를 참조하지 않는다 (`docs/04_REPORT_SPEC.md` §3.1).

---

## 구성

| 파일 | 용도 | 크기 |
|---|---|---|
| `NanumGothic.woff2` | 본문 (weight 400) | 240 KB |
| `NanumGothicBold.woff2` | 강조 (weight 700) | 306 KB |
| `D2Coding.woff2` | 요청·응답 원문, 코드 블록 (고정폭) | 314 KB |
| **합계** | | **860 KB** |

base64 임베딩 시 약 **1.1 MB** 가 보고서 HTML 1건에 더해진다.

### 서브셋 범위

원본 나눔고딕 TTF 는 4.5 MB, 전체 패밀리는 304 MB 다.
보고서에 필요한 문자만 남기고 woff2 로 변환해 **1/18 로 줄였다.**

```
U+0020-007E   ASCII
U+00A0-00FF   Latin-1               ° ± × ÷
U+2000-206F   일반 구두점            — – …
U+20A0-20BF   통화 기호
U+2190-21FF   화살표                 → ⇒     ← 패치 목표 버전 표기에 사용
U+2200-22FF   수학 연산자            ≥ ≤ ≠
U+25A0-25FF   도형                   ■ □ ● ○ ▲ ▼
U+2600-26FF   기타 기호              ※ ★ ☆
U+3000-303F   CJK 구두점             「」『』〈〉
U+3131-318E   한글 자모
U+AC00-D7A3   한글 음절 전체 11,172자
U+FF00-FFEF   전각 형태
```

**한글 음절은 11,172자 전부 포함한다.** 상용 2,350자만 넣으면 드물게 쓰이는 글자가
`□` 로 나오는데, 플러그인 이름이나 가이드 원문 인용에서 실제로 발생한다.

---

## 사용

```css
@font-face {
  font-family: 'NanumGothic';
  font-weight: 400;
  font-style: normal;
  font-display: swap;
  src: url(data:font/woff2;base64,<BASE64>) format('woff2');
}
@font-face {
  font-family: 'NanumGothic';
  font-weight: 700;
  src: url(data:font/woff2;base64,<BASE64>) format('woff2');
}
@font-face {
  font-family: 'D2Coding';
  font-weight: 400;
  src: url(data:font/woff2;base64,<BASE64>) format('woff2');
}

body       { font-family: 'NanumGothic', sans-serif; }
pre, code  { font-family: 'D2Coding', monospace; }
```

**주의**

- `font-weight` 를 각각 등록한다. 하나만 등록하면 브라우저가 Regular 를 인위적으로 굵게 그린다 (fake bold)
- `local()` 을 쓰지 않는다. 시스템 폰트에 의존하면 환경에 따라 결과가 달라진다
- 렌더러는 이 디렉터리를 읽어 base64 로 인라인한다. **임베딩 결과를 캐시**해 보고서마다 재인코딩하지 않는다

### D2Coding 을 뺄 수 있는가

뺄 수 있다. 314 KB (base64 419 KB) 가 줄어든다.
요청·응답 원문은 대부분 ASCII 라 시스템 고정폭(`monospace`)으로도 읽을 수 있다.

다만 응답 본문에 한글이 섞이면 폰트가 섞여 보인다.
**기본은 포함이며, 보고서 크기가 문제가 되면 제거를 검토한다.**

---

## 라이선스

| 폰트 | 라이선스 | 재배포 |
|---|---|---|
| 나눔고딕 (NanumGothic) | SIL Open Font License 1.1 | 가능 |
| D2Coding | SIL Open Font License 1.1 | 가능 |
| 맑은 고딕 (Malgun Gothic) | MS 독점 | **불가. 사용 금지** |

**OFL 은 라이선스 원문 동봉을 요구한다.**
`LICENSE-OFL.txt` 를 반드시 함께 배포한다. 상세는 해당 파일 참조.

출처

- 나눔글꼴 — https://hangeul.naver.com/font
- D2Coding — https://github.com/naver/d2codingfont

---

## 재생성

원본 TTF 는 저장소에 포함하지 않는다 (전체 패밀리 304 MB).
서브셋 `.woff2` 만 커밋하며, 아래는 재생성이 필요할 때만 실행한다.

```bash
pip install fonttools brotli
python3 assets/fonts/build_fonts.py --src <원본_ttf_디렉터리>
```

`--src` 는 재귀 탐색하므로 압축 해제한 폰트 패키지 루트를 그대로 지정하면 된다.

---

## M0 확인 사항

`IMPLEMENTATION_BRIEF.md` M0 완료 조건에 아래가 포함된다.

- [ ] `assets/fonts/` 에 `.woff2` 3종 존재
- [ ] `LICENSE-OFL.txt` 존재
- [ ] 각 폰트에 한글 음절 11,172자가 모두 포함됨

검증 스니펫

```python
from fontTools.ttLib import TTFont
for f in ["NanumGothic.woff2", "NanumGothicBold.woff2", "D2Coding.woff2"]:
    cmap = TTFont(f"assets/fonts/{f}").getBestCmap()
    hangul = sum(1 for c in cmap if 0xAC00 <= c <= 0xD7A3)
    assert hangul == 11172, f"{f}: 한글 {hangul}/11172"
```

M7 에서 폰트 문제를 발견하면 이미 늦다.
