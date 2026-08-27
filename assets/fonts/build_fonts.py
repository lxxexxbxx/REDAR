#!/usr/bin/env python3
"""
assets/fonts/*.woff2 재생성 스크립트.

원본 TTF 는 저장소에 포함하지 않는다 (나눔 전체 패밀리 304MB).
서브셋 woff2 만 커밋하며, 이 스크립트는 재생성이 필요할 때만 실행한다.

    pip install fonttools brotli
    python3 assets/fonts/build_fonts.py --src <원본_ttf_디렉터리>

원본 출처
    나눔글꼴  https://hangeul.naver.com/font
    D2Coding  https://github.com/naver/d2codingfont

라이선스
    둘 다 SIL Open Font License 1.1. 재배포 가능하나 라이선스 원문 동봉이 요구된다.
    assets/fonts/LICENSE-OFL.txt 참조.
"""
import argparse
import os
import sys

# 보고서에 쓰이는 문자 범위.
#   U+0020-007E  ASCII
#   U+00A0-00FF  Latin-1 (° ± × ÷ 등)
#   U+2000-206F  일반 구두점 (— – ' ' " " … 등)
#   U+20A0-20BF  통화 기호
#   U+2190-21FF  화살표 (→ ⇒ : 패치 목표 버전 표기에 사용)
#   U+2200-22FF  수학 연산자 (≥ ≤ ≠)
#   U+25A0-25FF  도형 (■ □ ● ○ ▲ ▼)
#   U+2600-26FF  기타 기호 (※ ☆ ★)
#   U+3000-303F  CJK 구두점
#   U+3131-318E  한글 자모
#   U+AC00-D7A3  한글 음절 전체 11,172자
#   U+FF00-FFEF  전각 형태
UNICODES = ",".join([
    "U+0020-007E", "U+00A0-00FF", "U+2000-206F", "U+20A0-20BF",
    "U+2190-21FF", "U+2200-22FF", "U+25A0-25FF", "U+2600-26FF",
    "U+3000-303F", "U+3131-318E", "U+AC00-D7A3", "U+FF00-FFEF",
])

# (출력 파일명, 원본 파일명 후보)
TARGETS = [
    ("NanumGothic.woff2",     ["NanumGothic.ttf"]),
    ("NanumGothicBold.woff2", ["NanumGothicBold.ttf"]),
    ("D2Coding.woff2",        ["D2Coding-Ver1.3.2-20180524-ligature.ttf",
                               "D2Coding.ttf"]),
]


def find_source(src_dir: str, candidates: list) -> str | None:
    """하위 디렉터리를 재귀 탐색해 원본 폰트를 찾는다."""
    for root, _dirs, files in os.walk(src_dir):
        for name in candidates:
            if name in files:
                return os.path.join(root, name)
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="원본 TTF 가 있는 디렉터리 (재귀 탐색)")
    ap.add_argument("--out", default=os.path.dirname(os.path.abspath(__file__)))
    args = ap.parse_args()

    try:
        from fontTools import subset
    except ImportError:
        print("fonttools 가 필요하다:  pip install fonttools brotli", file=sys.stderr)
        return 1

    total = 0
    for out_name, candidates in TARGETS:
        src = find_source(args.src, candidates)
        if src is None:
            print(f"[SKIP] {out_name}  원본을 찾지 못했다: {candidates}")
            continue

        out_path = os.path.join(args.out, out_name)
        subset.main([
            src,
            f"--output-file={out_path}",
            "--flavor=woff2",
            "--layout-features=*",
            "--no-hinting",
            "--desubroutinize",
            f"--unicodes={UNICODES}",
        ])
        size = os.path.getsize(out_path)
        total += size
        print(f"[OK]   {out_name:24s} {size/1024:7.1f} KB   <- {os.path.basename(src)}")

    print(f"\n합계 {total/1024:.1f} KB  ->  base64 임베딩 시 약 {total*4/3/1024:.1f} KB")
    print("보고서 HTML 1건에 이 크기가 더해진다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
