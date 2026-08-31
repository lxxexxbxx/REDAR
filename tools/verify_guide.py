#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
추출 CSV 가 PDF 원문에 실제로 존재하는지 대조 검증

  python3 tools/verify_guide.py --pdf <가이드>.pdf --csv data/guide_items_2026.csv

가이드 판형이 바뀌면 이 검증이 먼저 실패함
검증을 통과하지 못한 CSV 는 임포트하지 않음
"""
import argparse, csv, re, sys, collections
import pymupdf

ap = argparse.ArgumentParser()
ap.add_argument('--pdf', default='src.pdf')
ap.add_argument('--csv', default='data/guide_items_2026.csv')
a = ap.parse_args()

norm = lambda s: re.sub(r'\s+', '', s or '')

doc = pymupdf.open(a.pdf)
pages = [doc[i].get_text('text') for i in range(len(doc))]
csv.field_size_limit(10 ** 7)
items = []
for r in csv.DictReader(open(a.csv, encoding='utf-8-sig')):
    r['page_start'] = int(r['page_start']); r['page_end'] = int(r['page_end'])
    r['title'] = r['item_name']
    # criteria_safe / criteria_vuln 은 원문에서 '양호 :' '취약 :' 로 분리되어 있음
    # 이어붙이면 연속 문자열이 아니므로 각각 따로 대조함
    r['code'] = r['item_code']
    items.append(r)

FIELDS = ['title', 'check_content', 'check_purpose', 'security_threat',
          'target', 'criteria_safe', 'criteria_vuln', 'remediation', 'impact']

fail = collections.defaultdict(list)
for r in items:
    scope = norm(''.join(pages[r['page_start'] - 1: r['page_end']]))
    for f in FIELDS:
        v = norm(r[f])
        if not v:
            continue
        if v not in scope:
            fail[f].append(r['code'])

print('=== 원문 대조 (공백 무시 부분문자열 일치) ===')
for f in FIELDS:
    bad = fail[f]
    ok = len(items) - len(bad)
    print(f'{f:18} {ok:3}/{len(items)}  불일치 {len(bad):3} {bad[:6]}')

# 위험도 분포
rk = collections.Counter(r['severity_guide'] for r in items)
print('\n위험도 분포:', dict(rk))

# 코드 체계
pf = collections.Counter(r['item_code'].rsplit('-', 1)[0] for r in items)
print('분류별 항목수:', dict(pf), '| 합계', len(items))

# '점검 및 조치 사례'와 캡처 이미지는 설계상 미채택. 대조 대상 아님

if any(fail.values()):
    print('\n[FAIL] 원문과 불일치하는 필드가 있다. 판형이 바뀌었을 수 있다.')
    print('       파서를 수정하기 전까지 이 CSV 를 임포트하지 마라.')
    sys.exit(1)
print('\n[OK] 전 필드 원문 일치')
