#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
data/vuln_type_rules.csv 의 분류 정확도 실측

  python3 tools/measure_vuln_type.py --templates ~/nuclei-templates

other 비율이 5% 를 넘으면 규칙 보강 대상이다.
규칙을 고치기 전에 반드시 이 값을 먼저 본다. 감으로 고치면 오분류가 늘어난다.
"""
import argparse, csv, collections, os, re, sys
import yaml

CWE_RE = re.compile(r'CWE-\d+', re.I)

# 자산 식별 전용 템플릿(플러그인·테마 탐지). 취약점이 아니므로 분류 대상에서 뺀다.
# 포함하면 전부 other 로 잡혀 other 비율이 실제보다 크게 나온다.
DETECT_PATHS = ('/http/technologies/',)
DETECT_ID = ('-detect', '-detection')


def is_detection(t):
    return (any(p in t['path'] for p in DETECT_PATHS)
            or any(k in t['id'] for k in DETECT_ID))


def load_rules(path):
    rows = [dict(r, priority=int(r['priority']))
            for r in csv.DictReader(open(path, encoding='utf-8'))]
    rows.sort(key=lambda x: x['priority'])
    return rows


def load_templates(root, only_wp=True):
    out = []
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != '.git']
        for fn in files:
            if not fn.endswith(('.yaml', '.yml')):
                continue
            p = os.path.join(dirpath, fn)
            try:
                d = yaml.safe_load(open(p, encoding='utf-8', errors='ignore'))
            except Exception:
                continue
            if not isinstance(d, dict) or 'id' not in d:
                continue
            info = d.get('info') or {}
            tags = info.get('tags') or ''
            tags = tags if isinstance(tags, str) else ','.join(tags)
            rel = '/' + os.path.relpath(p, root).replace(os.sep, '/')
            if only_wp and 'wordpress' not in f"{d['id']} {tags} {rel}".lower():
                continue
            cl = info.get('classification') or {}
            cwe = cl.get('cwe-id') or []
            cwe = [cwe] if isinstance(cwe, str) else list(cwe)
            out.append({
                'id': d['id'], 'path': rel,
                'tags': [t.strip() for t in tags.split(',') if t.strip()],
                'cwe': sorted({m.upper() for x in cwe for m in CWE_RE.findall(str(x))}),
            })
    return out


def resolve(t, rules):
    for r in rules:
        if r['match_type'] == 'cwe_id' and r['match_value'] in t['cwe']:
            return r['vuln_type'], r['match_value']
        if r['match_type'] == 'tag' and r['match_value'] in t['tags']:
            return r['vuln_type'], 'tag:' + r['match_value']
        if r['match_type'] == 'template_prefix' and t['id'].startswith(r['match_value']):
            return r['vuln_type'], 'prefix'
    return 'other', None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--templates', required=True)
    ap.add_argument('--rules', default='data/vuln_type_rules.csv')
    ap.add_argument('--all', action='store_true', help='WordPress 외 템플릿도 포함')
    ap.add_argument('--with-detection', action='store_true',
                    help='자산 식별 템플릿도 포함 (기본: 제외)')
    a = ap.parse_args()

    rules = load_rules(a.rules)
    ts = load_templates(a.templates, only_wp=not a.all)
    if not a.with_detection:
        det = [t for t in ts if is_detection(t)]
        ts = [t for t in ts if not is_detection(t)]
        print(f'자산 식별 템플릿 {len(det)}개 제외')
    if not ts:
        sys.exit('템플릿을 찾지 못했다.')

    res = collections.Counter()
    other_cwe = collections.Counter()
    other_id = []
    for t in ts:
        vt, _ = resolve(t, rules)
        res[vt] += 1
        if vt == 'other':
            for w in t['cwe']:
                other_cwe[w] += 1
            other_id.append(t['id'])

    n = len(ts)
    print(f'템플릿 {n}개\n')
    for k, v in res.most_common():
        print(f'  {k:18} {v:5}  ({v / n * 100:4.1f}%)')

    rate = res['other'] / n * 100
    print(f'\nother 비율 {rate:.1f}%  ' + ('[OK]' if rate <= 5 else '[규칙 보강 필요]'))

    if other_cwe:
        print('\nother 로 떨어진 CWE (규칙 추가 후보):')
        for k, v in other_cwe.most_common(15):
            print(f'  {k:10} {v}')
    if other_id:
        print(f'\nother 템플릿 예시: {", ".join(other_id[:8])}')
    sys.exit(0 if rate <= 5 else 1)


if __name__ == '__main__':
    main()
