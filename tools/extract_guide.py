#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KISA 상세가이드 PDF -> guide_items 임포트 CSV

docs/03_GUIDE_DATA.md §1.2 B안 구현.
가이드 원문은 저장소에 포함하지 않으며, 사용자가 보유한 PDF 를 이 스크립트로 변환한다.

  pip install pymupdf pdfplumber
  pdftotext -layout <가이드>.pdf full.txt        # 선택. 명령어 들여쓰기 보존용
  python3 tools/extract_guide.py --pdf <가이드>.pdf \
      --csv data/guide_items_2026.csv --imgdir data/guide_images

산출 CSV 를 POST /api/v1/guide/import 에 업로드한다.

파싱 방식 메모
  - 항목 경계: 표 괘선 중 "라벨 열을 가로지르는 선"만 행 경계로 인정한다.
    값 열에만 걸친 선은 셀 내부 구분선(양호/취약)이므로 제외해야 한다.
  - HWP 표는 라벨이 셀 세로 중앙정렬이라 줄 순서 파싱이 어긋난다. 좌표 기반 필수.
  - 10장 Web Application 은 CI/SI 등 하이픈 없는 별도 체계이며 원문에 CC 중복이 있다.
    PK 는 WA-nn 으로 정규화하고 원문 약어는 item_code_raw 에 보존한다.
  - 원문 오타 (히)->하, (증)->중 정규화.
  - M-01~M-04(이동통신)는 대상/판단기준/조치방법이 없고 상세 설명만 있다. 원문 구조다.
"""
import os, re, io, json, sqlite3, argparse, hashlib
import collections
from collections import defaultdict

import pymupdf
import pdfplumber

CODE_RE = re.compile(r'^([A-Z]{1,3})-(\d{1,3})$')
# 그림 캡션. 원문이 "[ 실행 창 ]" 형태로 이미지 바로 아래에 둔다
IMGCAP_RE = re.compile(r'^\[\s*.{1,60}\s*\]$')
RISK_RE = re.compile(r'^\(([가-힣])\)$')
RISK_FIX = {'히': '하', '증': '중', '중': '중', '상': '상', '하': '하'}
HDR_RE  = re.compile(r'\b[A-Z]{1,3}-\d{1,3}\b')

# 페이지 머리말/꼬리말 제거 패턴
NOISE_RE = [
    re.compile(r'^\|\s*한국인터넷진흥원\s*\|$'),
    re.compile(r'^\d{4}\s*주요정보통신기반시설.*상세가이드$'),
    re.compile(r'^\d{1,2}\.\s?[가-힣A-Za-z()\s]{2,28}$'),  # "01. Unix 서버" 러닝헤더
    re.compile(r'^\d{1,3}$'),                          # 페이지 번호
]

# 표 라벨 -> DB 필드
FIELD_MAP = {
    '점검 내용': 'check_content',
    '점검내용': 'check_content',
    '점검 목적': 'check_purpose',
    '점검목적': 'check_purpose',
    '보안 위협': 'security_threat',
    '보안위협': 'security_threat',
    '참고': 'reference_note',
    '대상': 'target',
    '판단 기준': 'criteria',
    '판단기준': 'criteria',
    '조치 방법': 'remediation',
    '조치방법': 'remediation',
    '조치 시 영향': 'impact',
    '조치시 영향': 'impact',
    '상세 설명': 'detail',
    '상세설명': 'detail',
}
SECTION_HEADS = {'개요', '점검 대상 및 판단 기준', '점검 및 조치 사례', '상세 설명'}
CASE_HEAD = '점검 및 조치 사례'
BODY_HEADS = ['점검 및 조치 사례', '상세 설명']   # 표 종료 지점 (둘 중 먼저 나오는 것)
HDRCELL_RE = re.compile(r'^[A-Z]{1,4}(-\d{1,3})?\s*(\([가-힣]\))?$')

CATEGORY_NAME = {
    'U': 'UNIX 서버', 'W': 'Windows 서버', 'WEB': '웹 서비스', 'S': '보안 장비',
    'N': '네트워크 장비', 'C': '제어시스템', 'PC': 'PC', 'D': 'DBMS',
    'M': '이동통신', 'HV': '가상화 장비', 'CA': '클라우드',
    'WA': 'Web Application(웹)',
}
WA_RE = re.compile(r'^[A-Z]{2,4}$')


def template_xrefs(doc, threshold=3):
    """페이지 장식으로 판정되는 이미지 xref 집합.

    page.get_images() 는 머리말 띠·장 표지 같은 페이지 템플릿 그래픽까지 반환한다.
    2026판에서는 xref 69/77(595x75 상단 띠)이 각각 429/424 페이지에 등장하며,
    이를 거르지 않으면 추출물의 69%가 장식 이미지가 된다.
    같은 이미지가 여러 페이지에 반복되면 콘텐츠가 아니라 템플릿이다.
    """
    c = collections.Counter()
    for page in doc:
        for img in page.get_images(full=True):
            c[img[0]] += 1
    return {x for x, n in c.items() if n > threshold}


def content_images(page, skip_xrefs, header_y=92, footer_y=778, min_pt=60):
    """콘텐츠 이미지만 (xref, rect, caption) 로 반환"""
    pr = page.rect
    lines = []
    for b in page.get_text('dict')['blocks']:
        if b['type'] != 0:
            continue
        for l in b['lines']:
            t = ''.join(sp['text'] for sp in l['spans']).strip()
            if t:
                lines.append((l['bbox'][1], t))
    out = []
    for img in page.get_images(full=True):
        x = img[0]
        if x in skip_xrefs:
            continue
        for r in page.get_image_rects(x):
            if r.y1 <= header_y or r.y0 >= footer_y:
                continue                      # 머리말/꼬리말 영역
            if r.width < min_pt or r.height < min_pt:
                continue                      # 아이콘·구분선
            if r.width > pr.width * 0.8 and r.height > pr.height * 0.7:
                continue                      # 표지·간지 전면 그래픽
            cap = next((t for y, t in lines
                        if r.y1 < y < r.y1 + 45 and IMGCAP_RE.match(t)), '')
            out.append((x, r, cap))
    return out


def is_noise(t):
    t = t.strip()
    if not t:
        return True
    return any(p.match(t) for p in NOISE_RE)


def page_lines(page):
    """pymupdf 라인 추출 -> (x0, top, text, size)"""
    out = []
    for b in page.get_text('dict')['blocks']:
        if b['type'] != 0:
            continue
        for l in b['lines']:
            t = ''.join(s['text'] for s in l['spans'])
            if not t.strip():
                continue
            out.append({
                'x0': l['bbox'][0], 'top': l['bbox'][1], 'bottom': l['bbox'][3],
                'text': t.rstrip(), 'size': l['spans'][0]['size'],
            })
    out.sort(key=lambda r: (r['top'], r['x0']))
    return out


def detect_items(doc):
    """항목 시작 페이지 탐지 -> [(code, risk, page_idx)]"""
    items = []
    for i, page in enumerate(doc):
        lines = page_lines(page)
        head = [l for l in lines if 95 < l['top'] < 155]
        lab = [l['text'].strip() for l in head if l['x0'] < 135]
        val = [l['text'].strip() for l in head if l['x0'] >= 135]
        code = risk = raw = None
        for t in lab:
            if CODE_RE.match(t):
                code = raw = t
            elif RISK_RE.match(t):
                risk = RISK_FIX.get(RISK_RE.match(t).group(1))
        # 10장 Web Application: 하이픈 없는 약어 코드 -> WA-nn 정규화
        if not code and any('Web Application' in v for v in val):
            abbr = next((t for t in lab if WA_RE.match(t)), None)
            seq = next((re.match(r'^(\d{1,2})\.\s', v) for v in val
                        if re.match(r'^(\d{1,2})\.\s', v)), None)
            if abbr and seq:
                raw, code = abbr, f'WA-{int(seq.group(1)):02d}'
        if code:
            items.append({'code': code, 'code_raw': raw, 'risk': risk, 'page': i})
    return items


def row_bounds(pl_page):
    """가로 괘선 -> 행 경계 / 세로 괘선 -> 라벨·값 열 경계"""
    vs = sorted({round(e['x0'], 1) for e in pl_page.vertical_edges})
    inner = [v for v in vs if 100 < v < 250]
    split_x = inner[0] if inner else 131.9
    left = min([v for v in vs if 0 < v < 100], default=58.0)
    # 라벨 열을 실제로 가로지르는 선만 행 경계로 인정
    # (값 열에만 걸친 선은 셀 내부 구분선이므로 제외)
    hs = sorted({round(e['top'], 1) for e in pl_page.horizontal_edges
                 if e['x0'] <= left + 4 and e['x1'] >= split_x - 4})
    rows = [(hs[i], hs[i + 1]) for i in range(len(hs) - 1) if hs[i + 1] - hs[i] > 5]
    return rows, split_x


def parse_table_page(lines, rows, split_x):
    """행별 (라벨, 값) 추출"""
    cells = []
    for top, bot in rows:
        lab, val = [], []
        for l in lines:
            c = (l['top'] + l['bottom']) / 2
            if not (top - 1 <= c <= bot + 1):
                continue
            (lab if l['x0'] < split_x else val).append(l['text'].strip())
        cells.append((' '.join(lab).strip(), '\n'.join(val).strip()))
    return cells


def clean_case_text(raw_page_text):
    """사례 본문에서 머리말/꼬리말 제거"""
    keep = []
    for ln in raw_page_text.split('\n'):
        if is_noise(ln):
            continue
        keep.append(ln.rstrip())
    while keep and not keep[0].strip():
        keep.pop(0)
    while keep and not keep[-1].strip():
        keep.pop()
    return '\n'.join(keep)


def dedent_block(text):
    """공통 들여쓰기 제거 (명령어 상대 들여쓰기는 보존)"""
    ls = [l for l in text.split('\n') if l.strip()]
    if not ls:
        return text
    ind = min(len(l) - len(l.lstrip()) for l in ls)
    return '\n'.join(l[ind:] if len(l) >= ind else l for l in text.split('\n'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pdf', default='src.pdf')
    ap.add_argument('--out', default='')
    ap.add_argument('--json', default='')
    ap.add_argument('--csv', default='data/guide_items_2026.csv')
    ap.add_argument('--guide-version', default='2026')
    ap.add_argument('--imgdir', default='data/guide_images')
    ap.add_argument('--limit', type=int, default=0, help='앞에서 N개 항목만 처리(0=전체)')
    ap.add_argument('--no-images', action='store_true')
    args = ap.parse_args()

    doc = pymupdf.open(args.pdf)
    npages = len(doc)

    # 레이아웃 텍스트(명령어 들여쓰기 보존) 페이지 배열
    layout_pages = []
    for i in range(npages):
        layout_pages.append(doc[i].get_text('text', flags=pymupdf.TEXT_PRESERVE_WHITESPACE
                                            | pymupdf.TEXT_PRESERVE_LIGATURES))
    # pdftotext -layout 결과가 있으면 우선 사용
    if os.path.exists('full.txt'):
        lp = open('full.txt', encoding='utf-8').read().split('\f')
        if len(lp) >= npages:
            layout_pages = lp[:npages]

    global SKIP_XREFS
    SKIP_XREFS = set() if args.no_images else template_xrefs(doc)
    if SKIP_XREFS:
        print(f'[i] 페이지 장식으로 제외한 이미지 xref: {sorted(SKIP_XREFS)}')

    items = detect_items(doc)
    if args.limit:
        items = items[:args.limit]
    print(f'[i] pages={npages} items={len(items)}')

    # 항목별 페이지 범위
    all_items = detect_items(doc) if args.limit else items
    starts = [it['page'] for it in all_items] + [npages]

    os.makedirs(args.imgdir, exist_ok=True)
    plumb = pdfplumber.open(args.pdf)

    records, unknown_labels = [], defaultdict(int)

    for idx, it in enumerate(items):
        p0 = it['page']
        p1 = starts[idx + 1] - 1
        rec = {
            'code': it['code'], 'code_raw': it.get('code_raw') or it['code'], 'risk': it['risk'],
            'category': CATEGORY_NAME.get(it['code'].split('-')[0], ''),
            'prefix': it['code'].split('-')[0],
            'num': int(it['code'].split('-')[1]),
            'page_start': p0 + 1, 'page_end': p1 + 1,
            'title': '', 'section': '',
            'check_content': '', 'check_purpose': '', 'security_threat': '',
            'reference_note': '', 'target': '', 'criteria': '',
            'remediation': '', 'impact': '', 'detail': '', 'case_text': '', 'images': [],
        }

        # --- 표 영역 파싱 (사례 헤딩 전까지) ---
        case_start_page, case_start_y, body_head = None, None, CASE_HEAD
        for pi in range(p0, p1 + 1):
            lines = page_lines(doc[pi])
            hit = next((l for l in lines
                        if l['text'].strip() in BODY_HEADS and l['x0'] < 140), None)
            if hit:
                case_start_page, case_start_y = pi, hit['bottom']
                body_head = hit['text'].strip()
                break
        if case_start_page is None:
            case_start_page, case_start_y = p1 + 1, 0

        for pi in range(p0, min(case_start_page, p1) + 1):
            lines = page_lines(doc[pi])
            lines = [l for l in lines if 90 < l['top'] < 780]
            if pi == case_start_page:
                lines = [l for l in lines if l['bottom'] <= case_start_y]
            try:
                rows, sx = row_bounds(plumb.pages[pi])
            except Exception:
                continue
            if not rows:
                continue
            for lab, val in parse_table_page(lines, rows, sx):
                if not lab and not val:
                    continue
                # 헤더 행 (코드/위험도 + 분류/제목)
                if HDRCELL_RE.match(lab) or RISK_RE.match(lab):
                    if not rec['risk']:
                        mr = re.search(r'\(([가-힣])\)', lab)
                        if mr:
                            rec['risk'] = RISK_FIX.get(mr.group(1))
                    vs_ = [v.strip() for v in val.split('\n') if v.strip()]
                    for j, v in enumerate(vs_):
                        if v in SECTION_HEADS:
                            continue
                        if j == 0 and not rec['section']:
                            rec['section'] = v
                        elif not HDR_RE.search(v):
                            rec['title'] = (rec['title'] + ' ' + v).strip()
                    continue
                if not lab and val:
                    # 제목/분류는 항목 시작 페이지 상단에서만 확정
                    # (후속 페이지의 그림 캡션이 섞이는 것을 방지)
                    if pi != p0:
                        continue
                    for v in val.split('\n'):
                        v = v.strip()
                        if v in SECTION_HEADS or (v.startswith('[') and v.endswith(']')):
                            continue
                        if '>' in v and not rec['section']:
                            rec['section'] = v
                        elif v:
                            rec['title'] = (rec['title'] + ' ' + v).strip()
                    continue
                if lab in SECTION_HEADS:
                    continue
                key = FIELD_MAP.get(lab)
                if key:
                    rec[key] = (rec[key] + '\n' + val).strip() if rec[key] else val
                else:
                    unknown_labels[lab] += 1

        # --- 점검 및 조치 사례 ---
        parts = []
        for pi in range(case_start_page, p1 + 1):
            if pi >= npages:
                break
            txt = layout_pages[pi]
            if pi == case_start_page:
                pos = txt.find(body_head)
                if pos >= 0:
                    txt = txt[pos + len(body_head):]
            parts.append(clean_case_text(txt))
        body = dedent_block('\n'.join(p for p in parts if p.strip()))
        if body_head == '상세 설명':
            rec['detail'] = body
        else:
            rec['case_text'] = body

        # --- 이미지 ---
        if not args.no_images:
            n, seen = 0, set()
            for pi in range(p0, min(p1, npages - 1) + 1):
                for xref, _rect, cap in content_images(doc[pi], SKIP_XREFS):
                    if xref in seen:
                        continue          # 항목 내 동일 이미지 중복 방지
                    seen.add(xref)
                    try:
                        pix = pymupdf.Pixmap(doc, xref)
                        if pix.n - pix.alpha > 3:
                            pix = pymupdf.Pixmap(pymupdf.csRGB, pix)
                        n += 1
                        fn = f"{rec['code']}_{n:02d}.png"
                        pix.save(os.path.join(args.imgdir, fn))
                        rec['images'].append({'file': fn, 'page': pi + 1,
                                              'caption': cap})
                    except Exception:
                        pass

        rec['title'] = re.sub(r'^\d{1,2}\.\s*', '', rec['title'].strip())
        records.append(rec)
        if (idx + 1) % 50 == 0:
            print(f'  ... {idx+1}/{len(items)}')

    plumb.close()

    # ---------- 저장 ----------
    def split_criteria0(c):
        s_ = v_ = ''
        m = re.search(r'양호\s*[:：]\s*(.*?)(?=\n?\s*취약\s*[:：]|$)', c, re.S)
        if m:
            s_ = ' '.join(m.group(1).split())
        m = re.search(r'취약\s*[:：]\s*(.*)$', c, re.S)
        if m:
            v_ = ' '.join(m.group(1).split())
        return s_, v_

    import csv as _csv
    os.makedirs(os.path.dirname(os.path.abspath(args.csv)) or '.', exist_ok=True)
    COLS = ['item_code', 'item_code_raw', 'item_name', 'category', 'section',
            'severity_guide', 'check_content', 'check_purpose', 'security_threat',
            'reference_note', 'target', 'criteria_safe', 'criteria_vuln',
            'remediation', 'impact', 'detail', 'case_text', 'reference',
            'page_start', 'page_end', 'guide_version']
    with open(args.csv, 'w', newline='', encoding='utf-8-sig') as f:
        cw = _csv.writer(f, lineterminator='\n')
        cw.writerow(COLS)
        for r in records:
            cs, cv = split_criteria0(r['criteria'])
            cw.writerow([r['code'], r['code_raw'], r['title'], r['category'],
                         r['section'], r['risk'], r['check_content'], r['check_purpose'],
                         r['security_threat'], r['reference_note'], r['target'],
                         cs, cv, r['remediation'], r['impact'], r['detail'],
                         r['case_text'], '', r['page_start'], r['page_end'],
                         args.guide_version])
    print(f'[ok] {args.csv}  ({len(records)}행)')

    img_csv = os.path.splitext(args.csv)[0] + '_images.csv'
    with open(img_csv, 'w', newline='', encoding='utf-8-sig') as f:
        cw = _csv.writer(f, lineterminator='\n')
        cw.writerow(['item_code', 'file_path', 'page', 'caption', 'sort_order'])
        for r in records:
            for i, im in enumerate(r['images'], 1):
                cw.writerow([r['code'], os.path.join(args.imgdir, im['file']),
                             im['page'], im.get('caption', ''), i])
    print(f'[ok] {img_csv}')

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(records, f, ensure_ascii=False, indent=2)
    if not args.out:
        _report(records, unknown_labels)
        return

    if os.path.exists(args.out):
        os.remove(args.out)
    con = sqlite3.connect(args.out)
    con.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE item (
      code TEXT PRIMARY KEY, code_raw TEXT, prefix TEXT, num INTEGER,
      category TEXT, section TEXT, title TEXT, risk TEXT,
      check_content TEXT, check_purpose TEXT, security_threat TEXT,
      reference_note TEXT, target TEXT, criteria TEXT,
      criteria_safe TEXT, criteria_vuln TEXT,
      remediation TEXT, impact TEXT, detail TEXT, case_text TEXT,
      page_start INTEGER, page_end INTEGER
    );
    CREATE TABLE item_image (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT REFERENCES item(code), file TEXT, page INTEGER
    );
    CREATE TABLE nuclei_map (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      template_id TEXT, code TEXT REFERENCES item(code),
      confidence REAL DEFAULT 1.0, note TEXT,
      UNIQUE(template_id, code)
    );
    CREATE VIRTUAL TABLE item_fts USING fts5(
      code UNINDEXED, title, check_content, security_threat, remediation, case_text,
      tokenize='unicode61'
    );
    CREATE INDEX idx_item_prefix ON item(prefix);
    CREATE INDEX idx_item_risk ON item(risk);
    CREATE INDEX idx_map_tid ON nuclei_map(template_id);
    """)

    def split_criteria(c):
        safe = vuln = ''
        m = re.search(r'양호\s*[:：]\s*(.*?)(?=\n?\s*취약\s*[:：]|$)', c, re.S)
        if m:
            safe = ' '.join(m.group(1).split())
        m = re.search(r'취약\s*[:：]\s*(.*)$', c, re.S)
        if m:
            vuln = ' '.join(m.group(1).split())
        return safe, vuln

    for r in records:
        s, v = split_criteria(r['criteria'])
        con.execute("""INSERT INTO item VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            r['code'], r['code_raw'], r['prefix'], r['num'], r['category'], r['section'],
            r['title'], r['risk'],
            r['check_content'], r['check_purpose'], r['security_threat'], r['reference_note'],
            r['target'], r['criteria'], s, v, r['remediation'], r['impact'], r['detail'],
            r['case_text'], r['page_start'], r['page_end']))
        con.execute("INSERT INTO item_fts VALUES (?,?,?,?,?,?)", (
            r['code'], r['title'], r['check_content'], r['security_threat'],
            r['remediation'], r['case_text']))
        for im in r['images']:
            con.execute("INSERT INTO item_image(code,file,page) VALUES (?,?,?)",
                        (r['code'], im['file'], im['page']))
    con.commit()

    con.close()
    _report(records, unknown_labels)


def _report(records, unknown_labels):
    # ---------- 검증 리포트 ----------
    req = ['title', 'check_content', 'check_purpose', 'target', 'criteria', 'remediation']
    print('\n=== 필드 결측률 ===')
    for k in req + ['security_threat', 'impact', 'detail', 'case_text']:
        miss = [r['code'] for r in records if not r[k].strip()]
        print(f'{k:18} 결측 {len(miss):3}/{len(records)}  {miss[:8]}')
    bad = [r['code'] for r in records if not r['criteria'].strip()
           or ('양호' not in r['criteria'] and '취약' not in r['criteria'])]
    print(f'\n판단기준 파싱 이상: {len(bad)} {bad[:10]}')
    if unknown_labels:
        print(f'\n미매핑 라벨: {dict(unknown_labels)}')
    imgs = [im for r in records for im in r['images']]
    withcap = sum(1 for im in imgs if im.get('caption'))
    print(f'\n총 이미지: {len(imgs)}장 (캡션 확보 {withcap})')
    print(f'이미지 있는 항목: {sum(1 for r in records if r["images"])}/{len(records)}')


if __name__ == '__main__':
    main()
