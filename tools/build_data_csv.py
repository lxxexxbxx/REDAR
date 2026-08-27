#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
data/*.csv 생성기 (오프라인 1회 실행. 산출물은 저장소에 커밋)

  python3 tools/build_data_csv.py --guide-db kisa.db --templates ~/nuclei-templates

산출
  data/vuln_type_rules.csv        nuclei tags/cwe -> VulnType
  data/guide_mappings.csv         탐지 -> KISA 점검항목 (cwe/exposure/vuln_type/cve_present)
  data/guide_mappings.templates.csv   CWE 로 안 풀리는 템플릿 예외 목록
  data/component_advisories.csv   플러그인/테마 취약 버전 -> 패치 목표
"""
import argparse, csv, os, re, sqlite3, sys, collections
import yaml

# ── VulnType (docs/00_API_SPEC.md §0.4 와 일치해야 함) ────────────────
VULN_TYPES = ['rce', 'sqli', 'xss', 'csrf', 'ssrf', 'auth_bypass',
              'deserialization', 'path_traversal', 'file_upload',
              'open_redirect', 'info_disclosure', 'access_control',
              'misconfig', 'other']

# ── CWE -> VulnType (priority 10) ────────────────────────────────────
CWE_VT = {
    'CWE-94': 'rce', 'CWE-95': 'rce', 'CWE-78': 'rce', 'CWE-77': 'rce',
    'CWE-88': 'rce', 'CWE-917': 'rce', 'CWE-1336': 'rce', 'CWE-502': 'deserialization',
    'CWE-89': 'sqli', 'CWE-564': 'sqli',
    'CWE-79': 'xss', 'CWE-80': 'xss', 'CWE-83': 'xss', 'CWE-116': 'xss',
    'CWE-352': 'csrf',
    'CWE-918': 'ssrf', 'CWE-611': 'ssrf',
    'CWE-287': 'auth_bypass', 'CWE-288': 'auth_bypass', 'CWE-290': 'auth_bypass',
    'CWE-294': 'auth_bypass', 'CWE-306': 'auth_bypass', 'CWE-798': 'auth_bypass',
    'CWE-1390': 'auth_bypass', 'CWE-521': 'auth_bypass', 'CWE-307': 'auth_bypass',
    'CWE-640': 'auth_bypass', 'CWE-620': 'auth_bypass',
    'CWE-384': 'auth_bypass', 'CWE-613': 'auth_bypass',
    'CWE-22': 'path_traversal', 'CWE-23': 'path_traversal', 'CWE-24': 'path_traversal',
    'CWE-35': 'path_traversal', 'CWE-36': 'path_traversal', 'CWE-73': 'path_traversal',
    'CWE-98': 'path_traversal', 'CWE-99': 'path_traversal', 'CWE-552': 'path_traversal',
    'CWE-434': 'file_upload', 'CWE-436': 'file_upload',
    'CWE-601': 'open_redirect',
    'CWE-200': 'info_disclosure', 'CWE-209': 'info_disclosure',
    'CWE-213': 'info_disclosure', 'CWE-215': 'info_disclosure',
    'CWE-497': 'info_disclosure', 'CWE-532': 'info_disclosure',
    'CWE-538': 'info_disclosure', 'CWE-540': 'info_disclosure',
    'CWE-548': 'info_disclosure', 'CWE-319': 'info_disclosure',
    'CWE-311': 'info_disclosure',
    'CWE-284': 'access_control', 'CWE-285': 'access_control',
    'CWE-425': 'access_control', 'CWE-566': 'access_control',
    'CWE-639': 'access_control', 'CWE-862': 'access_control',
    'CWE-863': 'access_control', 'CWE-269': 'access_control',
    'CWE-266': 'access_control', 'CWE-264': 'access_control',
    'CWE-16': 'misconfig', 'CWE-276': 'misconfig', 'CWE-1188': 'misconfig',
    'CWE-1021': 'misconfig', 'CWE-693': 'misconfig', 'CWE-650': 'misconfig',
    'CWE-565': 'misconfig', 'CWE-614': 'misconfig', 'CWE-1004': 'misconfig',
    'CWE-1275': 'misconfig', 'CWE-326': 'misconfig', 'CWE-327': 'misconfig',
    'CWE-937': 'misconfig', 'CWE-1035': 'misconfig', 'CWE-1104': 'misconfig',
}

# ── tag -> VulnType (priority 50~70) ─────────────────────────────────
TAG_VT = [
    ('rce', 'rce', 50), ('code-injection', 'rce', 50), ('command-injection', 'rce', 50),
    ('ssti', 'rce', 50), ('deserialization', 'deserialization', 50),
    ('sqli', 'sqli', 50), ('sql-injection', 'sqli', 50),
    ('xss', 'xss', 50), ('cross-site-scripting', 'xss', 50), ('dom-xss', 'xss', 50),
    ('csrf', 'csrf', 50), ('xsrf', 'csrf', 50),
    ('ssrf', 'ssrf', 50), ('xxe', 'ssrf', 60),
    ('auth-bypass', 'auth_bypass', 50), ('authbypass', 'auth_bypass', 50),
    ('unauth', 'auth_bypass', 55), ('default-login', 'auth_bypass', 50),
    ('brute-force', 'auth_bypass', 60), ('weak-password', 'auth_bypass', 55),
    ('lfi', 'path_traversal', 50), ('rfi', 'path_traversal', 50),
    ('traversal', 'path_traversal', 50), ('path-traversal', 'path_traversal', 50),
    ('file-download', 'path_traversal', 60),
    ('fileupload', 'file_upload', 50), ('file-upload', 'file_upload', 50),
    ('arbitrary-file-upload', 'file_upload', 50),
    ('redirect', 'open_redirect', 55), ('open-redirect', 'open_redirect', 50),
    ('disclosure', 'info_disclosure', 50), ('exposure', 'info_disclosure', 50),
    ('info-leak', 'info_disclosure', 50), ('fpd', 'info_disclosure', 55),
    ('listing', 'info_disclosure', 60), ('logs', 'info_disclosure', 65),
    ('idor', 'access_control', 50), ('privilege-escalation', 'access_control', 50),
    ('privesc', 'access_control', 50), ('authz', 'access_control', 55),
    ('misconfig', 'misconfig', 50), ('misconfiguration', 'misconfig', 50),
    ('default-page', 'misconfig', 60), ('debug', 'misconfig', 60),
    ('config', 'misconfig', 70),
    # 광범위한 태그는 후순위. 'injection' 은 XSS 에도 붙으므로 sqli 로 보내지 않는다
    ('injection', 'other', 80),
    ('tech', 'other', 90), ('detect', 'other', 90),
    ('panel', 'other', 90), ('login', 'other', 90),
]
TEMPLATE_PREFIX_VT = [('wordpress-', 'other', 95)]

# ── CWE -> KISA 점검항목 ─────────────────────────────────────────────
# (item_code, confidence, 근거)
CWE_GUIDE = {
    'CWE-94':  [('WA-01', 'high', '코드 인젝션. 외부 입력이 코드로 실행되는 경로에 직접 대응')],
    'CWE-95':  [('WA-01', 'high', 'eval 계열 인젝션. 상동')],
    'CWE-77':  [('WA-01', 'high', '명령어 삽입. 코드 인젝션 항목의 운영체제 명령 실행 유형')],
    'CWE-78':  [('WA-01', 'high', 'OS 명령 실행. 상동')],
    'CWE-917': [('WA-01', 'high', '표현식 언어 인젝션. 상동')],
    'CWE-1336':[('WA-01', 'high', '서버사이드 템플릿 인젝션. 상동')],
    'CWE-90':  [('WA-01', 'high', 'LDAP 인젝션. 항목 개요에 LDAP 인젝션이 명시됨')],
    'CWE-91':  [('WA-01', 'high', 'XML 인젝션. 상동')],
    'CWE-502': [('WA-01', 'medium', '역직렬화를 통한 코드 실행. 인젝션 유형은 아니나 결과가 동일')],
    'CWE-611': [('WA-01', 'medium', 'XXE. 항목 개요의 XML 인젝션 범위')],
    'CWE-89':  [('WA-02', 'high', 'SQL 인젝션 항목에 직접 대응')],
    'CWE-564': [('WA-02', 'high', 'ORM 쿼리 인젝션. 상동')],
    'CWE-548': [('WA-03', 'high', '디렉터리 인덱싱 항목에 직접 대응'),
                ('WEB-04', 'high', '웹 서비스 디렉터리 리스팅 방지 설정. 서버 설정 측면')],
    'CWE-209': [('WA-04', 'high', '오류 메시지 노출. 에러 페이지 적용 미흡 항목'),
                ('WEB-22', 'medium', '에러 페이지 관리. 서버 설정 측면')],
    'CWE-200': [('WA-05', 'high', '정보 누출 항목에 직접 대응')],
    'CWE-215': [('WA-05', 'high', '디버그 정보 노출. 정보 누출 항목')],
    'CWE-497': [('WA-05', 'high', '시스템 정보 노출. 상동')],
    'CWE-538': [('WA-05', 'high', '파일·디렉터리 정보 노출. 상동')],
    'CWE-213': [('WA-05', 'medium', '의도된 정보 노출. 상동')],
    'CWE-540': [('WA-05', 'high', '소스 코드 노출'),
                ('WEB-13', 'high', '웹 서비스 설정 파일 노출 제한')],
    'CWE-532': [('WA-05', 'high', '로그 파일을 통한 정보 노출'),
                ('WEB-26', 'medium', '로그 디렉터리 및 파일 권한 설정')],
    'CWE-79':  [('WA-06', 'high', '크로스사이트 스크립트 항목에 직접 대응')],
    'CWE-80':  [('WA-06', 'high', '상동')],
    'CWE-83':  [('WA-06', 'high', '상동')],
    'CWE-116': [('WA-06', 'medium', '출력값 인코딩 미흡. XSS 항목의 조치 방법에 해당')],
    'CWE-352': [('WA-07', 'high', '크로스사이트 요청 위조 항목에 직접 대응')],
    'CWE-918': [('WA-08', 'high', '서버사이드 요청 위조 항목에 직접 대응')],
    'CWE-521': [('WA-09', 'high', '약한 비밀번호 정책 항목에 직접 대응'),
                ('WEB-02', 'medium', '취약한 비밀번호 사용 제한. 서버 계정 측면')],
    'CWE-798': [('WA-09', 'high', '하드코딩된 자격증명'),
                ('WEB-01', 'medium', 'Default 관리자 계정명 변경')],
    'CWE-1391':[('WA-09', 'high', '추측 가능한 자격증명. 상동')],
    'CWE-287': [('WA-10', 'high', '불충분한 인증 절차 항목에 직접 대응')],
    'CWE-306': [('WA-10', 'high', '필수 인증 누락. 상동')],
    'CWE-288': [('WA-10', 'high', '대체 경로를 통한 인증 우회. 상동')],
    'CWE-290': [('WA-10', 'high', '스푸핑을 통한 인증 우회. 상동')],
    'CWE-294': [('WA-10', 'medium', '캡처·재전송 인증 우회. 상동')],
    'CWE-1390':[('WA-10', 'high', '취약한 인증. 상동')],
    'CWE-862': [('WA-11', 'high', '인가 누락. 불충분한 권한 검증 항목에 직접 대응')],
    'CWE-863': [('WA-11', 'high', '잘못된 인가. 상동')],
    'CWE-285': [('WA-11', 'high', '부적절한 인가. 상동')],
    'CWE-284': [('WA-11', 'high', '부적절한 접근 통제. 상동')],
    'CWE-639': [('WA-11', 'high', 'IDOR. 상동')],
    'CWE-566': [('WA-11', 'high', '키 기반 접근 통제 우회. 상동')],
    'CWE-269': [('WA-11', 'high', '권한 관리 미흡으로 인한 권한 상승. 상동')],
    'CWE-266': [('WA-11', 'high', '부적절한 권한 부여. 상동')],
    'CWE-264': [('WA-11', 'medium', '권한·접근제어 상위 분류. 상동')],
    'CWE-425': [('WA-11', 'medium', '강제 브라우징'),
                ('WEB-14', 'medium', '웹 서비스 경로 내 파일의 접근 통제')],
    'CWE-640': [('WA-12', 'high', '취약한 비밀번호 복구 절차 항목에 직접 대응')],
    'CWE-620': [('WA-12', 'high', '비밀번호 변경 시 검증 누락. 상동')],
    'CWE-841': [('WA-13', 'high', '워크플로 순서 위반. 프로세스 검증 누락 항목')],
    'CWE-472': [('WA-13', 'medium', '웹 파라미터 변조. 상동')],
    'CWE-807': [('WA-13', 'medium', '신뢰할 수 없는 입력에 의존한 판단. 상동')],
    'CWE-434': [('WA-14', 'high', '악성 파일 업로드 항목에 직접 대응'),
                ('WEB-24', 'medium', '별도의 업로드 경로 사용 및 권한 설정')],
    'CWE-22':  [('WA-15', 'high', '경로 조작을 통한 파일 다운로드 항목에 직접 대응'),
                ('WEB-06', 'medium', '웹 서비스 상위 디렉터리 접근 제한 설정')],
    'CWE-23':  [('WA-15', 'high', '상대 경로 조작. 상동'),
                ('WEB-06', 'medium', '상동')],
    'CWE-24':  [('WA-15', 'high', '상위 디렉터리 조작. 상동')],
    'CWE-35':  [('WA-15', 'high', '상동')],
    'CWE-36':  [('WA-15', 'high', '절대 경로 조작. 상동')],
    'CWE-73':  [('WA-15', 'high', '파일명 외부 제어. 상동')],
    'CWE-98':  [('WA-15', 'high', 'PHP 파일 포함(LFI/RFI)'),
                ('WA-01', 'medium', 'RFI 는 원격 코드 실행으로 이어짐')],
    'CWE-99':  [('WA-15', 'medium', '리소스 식별자 제어. 상동')],
    'CWE-552': [('WA-15', 'high', '외부 접근 가능 파일'),
                ('WEB-14', 'medium', '웹 서비스 경로 내 파일의 접근 통제')],
    'CWE-384': [('WA-16', 'high', '세션 고정. 불충분한 세션 관리 항목')],
    'CWE-613': [('WA-16', 'high', '세션 만료 미흡. 상동')],
    'CWE-488': [('WA-16', 'medium', '세션 데이터 노출. 상동')],
    'CWE-319': [('WA-17', 'high', '평문 전송. 데이터 평문 전송 항목에 직접 대응'),
                ('WEB-20', 'high', 'SSL/TLS 활성화')],
    'CWE-311': [('WA-17', 'high', '암호화 미적용. 상동'),
                ('WEB-20', 'high', '상동')],
    'CWE-326': [('WA-17', 'medium', '취약한 암호 강도'),
                ('WEB-20', 'medium', 'SSL/TLS 설정')],
    'CWE-327': [('WA-17', 'medium', '위험한 암호 알고리즘. 상동'),
                ('WEB-20', 'medium', '상동')],
    'CWE-565': [('WA-18', 'high', '검증 없는 쿠키 의존. 쿠키 변조 항목')],
    'CWE-1004':[('WA-18', 'medium', 'HttpOnly 미설정. 상동')],
    'CWE-614': [('WA-18', 'medium', 'Secure 플래그 미설정. 상동')],
    'CWE-1275':[('WA-18', 'medium', 'SameSite 미설정. 상동')],
    'CWE-419': [('WA-19', 'high', '보호되지 않은 대체 채널. 관리자페이지 노출 항목')],
    'CWE-307': [('WA-20', 'high', '인증 시도 제한 미흡. 자동화 공격 항목'),
                ('WA-09', 'medium', '약한 비밀번호 정책과 결합 시 위험 증가')],
    'CWE-799': [('WA-20', 'high', '상호작용 빈도 제어 미흡. 상동')],
    'CWE-770': [('WA-20', 'medium', '자원 할당 제한 없음. 상동')],
    'CWE-650': [('WA-21', 'high', '신뢰된 HTTP Method. 불필요한 Method 악용 항목')],
    'CWE-601': [('WEB-21', 'high', '오픈 리다이렉트. HTTP 리디렉션 항목')],
    'CWE-1021':[('WEB-16', 'medium', '클릭재킹. 보안 헤더 설정 항목')],
    'CWE-693': [('WEB-16', 'medium', '보호 기법 미적용. 상동')],
    'CWE-16':  [('WEB-16', 'low', '설정 미흡. 범위가 넓어 검토 필요')],
    'CWE-276': [('WEB-14', 'medium', '기본 권한 부적절. 파일 접근 통제 항목')],
    'CWE-1188':[('WEB-16', 'low', '안전하지 않은 기본 설정. 검토 필요')],
    'CWE-937': [('WEB-25', 'high', '취약 버전 구성요소 사용. 보안 패치 적용 항목')],
    'CWE-1035':[('WEB-25', 'high', '상동')],
    'CWE-1104':[('WEB-25', 'high', '미유지보수 서드파티 구성요소. 상동')],
}

# ── exposure_key -> KISA 점검항목 ────────────────────────────────────
# 키 목록은 docs/00_API_SPEC.md §1.2 및 IMPLEMENTATION_BRIEF M4 와 일치해야 한다
EXPOSURE_GUIDE = [
    ('xmlrpc_enabled', 'WA-20', 'high',
     'xmlrpc.php 는 system.multicall 로 인증 시도를 증폭할 수 있어 자동화 공격 항목에 해당'),
    ('xmlrpc_enabled', 'WEB-15', 'medium',
     '운영에 불필요한 스크립트. 불필요한 스크립트 매핑 제거 항목'),
    ('rest_user_enum', 'WA-05', 'high',
     'REST API 를 통한 사용자 계정 열거. 정보 누출 항목'),
    ('readme_accessible', 'WEB-07', 'high',
     '설치 기본 파일 노출. 웹 서비스 경로 내 불필요한 파일 제거 항목'),
    ('readme_accessible', 'WA-05', 'medium',
     'readme 에서 제품 버전 확인 가능. 정보 누출'),
    ('directory_listing', 'WA-03', 'high', '디렉터리 인덱싱 항목에 직접 대응'),
    ('directory_listing', 'WEB-04', 'high', '웹 서비스 디렉터리 리스팅 방지 설정'),
    ('wp_version_exposed', 'WA-05', 'high',
     '제품 버전 노출. 공격자의 취약점 선별을 용이하게 함'),
    ('wp_version_exposed', 'WEB-16', 'medium', '헤더·메타 정보 노출 제한 항목'),
    ('wp_login_accessible', 'WA-19', 'high',
     '관리자 로그인 페이지가 외부에 노출. 관리자페이지 노출 항목'),
    ('wp_login_no_ratelimit', 'WA-20', 'high',
     '로그인 시도 제한 없음. 자동화 공격 항목'),
    ('wp_login_no_ratelimit', 'WA-09', 'medium',
     '약한 비밀번호 정책과 결합 시 계정 탈취 위험'),
    ('admin_page_public', 'WA-19', 'high', '관리자페이지 노출 항목에 직접 대응'),
    ('dir_backup_files', 'WEB-07', 'high', '백업·임시 파일 노출. 불필요한 파일 제거 항목'),
    ('dir_backup_files', 'WEB-13', 'high', '설정 파일 노출 제한 항목'),
    ('tls_weak_config', 'WEB-20', 'high', 'SSL/TLS 활성화 및 설정 항목'),
    ('tls_weak_config', 'WA-17', 'high', '데이터 평문 전송 항목'),
    ('server_header_verbose', 'WEB-16', 'high', '웹 서비스 헤더 정보 노출 제한 항목'),
]

# ── VulnType -> KISA 점검항목 (fallback) ─────────────────────────────
VT_GUIDE = {
    'rce': 'WA-01', 'deserialization': 'WA-01', 'sqli': 'WA-02', 'xss': 'WA-06',
    'csrf': 'WA-07', 'ssrf': 'WA-08', 'auth_bypass': 'WA-10',
    'path_traversal': 'WA-15', 'file_upload': 'WA-14', 'open_redirect': 'WEB-21',
    'info_disclosure': 'WA-05', 'access_control': 'WA-11', 'misconfig': 'WA-05',
}
VT_GUIDE_NOTE = {
    'misconfig': 'WordPress misconfiguration 템플릿은 대부분 경로·설정 노출이므로 정보 누출로 회수. 검토 필요',
}


# ── 테마 / 플러그인 판별 ───────────────────────────────────────────────
# nuclei-templates 는 WordPress 취약점을 전부 /http/cves/YYYY/ 아래에 둔다.
# 즉 템플릿 파일 경로에는 테마·플러그인 구분 정보가 없다.
# 구분은 템플릿이 요청하는 URL 에 있다:  /wp-content/themes/<slug>
# 파일 경로로 판별하면 테마 59종(twentytwenty*, astra, divi, oceanwp …)이
# 전부 wp_plugin 으로 떨어져 v_patch_plan 조인에서 빠진다. (CHANGELOG §12.3)
_TH_RE = re.compile(r'/wp-content/themes/([a-z0-9][a-z0-9._-]*)', re.I)
_PL_RE = re.compile(r'/wp-content/plugins/([a-z0-9][a-z0-9._-]*)', re.I)


def load_theme_slugs(root):
    """themes/ 에만 등장하는 슬러그 집합. 양쪽에 나오면 모호하므로 제외한다."""
    if not root:
        print('  [경고] --templates 미지정 → 테마 판별 불가. 전부 wp_plugin 이 된다.')
        return set()
    th, pl = set(), set()
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != '.git']
        for fn in files:
            if not fn.endswith(('.yaml', '.yml')):
                continue
            try:
                txt = open(os.path.join(dirpath, fn), encoding='utf-8',
                           errors='ignore').read()
            except Exception:
                continue
            th.update(m.lower() for m in _TH_RE.findall(txt))
            pl.update(m.lower() for m in _PL_RE.findall(txt))
    out = th - pl
    print(f'  테마 슬러그 {len(out)}종 (양쪽 등장 {len(th & pl)}종은 wp_plugin 유지)')
    return out


def vkey(v):
    if not v:
        return ''
    return '.'.join(f'{int(p):05d}' if p.isdigit() else p.rjust(5, '0')
                    for p in str(v).split('.')[:4])


def w(path, header, rows):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        cw = csv.writer(f, lineterminator='\n')
        cw.writerow(header)
        cw.writerows(rows)
    print(f'  {path:44} {len(rows)}행')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--guide-db', default='kisa.db')
    ap.add_argument('--out', default='data')
    ap.add_argument('--templates',
                    help='nuclei-templates 경로. 테마/플러그인 판별에 필요하다')
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    con = sqlite3.connect(args.guide_db)
    con.row_factory = sqlite3.Row
    valid = {r[0] for r in con.execute('SELECT code FROM item')}

    # ---- vuln_type_rules.csv ----
    rows = [['cwe_id', k, v, 10] for k, v in CWE_VT.items()]
    rows += [['tag', k, v, p] for k, v, p in TAG_VT]
    rows += [['template_prefix', k, v, p] for k, v, p in TEMPLATE_PREFIX_VT]
    bad = {r[2] for r in rows} - set(VULN_TYPES)
    if bad:
        sys.exit(f'VulnType Enum 밖의 값: {bad}')
    w(f'{args.out}/vuln_type_rules.csv',
      ['match_type', 'match_value', 'vuln_type', 'priority'], rows)

    # ---- guide_mappings.csv ----
    gm, seen = [], set()

    def add(mt, mv, code, conf, basis):
        if code not in valid:
            sys.exit(f'존재하지 않는 item_code: {code}')
        k = (mt, mv, code)
        if k in seen:
            return
        seen.add(k)
        gm.append([mt, mv, code, conf, basis])

    for cwe, ms in CWE_GUIDE.items():
        for code, conf, basis in ms:
            add('cwe_id', cwe, code, conf, basis)
    for key, code, conf, basis in EXPOSURE_GUIDE:
        add('exposure_key', key, code, conf, basis)
    for vt, code in VT_GUIDE.items():
        add('vuln_type', vt, code, 'low',
            VT_GUIDE_NOTE.get(vt, '상위 매핑 미적용 시 fallback. 유형 기준 최근접 항목'))
    add('cve_present', '*', 'WEB-25', 'high',
        'CVE 를 가진 탐지에 항상 추가. 유형별 근본 대책과 별도로 패치 적용을 남긴다 (2트랙)')

    w(f'{args.out}/guide_mappings.csv',
      ['match_type', 'match_value', 'item_code', 'confidence', 'mapping_basis'], gm)

    # ---- component_advisories.csv ----
    has_tpl = con.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE name='wp_template'").fetchone()[0]
    if not has_tpl:
        print('  (wp_template 없음 - advisories/templates CSV 생략)')
        return

    theme_slugs = load_theme_slugs(args.templates)

    adv, aseen = [], set()
    for t in con.execute("SELECT * FROM wp_template WHERE is_detect=0"):
        slugs = [x for x in (t['slugs'] or '').split(',') if x]
        cves = [x for x in (t['cve'] or '').split(',') if x] or ['']
        for slug in slugs:
            # 파일 경로가 아니라 슬러그의 출처로 판별한다. 위 load_theme_slugs 주석 참조.
            ctype = 'wp_theme' if slug.lower() in theme_slugs else 'wp_plugin'
            for cve in cves:
                k = (ctype, slug, cve, t['id'])
                if k in aseen:
                    continue
                aseen.add(k)
                fv = t['fix_version'] or ''
                adv.append([ctype, slug, cve, t['id'], (t['name'] or '')[:120],
                            f'< {fv}' if fv else '', fv, vkey(fv),
                            t['severity'] or '', t['cvss'] or '',
                            (t['reference'] or '').split('\n')[0][:160]])
    w(f'{args.out}/component_advisories.csv',
      ['component_type', 'slug', 'cve_id', 'template_id', 'title', 'affected_range',
       'fixed_version', 'fixed_version_key', 'severity', 'cvss_score', 'reference'], adv)

    # ---- guide_mappings.templates.csv (CWE 로 안 풀리는 예외만) ----
    rules_path = os.path.join(os.path.dirname(os.path.abspath(args.guide_db)),
                              'mapping_rules.yaml')
    kw = yaml.safe_load(open(rules_path, encoding='utf-8')).get('keyword', []) \
        if os.path.exists(rules_path) else []
    tex, tseen = [], set()
    for t in con.execute("SELECT * FROM wp_template WHERE is_detect=0"):
        cwes = [x for x in (t['cwe'] or '').split(',') if x]
        if any(c in CWE_GUIDE for c in cwes):
            continue                      # cwe_id 계층이 처리하므로 제외
        blob = f"{t['id']} {t['name']} {t['tags']} {t['path']}".lower()
        hit = next((r for r in kw if any(k in blob for k in r['match'])), None)
        if not hit or hit['code'] not in valid:
            continue
        k = (t['id'], hit['code'])
        if k in tseen:
            continue
        tseen.add(k)
        conf = 'high' if hit['conf'] >= 0.9 else ('medium' if hit['conf'] >= 0.6 else 'low')
        tex.append(['template_id', t['id'], hit['code'], conf,
                    f"CWE 미기재 템플릿. 키워드 근거: {'/'.join(hit['match'][:2])}"])
    w(f'{args.out}/guide_mappings.templates.csv',
      ['match_type', 'match_value', 'item_code', 'confidence', 'mapping_basis'], tex)
    con.close()


if __name__ == '__main__':
    main()
