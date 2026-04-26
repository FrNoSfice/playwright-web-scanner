# detectors/xss_detector.py

from urllib.parse import urlparse, parse_qsl

from services.scan_store import add_vulnerability


DANGEROUS_JS_KEYWORDS = [
    'innerhtml',
    'outerhtml',
    'document.write',
    'eval(',
    'insertadjacenthtml'
]


def get_query_param_names(url):
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    return list(params.keys())


def detect_dom_xss_risk(task_id, page_id, current_url, html_lower):
    matched = []
    for keyword in DANGEROUS_JS_KEYWORDS:
        if keyword in html_lower:
            matched.append(keyword)

    if matched:
        add_vulnerability(
            task_id=task_id,
            page_id=page_id,
            vuln_name='DOM型XSS风险特征',
            vuln_type='XSS',
            risk_level=2,
            page_url=current_url,
            param_name=None,
            param_position='前端脚本',
            payload=None,
            vuln_desc='页面脚本中存在可能导致 DOM 型 XSS 的危险函数调用特征。',
            evidence='匹配到危险关键词：' + ', '.join(matched[:5]),
            suggestion='避免直接使用 innerHTML、document.write、eval 等危险 API，必要时对输入进行编码与过滤。'
        )


def build_test_url(url, param_name, param_value):
    from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param_name] = param_value
    new_query = urlencode(params, doseq=True)

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))


def fetch_page_snapshot(context, url):
    page = context.new_page()
    try:
        response = page.goto(url, wait_until='networkidle', timeout=15000)
        status_code = response.status if response else 200
        html = page.content()
        return status_code, html
    finally:
        page.close()


def detect_basic_reflected_xss(context, task_id, page_id, current_url):
    param_names = get_query_param_names(current_url)
    if not param_names:
        return False

    for param_name in param_names[:3]:
        payload = '<xssprobe2026>'
        test_url = build_test_url(current_url, param_name, payload)

        try:
            _, test_html = fetch_page_snapshot(context, test_url)
        except Exception:
            continue

        if payload.lower() in test_html.lower():
            add_vulnerability(
                task_id=task_id,
                page_id=page_id,
                vuln_name='潜在反射型XSS风险',
                vuln_type='XSS',
                risk_level=2,
                page_url=current_url,
                param_name=param_name,
                param_position='URL参数',
                payload=payload,
                vuln_desc='简单反射测试中，输入标记在响应页面中原样出现，存在潜在反射型 XSS 风险。',
                evidence=f'参数 {param_name} 的测试标记在页面响应中原样出现。',
                suggestion='对用户输入进行 HTML 编码与过滤，避免未经处理的内容直接输出到页面。'
            )
            return True

    return False