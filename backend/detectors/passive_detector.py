# detectors/passive_detector.py

from urllib.parse import urlparse, parse_qsl

from services.scan_store import add_vulnerability


ERROR_KEYWORDS = [
    'sql syntax',
    'mysql',
    'syntax error',
    'warning',
    'exception',
    'traceback',
    'fatal error',
    'unclosed quotation mark'
]

COMMAND_PARAM_KEYWORDS = [
    'cmd', 'exec', 'command', 'ping', 'ip', 'host', 'query', 'shell'
]

COMMAND_OUTPUT_KEYWORDS = [
    'uid=',
    'gid=',
    'root:x:0:',
    'windows ip configuration',
    'volume serial number',
    'ping statistics'
]

SECURITY_HEADERS = [
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy'
]


def get_query_param_names(url):
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    return list(params.keys())


def detect_parameter_input(task_id, page_id, current_url):
    parsed = urlparse(current_url)
    if parsed.query:
        add_vulnerability(
            task_id=task_id,
            page_id=page_id,
            vuln_name='可疑URL参数输入点',
            vuln_type='Parameter',
            risk_level=1,
            page_url=current_url,
            param_name=parsed.query,
            param_position='URL参数',
            payload=None,
            vuln_desc='当前页面URL存在查询参数，可作为后续安全检测的潜在输入点。',
            evidence=f'URL中发现参数：{parsed.query}',
            suggestion='对URL参数进行严格校验、过滤和编码处理。'
        )


def detect_info_leak(task_id, page_id, current_url, html_lower):
    for keyword in ERROR_KEYWORDS:
        if keyword in html_lower:
            add_vulnerability(
                task_id=task_id,
                page_id=page_id,
                vuln_name='敏感错误信息暴露',
                vuln_type='InfoLeak',
                risk_level=2,
                page_url=current_url,
                param_name=None,
                param_position='页面内容',
                payload=None,
                vuln_desc='页面中出现了可能暴露后端实现细节的错误信息。',
                evidence=f'页面内容中匹配到关键词：{keyword}',
                suggestion='关闭生产环境调试信息，统一使用友好错误页面。'
            )
            break


def detect_missing_security_headers(task_id, page_id, current_url, headers):
    if not headers:
        return

    lower_headers = {k.lower(): v for k, v in headers.items()}
    missing_headers = [h for h in SECURITY_HEADERS if h not in lower_headers]

    if current_url.startswith('https://') and 'strict-transport-security' not in lower_headers:
        missing_headers.append('strict-transport-security')

    if missing_headers:
        add_vulnerability(
            task_id=task_id,
            page_id=page_id,
            vuln_name='安全响应头缺失',
            vuln_type='Header',
            risk_level=1,
            page_url=current_url,
            param_name=None,
            param_position='HTTP响应头',
            payload=None,
            vuln_desc='目标页面缺少部分常见安全响应头，可能增加被利用风险。',
            evidence='缺失响应头：' + ', '.join(missing_headers),
            suggestion='建议补充 CSP、X-Frame-Options、X-Content-Type-Options、Referrer-Policy 等安全响应头。'
        )


def detect_upload_risk(task_id, page_id, current_url, page):
    file_input_count = page.locator('input[type="file"]').count()
    if file_input_count == 0:
        return

    accept_missing = 0
    total_checked = min(file_input_count, 5)

    for i in range(total_checked):
        accept_value = page.locator('input[type="file"]').nth(i).get_attribute('accept')
        if not accept_value:
            accept_missing += 1

    form_count = page.locator('form').count()
    multipart_found = False
    for i in range(min(form_count, 5)):
        enctype = page.locator('form').nth(i).get_attribute('enctype')
        if enctype and 'multipart/form-data' in enctype.lower():
            multipart_found = True
            break

    risk_level = 2 if accept_missing > 0 else 1
    evidence_parts = [f'发现文件上传控件 {file_input_count} 个']
    if accept_missing > 0:
        evidence_parts.append(f'{accept_missing} 个控件未设置 accept 属性')
    if multipart_found:
        evidence_parts.append('页面存在 multipart/form-data 表单')

    add_vulnerability(
        task_id=task_id,
        page_id=page_id,
        vuln_name='文件上传风险特征',
        vuln_type='FileUpload',
        risk_level=risk_level,
        page_url=current_url,
        param_name=None,
        param_position='表单上传入口',
        payload=None,
        vuln_desc='检测到文件上传入口，若服务端校验不足，可能引发不安全文件上传问题。',
        evidence='；'.join(evidence_parts),
        suggestion='对上传文件的类型、扩展名、大小和内容进行服务端白名单校验，并将上传目录与执行目录隔离。'
    )


def detect_command_execution_risk(task_id, page_id, current_url, page, html_lower):
    suspicious_fields = []

    elements = page.eval_on_selector_all(
        'input, textarea',
        """
        elements => elements.map(e => ({
            name: e.getAttribute('name') || '',
            placeholder: e.getAttribute('placeholder') || '',
            type: e.getAttribute('type') || ''
        }))
        """
    )

    for item in elements:
        name = (item.get('name') or '').lower()
        placeholder = (item.get('placeholder') or '').lower()

        for keyword in COMMAND_PARAM_KEYWORDS:
            if keyword in name or keyword in placeholder:
                suspicious_fields.append(name or placeholder)
                break

    query_params = get_query_param_names(current_url)
    suspicious_params = []
    for param in query_params:
        lower_param = param.lower()
        for keyword in COMMAND_PARAM_KEYWORDS:
            if keyword in lower_param:
                suspicious_params.append(param)
                break

    output_hits = []
    for keyword in COMMAND_OUTPUT_KEYWORDS:
        if keyword in html_lower:
            output_hits.append(keyword)

    if suspicious_fields or suspicious_params or output_hits:
        risk_level = 3 if output_hits else 2
        evidence_parts = []

        if suspicious_fields:
            evidence_parts.append('疑似高风险输入字段：' + ', '.join(list(set(suspicious_fields))[:5]))
        if suspicious_params:
            evidence_parts.append('疑似高风险参数：' + ', '.join(list(set(suspicious_params))[:5]))
        if output_hits:
            evidence_parts.append('页面输出中出现系统命令结果特征：' + ', '.join(output_hits[:5]))

        add_vulnerability(
            task_id=task_id,
            page_id=page_id,
            vuln_name='潜在命令执行风险',
            vuln_type='CommandExec',
            risk_level=risk_level,
            page_url=current_url,
            param_name=', '.join(list(set(suspicious_params))[:5]) if suspicious_params else None,
            param_position='URL参数/表单输入',
            payload=None,
            vuln_desc='页面存在疑似命令执行相关特征，若后端将用户输入直接拼接到系统命令中，可能导致命令执行风险。',
            evidence='；'.join(evidence_parts),
            suggestion='禁止直接拼接系统命令，对输入参数进行白名单校验，并使用安全 API 替代 shell 调用。'
        )