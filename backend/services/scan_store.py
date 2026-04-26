# services/scan_store.py

from db import execute, fetch_one


def add_log(task_id, log_level, log_content):
    sql = """
    INSERT INTO scan_log (task_id, log_level, log_content)
    VALUES (%s, %s, %s)
    """
    execute(sql, (task_id, log_level, log_content))


def add_vulnerability(task_id, page_id, vuln_name, vuln_type, risk_level,
                      page_url, param_name=None, param_position=None,
                      payload=None, vuln_desc=None, evidence=None, suggestion=None):
    sql = """
    INSERT INTO vuln_result (
        task_id, page_id, vuln_name, vuln_type, risk_level, page_url,
        param_name, param_position, payload, vuln_desc, evidence, suggestion
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    execute(sql, (
        task_id, page_id, vuln_name, vuln_type, risk_level, page_url,
        param_name, param_position, payload, vuln_desc, evidence, suggestion
    ))


def save_page_info(task_id, page_url, page_title, response_status, page_level,
                   link_count, form_count, input_count, textarea_count, button_count):
    sql = """
    INSERT INTO page_info (
        task_id, page_url, page_title, request_method, response_status,
        page_level, link_count, form_count, input_count, textarea_count,
        button_count, is_scanned
    ) VALUES (%s, %s, %s, 'GET', %s, %s, %s, %s, %s, %s, %s, 1)
    """
    return execute(sql, (
        task_id, page_url, page_title, response_status, page_level,
        link_count, form_count, input_count, textarea_count, button_count
    ))


def update_task_statistics(task_id):
    page_row = fetch_one(
        "SELECT COUNT(*) AS total_pages FROM page_info WHERE task_id = %s",
        (task_id,)
    )
    vuln_row = fetch_one(
        "SELECT COUNT(*) AS total_vulns FROM vuln_result WHERE task_id = %s",
        (task_id,)
    )
    high_row = fetch_one(
        "SELECT COUNT(*) AS cnt FROM vuln_result WHERE task_id = %s AND risk_level = 3",
        (task_id,)
    )
    medium_row = fetch_one(
        "SELECT COUNT(*) AS cnt FROM vuln_result WHERE task_id = %s AND risk_level = 2",
        (task_id,)
    )
    low_row = fetch_one(
        "SELECT COUNT(*) AS cnt FROM vuln_result WHERE task_id = %s AND risk_level = 1",
        (task_id,)
    )

    sql = """
    UPDATE task_info
    SET total_pages = %s,
        total_vulns = %s,
        high_risk_count = %s,
        medium_risk_count = %s,
        low_risk_count = %s
    WHERE id = %s
    """
    execute(sql, (
        page_row['total_pages'],
        vuln_row['total_vulns'],
        high_row['cnt'],
        medium_row['cnt'],
        low_row['cnt'],
        task_id
    ))