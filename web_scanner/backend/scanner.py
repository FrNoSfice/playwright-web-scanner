# scanner.py

import ipaddress
import threading
from collections import deque
from datetime import datetime
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

from db import execute, fetch_one
from services.scan_store import add_log, save_page_info, update_task_statistics
from detectors.sql_detector import detect_sql_injection
from detectors.xss_detector import detect_dom_xss_risk, detect_basic_reflected_xss
from detectors.passive_detector import (
    detect_parameter_input,
    detect_info_leak,
    detect_missing_security_headers,
    detect_upload_risk,
    detect_command_execution_risk,
)


def normalize_url(url):
    if not url:
        return None
    url = url.split('#')[0].strip()
    if not url.startswith('http://') and not url.startswith('https://'):
        return None
    return url


def is_same_domain(base_url, target_url):
    return urlparse(base_url).netloc == urlparse(target_url).netloc


def is_local_or_private_target(url):
    hostname = urlparse(url).hostname
    if not hostname:
        return False

    if hostname in ['127.0.0.1', 'localhost', '::1']:
        return True

    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def scan_single_page(context, task_id, current_url, depth, allow_active_test):
    page = context.new_page()
    try:
        response = page.goto(current_url, wait_until='networkidle', timeout=30000)
        status_code = response.status if response else 200
        headers = response.all_headers() if response else {}

        page_title = page.title()
        html = page.content()
        html_lower = html.lower()

        link_count = page.locator('a').count()
        form_count = page.locator('form').count()
        input_count = page.locator('input').count()
        textarea_count = page.locator('textarea').count()
        button_count = page.locator('button').count()

        page_id = save_page_info(
            task_id=task_id,
            page_url=current_url,
            page_title=page_title,
            response_status=status_code,
            page_level=depth,
            link_count=link_count,
            form_count=form_count,
            input_count=input_count,
            textarea_count=textarea_count,
            button_count=button_count
        )

        # 被动检测
        detect_parameter_input(task_id, page_id, current_url)
        detect_info_leak(task_id, page_id, current_url, html_lower)
        detect_missing_security_headers(task_id, page_id, current_url, headers)
        detect_dom_xss_risk(task_id, page_id, current_url, html_lower)
        detect_upload_risk(task_id, page_id, current_url, page)
        detect_command_execution_risk(task_id, page_id, current_url, page, html_lower)

        # 主动检测
        if allow_active_test:
            detect_sql_injection(context, task_id, page_id, current_url, page)
            detect_basic_reflected_xss(context, task_id, page_id, current_url)

        href_list = page.eval_on_selector_all(
            'a[href]',
            'elements => elements.map(e => e.href)'
        )

        result_links = []
        for href in href_list:
            full_url = normalize_url(href)
            if full_url and is_same_domain(current_url, full_url):
                result_links.append(full_url)

        return list(set(result_links))

    finally:
        page.close()


def run_scan_task(task_id):
    task = fetch_one("SELECT * FROM task_info WHERE id = %s", (task_id,))
    if not task:
        return

    target_url = task['target_url']
    scan_depth = task['scan_depth']
    allow_active_test = is_local_or_private_target(target_url)

    success_count = 0
    fail_count = 0

    try:
        add_log(task_id, 'INFO', f'扫描任务开始，目标地址：{target_url}')
        add_log(
            task_id,
            'INFO',
            '当前扫描模式：授权深度检测' if allow_active_test else '当前扫描模式：第三方基础检测'
        )

        execute(
            "UPDATE task_info SET scan_status = %s, started_at = %s WHERE id = %s",
            (1, datetime.now(), task_id)
        )

        visited = set()
        queue = deque()
        queue.append((target_url, 1))

        max_pages = 20

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)

            while queue and len(visited) < max_pages:
                current_url, depth = queue.popleft()

                if current_url in visited:
                    continue
                if depth > scan_depth:
                    continue

                try:
                    visited.add(current_url)
                    add_log(task_id, 'INFO', f'正在扫描页面：{current_url}')
                    links = scan_single_page(context, task_id, current_url, depth, allow_active_test)
                    success_count += 1

                    for link in links:
                        if link not in visited:
                            queue.append((link, depth + 1))

                except Exception as e:
                    fail_count += 1
                    add_log(task_id, 'ERROR', f'页面扫描失败：{current_url}，原因：{str(e)}')

            browser.close()

        update_task_statistics(task_id)

        if success_count == 0:
            execute("""
                UPDATE task_info
                SET scan_status = %s,
                    finished_at = %s,
                    success_pages = %s,
                    failed_pages = %s
                WHERE id = %s
            """, (3, datetime.now(), success_count, fail_count, task_id))

            add_log(task_id, 'ERROR', f'扫描任务失败：所有页面均扫描失败，共失败 {fail_count} 页')
        else:
            execute("""
                UPDATE task_info
                SET scan_status = %s,
                    finished_at = %s,
                    success_pages = %s,
                    failed_pages = %s
                WHERE id = %s
            """, (2, datetime.now(), success_count, fail_count, task_id))

            add_log(task_id, 'INFO', f'扫描任务已完成：成功 {success_count} 页，失败 {fail_count} 页')

    except Exception as e:
        execute("""
            UPDATE task_info
            SET scan_status = %s,
                finished_at = %s,
                success_pages = %s,
                failed_pages = %s
            WHERE id = %s
        """, (3, datetime.now(), success_count, fail_count, task_id))

        add_log(task_id, 'ERROR', f'扫描任务失败：{str(e)}')


def start_scan_thread(task_id):
    thread = threading.Thread(target=run_scan_task, args=(task_id,), daemon=True)
    thread.start()