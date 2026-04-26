# app.py

from flask import Flask, request, jsonify
from flask_cors import CORS

from db import fetch_one, fetch_all, execute, execute_update, execute_transaction
from scanner import start_scan_thread, add_log


app = Flask(__name__)
CORS(app)


def success(data=None, message='success', code=200):
    return jsonify({
        'code': code,
        'message': message,
        'data': data
    }), code


def fail(message='fail', code=400):
    return jsonify({
        'code': code,
        'message': message,
        'data': None
    }), code


def format_datetime_field(row, fields):
    if not row:
        return row
    for field in fields:
        if field in row and row[field]:
            row[field] = row[field].strftime('%Y-%m-%d %H:%M:%S')
    return row


def format_datetime_rows(rows, fields):
    result = []
    for row in rows:
        result.append(format_datetime_field(row, fields))
    return result


@app.route('/')
def index():
    return 'Web Scan System Running'


# 1. 创建任务
@app.route('/task/create', methods=['POST'])
def create_task():
    data = request.get_json()

    task_name = data.get('task_name', '').strip()
    target_url = data.get('target_url', '').strip()
    scan_depth = data.get('scan_depth', 1)
    remark = data.get('remark', '').strip()

    if not task_name:
        return fail('任务名称不能为空')

    if not target_url:
        return fail('目标网址不能为空')

    if not (target_url.startswith('http://') or target_url.startswith('https://')):
        return fail('目标网址格式不正确，必须以 http:// 或 https:// 开头')

    sql = """
    INSERT INTO task_info (task_name, target_url, scan_depth, remark)
    VALUES (%s, %s, %s, %s)
    """
    task_id = execute(sql, (task_name, target_url, scan_depth, remark))

    add_log(task_id, 'INFO', '扫描任务已创建，等待执行')

    return success(
        data={'task_id': task_id},
        message='任务创建成功'
    )


# 2. 获取任务列表
@app.route('/task/list', methods=['GET'])
def task_list():
    sql = """
          SELECT id, \
                 task_name, \
                 target_url, \
                 scan_depth, \
                 scan_status,
                 total_pages, \
                 total_vulns, \
                 high_risk_count,
                 medium_risk_count, \
                 low_risk_count,
                 success_pages, \
                 failed_pages,
                 created_at, \
                 started_at, \
                 finished_at
          FROM task_info
          ORDER BY id DESC \
          """
    rows = fetch_all(sql)
    rows = format_datetime_rows(rows, ['created_at', 'started_at', 'finished_at'])
    return success(data=rows)


# 3. 获取单个任务详情
@app.route('/task/<int:task_id>', methods=['GET'])
def task_detail(task_id):
    sql = """
    SELECT *
    FROM task_info
    WHERE id = %s
    """
    row = fetch_one(sql, (task_id,))
    if not row:
        return fail('任务不存在', 404)

    row = format_datetime_field(row, ['created_at', 'started_at', 'finished_at', 'updated_at'])
    return success(data=row)


# 4. 启动扫描
@app.route('/scan/start/<int:task_id>', methods=['POST'])
def start_scan(task_id):
    task = fetch_one("SELECT * FROM task_info WHERE id = %s", (task_id,))
    if not task:
        return fail('任务不存在', 404)

    if task['scan_status'] == 1:
        return fail('该任务正在扫描中，不能重复启动')

    # 清空旧结果，便于重复测试
    execute("DELETE FROM vuln_result WHERE task_id = %s", (task_id,))
    execute("DELETE FROM page_info WHERE task_id = %s", (task_id,))
    execute("""
            UPDATE task_info
            SET total_pages       = 0,
                total_vulns       = 0,
                high_risk_count   = 0,
                medium_risk_count = 0,
                low_risk_count    = 0,
                success_pages     = 0,
                failed_pages      = 0,
                started_at        = NULL,
                finished_at       = NULL
            WHERE id = %s
            """, (task_id,))

    add_log(task_id, 'INFO', '用户手动启动扫描任务')

    start_scan_thread(task_id)

    return success(message='扫描已启动')


# 5. 获取扫描结果
@app.route('/result/<int:task_id>', methods=['GET'])
def result_list(task_id):
    task = fetch_one("SELECT id FROM task_info WHERE id = %s", (task_id,))
    if not task:
        return fail('任务不存在', 404)

    sql = """
    SELECT id, task_id, page_id, vuln_name, vuln_type, risk_level,
           page_url, param_name, param_position, payload,
           vuln_desc, evidence, suggestion, scan_time,
           created_at, updated_at
    FROM vuln_result
    WHERE task_id = %s
    ORDER BY risk_level DESC, id DESC
    """
    rows = fetch_all(sql, (task_id,))
    rows = format_datetime_rows(rows, ['scan_time', 'created_at', 'updated_at'])
    return success(data=rows)


# 6. 获取任务日志（后面你前端也可以加一个日志页）
@app.route('/task/log/<int:task_id>', methods=['GET'])
def task_logs(task_id):
    sql = """
    SELECT id, task_id, log_level, log_content, created_at
    FROM scan_log
    WHERE task_id = %s
    ORDER BY id DESC
    """
    rows = fetch_all(sql, (task_id,))
    rows = format_datetime_rows(rows, ['created_at'])
    return success(data=rows)


@app.route('/task/delete/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    task = fetch_one(
        "SELECT id, scan_status, task_name FROM task_info WHERE id = %s",
        (task_id,)
    )
    if not task:
        return fail('任务不存在', 404)

    # scan_status = 1 表示扫描中，这版源码里就是这个状态
    if task['scan_status'] == 1:
        return fail('该任务正在扫描中，不能删除')

    try:
        execute_transaction([
            ("DELETE FROM vuln_result WHERE task_id = %s", (task_id,)),
            ("DELETE FROM page_info WHERE task_id = %s", (task_id,)),
            ("DELETE FROM scan_log WHERE task_id = %s", (task_id,)),
            ("DELETE FROM task_info WHERE id = %s", (task_id,))
        ])

        return success(message='任务删除成功')
    except Exception as e:
        return fail(f'删除任务失败：{str(e)}', 500)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)