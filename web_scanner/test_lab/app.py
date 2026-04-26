from flask import Flask, request, render_template, jsonify
import pymysql

app = Flask(__name__)

def get_conn():
    return pymysql.connect(
        host="127.0.0.1",
        user="lab_user",
        password="lab_pass_2026",
        database="test_lab",
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor
    )

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/dynamic/list")
def dynamic_list():
    return render_template("dynamic_list.html")

@app.route("/api/products")
def api_products():
    conn = get_conn()
    with conn.cursor() as cursor:
        cursor.execute("SELECT id,name,price FROM products")
        rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)

@app.route("/dynamic/form")
def dynamic_form():
    return render_template("dynamic_form.html")

@app.route("/sqli/item")
def sqli_item():
    item_id = request.args.get("id", "")
    conn = get_conn()
    try:
        with conn.cursor() as cursor:
            sql = f"SELECT id,name,price,description FROM products WHERE id = {item_id}"
            cursor.execute(sql)
            row = cursor.fetchone()
        conn.close()
        return render_template("sqli_item.html", row=row, item_id=item_id, error=None)
    except Exception as e:
        conn.close()
        return render_template("sqli_item.html", row=None, item_id=item_id, error=str(e)), 500

@app.route("/sqli/login", methods=["GET", "POST"])
def sqli_login():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_conn()
        try:
            with conn.cursor() as cursor:
                sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
                cursor.execute(sql)
                row = cursor.fetchone()
            conn.close()
            if row:
                msg = f"欢迎，{row['username']}，角色：{row['role']}"
            else:
                msg = "用户名或密码错误"
        except Exception as e:
            conn.close()
            msg = f"数据库异常：{e}"
    return render_template("sqli_login.html", msg=msg)

@app.route("/xss/reflect")
def xss_reflect():
    q = request.args.get("q", "")
    return render_template("xss_reflect.html", q=q)

@app.route("/xss/store", methods=["GET", "POST"])
def xss_store():
    conn = get_conn()
    if request.method == "POST":
        nickname = request.form.get("nickname", "")
        content = request.form.get("content", "")
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO comments(nickname, content) VALUES(%s, %s)",
                (nickname, content)
            )
        conn.commit()

    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM comments ORDER BY id DESC")
        rows = cursor.fetchall()
    conn.close()
    return render_template("xss_store.html", rows=rows)

@app.route("/xss/dom")
def xss_dom():
    return render_template("xss_dom.html")

@app.route("/debug/error")
def debug_error():
    fake_error = """
Traceback (most recent call last):
  File "/srv/test_lab/app.py", line 999, in debug_error
    a = 1 / 0
ZeroDivisionError: division by zero

SQLSTATE[42000]: You have an error in your SQL syntax
Warning: debug mode enabled
"""
    return fake_error, 500, {"Content-Type": "text/plain; charset=utf-8"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)