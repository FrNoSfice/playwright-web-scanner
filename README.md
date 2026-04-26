基于 Playwright 的 Web 安全扫描原型系统

一、项目简介

本项目是一个面向动态网页场景的 Web 安全扫描原型系统，主要用于本科毕业设计。

系统采用前后端分离结构，后端基于 Flask 和 Playwright 实现页面访问、链接发现、表单识别、被动检测、SQL 注入风险检测和 XSS 风险识别；前端基于 Vue 3 实现扫描任务创建、任务列表展示、扫描结果查看和漏洞信息展示。

本系统主要面向教学、毕业设计和授权测试环境，用于验证动态网页场景下 Web 安全扫描流程的基本可行性。


二、技术栈

1. 前端

- Vue 3
- Vue Router
- Axios
- Element Plus
- Vite

2. 后端

- Python
- Flask
- Playwright

3. 数据库

- MySQL

4. 测试靶场

- Flask
- MySQL

5. 检测内容

- SQL 注入风险检测
- XSS 风险识别
- 敏感错误信息检测
- 安全响应头缺失检测
- 页面链接发现
- 表单识别


三、项目结构

web_scanner/
├── backend/          后端接口、扫描调度和漏洞检测逻辑
├── frontend/         前端页面与接口调用
├── database/         扫描系统数据库初始化脚本
├── test_lab/         本地测试靶场
├── start_web.bat     Windows 本地启动脚本
├── requirements.txt  Python 依赖文件
└── README.txt        项目说明文件


四、运行环境

建议使用以下环境运行本项目：

- Windows 10 / Windows 11
- Python 3.10 及以上
- Node.js 18 及以上
- MySQL 8.0
- Chromium 浏览器环境，由 Playwright 自动安装


五、后端运行

进入后端目录：

cd backend

安装 Python 依赖：

pip install -r ../requirements.txt

安装 Playwright 浏览器环境：

playwright install

复制配置文件：

copy config.example.py config.py

运行前请根据本机 MySQL 配置修改：

backend/config.py

启动后端服务：

python app.py


六、前端运行

进入前端目录：

cd frontend

安装前端依赖：

npm install

启动前端开发服务：

npm run dev

启动成功后，可根据终端提示访问前端页面，通常为：

http://localhost:5173/


七、数据库初始化

请先确保 MySQL 服务已经启动。

在项目根目录执行：

mysql -u root -p < database/init.sql

如果使用的是非 root 用户，请根据实际情况修改命令中的用户名。


八、测试靶场运行

进入测试靶场目录：

cd test_lab

启动靶场服务：

python app.py

靶场默认访问地址：

http://127.0.0.1:5001/

测试靶场主要用于配合扫描系统进行功能验证，包括动态页面、表单提交、SQL 注入测试页面和 XSS 测试页面等。


九、基本使用流程

1. 启动 MySQL 数据库；
2. 初始化扫描系统数据库；
3. 启动测试靶场；
4. 启动后端 Flask 服务；
5. 启动前端 Vue 服务；
6. 在前端页面中新建扫描任务；
7. 输入目标地址，例如：

http://127.0.0.1:5001/

8. 等待扫描完成后，在任务列表或结果页面查看检测结果。


十、注意事项

1. 本项目仅用于教学、毕业设计和授权测试环境；
2. 禁止将本项目用于未授权网站扫描；
3. 扫描前请确认目标站点属于本地靶场、实验环境或已获得授权的测试范围；
4. 首次运行 Playwright 前需要执行 playwright install；
5. 运行前请检查 backend/config.py 中的数据库连接信息是否正确；
6. 如果前端无法获取任务列表，请优先检查后端服务和数据库连接是否正常。


十一、项目用途声明

本项目为本科毕业设计原型系统，主要用于展示基于 Playwright 的动态网页访问、页面发现、输入点识别和基础 Web 漏洞风险检测流程。

项目不以商业化扫描器为目标，检测结果仅作为教学实验和毕业设计分析依据。
