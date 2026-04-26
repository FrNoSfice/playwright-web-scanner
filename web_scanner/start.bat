@echo off
chcp 65001 >nul
setlocal

cd /d "%~dp0"

set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"

set "BACKEND_DIR=%PROJECT_DIR%\backend"
set "FRONTEND_DIR=%PROJECT_DIR%\frontend"
set "TEST_LAB_DIR=%PROJECT_DIR%\test_lab"

title Web Scanner Launcher

echo ==============================
echo Web Scanner Launcher
echo ==============================
echo.

if not exist "%BACKEND_DIR%" (
    echo [ERROR] backend folder not found.
    pause
    exit /b
)

if not exist "%FRONTEND_DIR%" (
    echo [ERROR] frontend folder not found.
    pause
    exit /b
)

if not exist "%TEST_LAB_DIR%" (
    echo [ERROR] test_lab folder not found.
    pause
    exit /b
)

if not exist "%BACKEND_DIR%\config.py" (
    echo [WARN] backend\config.py not found.
    echo Please copy backend\config.example.py to backend\config.py and edit database config.
    echo.
)

echo [1/3] Start test_lab on http://127.0.0.1:5001
start "Test Lab - Flask 5001" cmd /k "cd /d ""%TEST_LAB_DIR%"" && python app.py"

timeout /t 2 /nobreak >nul

echo [2/3] Start backend on http://127.0.0.1:5000
start "Scanner Backend - Flask 5000" cmd /k "cd /d ""%BACKEND_DIR%"" && python app.py"

timeout /t 2 /nobreak >nul

echo [3/3] Start frontend on http://127.0.0.1:5173
start "Scanner Frontend - Vue 5173" cmd /k "cd /d ""%FRONTEND_DIR%"" && npm run dev"

echo.
echo ==============================
echo Started.
echo ==============================
echo Test Lab: http://127.0.0.1:5001
echo Backend : http://127.0.0.1:5000
echo Frontend: http://127.0.0.1:5173
echo.
pause