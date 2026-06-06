@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
title CyberClaw - IoT Security Platform

set "ROOT_DIR=%~dp0"
if "%ROOT_DIR:~-1%"=="\" set "ROOT_DIR=%ROOT_DIR:~0,-1%"

echo.
echo  ==========================================
echo    CyberClaw - IoT Security Platform
echo  ==========================================
echo.

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] python not found, install Python 3.10+
    pause
    exit /b 1
)

where node >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] node not found, install Node.js 18+
    pause
    exit /b 1
)

if not exist "%ROOT_DIR%\.env" (
    if exist "%ROOT_DIR%\.env.example" (
        copy "%ROOT_DIR%\.env.example" "%ROOT_DIR%\.env" >nul
        echo  [CONFIG] .env created from .env.example
        echo  Please edit .env and fill in GLM_API_KEY
        notepad "%ROOT_DIR%\.env"
        pause
        exit /b 0
    )
)

echo  [1/4] Checking backend dependencies...
python -c "import cyberclaw_core" >nul 2>&1
if !errorlevel! neq 0 (
    echo  [INSTALL] cyberclaw_core...
    pushd "%ROOT_DIR%\src\cyberclaw_core"
    pip install -e . -q
    popd
)
python -c "import fastapi" >nul 2>&1
if !errorlevel! neq 0 (
    echo  [INSTALL] server requirements...
    pushd "%ROOT_DIR%"
    pip install -r server/requirements.txt -q
    popd
)

echo  [2/4] Checking frontend dependencies...
if not exist "%ROOT_DIR%\ui\cyberclaw-hud\node_modules" (
    echo  [INSTALL] npm install...
    pushd "%ROOT_DIR%\ui\cyberclaw-hud"
    call npm install
    popd
)

echo  [3/4] Starting backend FastAPI :8000 ...
start "CyberClaw Backend" /d "%ROOT_DIR%" cmd /k python -m uvicorn server.main:app --reload --port 8000

echo        Waiting for backend...
set READY=0
for /L %%i in (1,1,30) do (
    if !READY!==0 (
        ping -n 2 127.0.0.1 >nul 2>&1
        python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/topology', timeout=2)" >nul 2>&1
        if !errorlevel!==0 (
            set READY=1
            echo        Backend ready
        )
    )
)
if !READY!==0 (
    echo        Backend may still be starting...
    timeout /t 2 /nobreak >nul
)

echo  [4/4] Starting frontend Vite+Express :3000 ...
start "CyberClaw Frontend" /d "%ROOT_DIR%\ui\cyberclaw-hud" cmd /k npm run dev

echo.
echo  ==========================================
echo   Ready! Access:
echo.
echo   3D HUD:    http://localhost:3000
echo   Chat:      http://localhost:3000/chat/
echo   API Docs:  http://localhost:8000/docs
echo.
echo   Close cmd windows to stop services
echo  ==========================================
echo.

timeout /t 2 /nobreak >nul
start http://localhost:3000

endlocal
pause
