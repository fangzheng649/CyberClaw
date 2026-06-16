@echo off
chcp 65001 >nul
title CyberClaw MQTT Broker
cd /d "%~dp0"
echo ========================================
echo   CyberClaw MQTT Broker 启动器
echo ========================================
echo.
echo 正在启动 broker...
echo （这个窗口要保持开着）
echo.
python start_broker.py
echo.
echo Broker 已停止。按任意键关闭窗口。
pause >nul
