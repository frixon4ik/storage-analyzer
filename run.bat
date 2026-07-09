@echo off
REM Запуск анализатора папок
cd /d "%~dp0"
python app.py
if errorlevel 1 pause
