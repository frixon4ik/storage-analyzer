@echo off
REM Build for Windows: dist\FolderAnalyzer.exe (single portable file, no Python needed).
REM Run ON Windows (PyInstaller builds only for the current OS). Requires Python 3.10+.
setlocal
cd /d "%~dp0"

set "PY=python"
where py >/dev/null 2>/dev/null && set "PY=py -3"

if not exist ".venv\Scripts\python.exe" (
  %PY% -m venv .venv || goto :error
)
".venv\Scripts\python.exe" -m pip install --upgrade pip || goto :error
".venv\Scripts\python.exe" -m pip install -r requirements.txt pyinstaller || goto :error
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean FolderAnalyzer.spec || goto :error

echo.
echo Done: dist\FolderAnalyzer.exe
exit /b 0

:error
echo.
echo Build failed. Make sure Python 3.10+ is installed (https://www.python.org/downloads/).
exit /b 1
