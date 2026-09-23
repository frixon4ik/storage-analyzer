#!/usr/bin/env bash
# Сборка для macOS: dist/FolderAnalyzer.app + установочный образ dist/FolderAnalyzer-<версия>.dmg
# Запускать НА macOS (PyInstaller собирает только под текущую ОС и архитектуру).
#
#   ./build_macos.sh                         # обычная сборка (ad-hoc подпись)
#   CODESIGN_IDENTITY="Developer ID Application: …" ./build_macos.sh   # подпись сертификатом
#   TARGET_ARCH=universal2 ./build_macos.sh  # только с universal-сборкой Python
set -euo pipefail
cd "$(dirname "$0")"

VERSION="2.0"
VENV=".venv"

# --- окружение: нужен Python 3.10+ (системный /usr/bin/python3 на macOS — 3.9)
if [ ! -x "$VENV/bin/python" ]; then
  if command -v uv >/dev/null 2>&1; then
    uv venv --python 3.12 "$VENV"
  else
    PY=""
    for c in python3.13 python3.12 python3.11 python3.10 python3; do
      if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
        PY="$c"; break
      fi
    done
    if [ -z "$PY" ]; then
      echo "Нужен Python 3.10+ (python.org, Homebrew: brew install python, или uv)." >&2
      exit 1
    fi
    "$PY" -m venv "$VENV"
  fi
fi
if command -v uv >/dev/null 2>&1; then
  uv pip install --python "$VENV/bin/python" -r requirements.txt pyinstaller pillow
else
  "$VENV/bin/python" -m pip install --upgrade pip
  "$VENV/bin/python" -m pip install -r requirements.txt pyinstaller pillow
fi

# --- иконка по сетке macOS
"$VENV/bin/python" make_icon.py --macos

# --- сборка .app
rm -rf build/FolderAnalyzer-macOS dist/FolderAnalyzer dist/FolderAnalyzer.app
"$VENV/bin/python" -m PyInstaller --noconfirm --clean FolderAnalyzer-macOS.spec

APP="dist/FolderAnalyzer.app"
codesign --verify --deep --strict "$APP" && echo "Подпись .app корректна."

# --- установочный образ .dmg (перетащить в «Программы»)
DMG="dist/FolderAnalyzer-$VERSION.dmg"
STAGE="$(mktemp -d)"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Программы"
rm -f "$DMG"
hdiutil create -volname "Анализатор хранилищ" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGE"

echo
echo "Готово:"
echo "  $APP  — приложение (перетащите в «Программы»)"
echo "  $DMG  — установочный образ"
echo
echo "Первый запуск неподписанной сборки: ПКМ по приложению → «Открыть»,"
echo "или: xattr -dr com.apple.quarantine /Applications/FolderAnalyzer.app"
