#!/usr/bin/env bash
# Сборка для macOS: .app-бандл (с установкой перетаскиванием) + портативный бинарник.
# Запускать НА macOS.
set -e
cd "$(dirname "$0")"

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt pyinstaller

ICON=""
[ -f app_icon.icns ] && ICON="--icon app_icon.icns"

python3 -m PyInstaller --noconfirm --windowed --onefile --name FolderAnalyzer $ICON \
  --add-data "app_icon.png:." \
  --collect-submodules botocore --collect-data botocore --collect-data boto3 \
  app.py

echo
echo "Готово:"
echo "  dist/FolderAnalyzer.app — приложение (перетащите в /Applications)"
echo "  dist/FolderAnalyzer     — портативный бинарник для запуска из терминала"
echo
echo "Если macOS блокирует запуск (неподписанное): ПКМ по .app → «Открыть»,"
echo "или: xattr -dr com.apple.quarantine dist/FolderAnalyzer.app"
