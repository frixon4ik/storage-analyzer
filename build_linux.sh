#!/usr/bin/env bash
# Сборка портативного бинарника для Linux (Ubuntu и др.).
# Запускать НА Linux (PyInstaller собирает только под текущую ОС).
set -e
cd "$(dirname "$0")"

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt pyinstaller

python3 -m PyInstaller --noconfirm --onefile --name FolderAnalyzer \
  --add-data "app_icon.png:." \
  --collect-submodules botocore --collect-data botocore --collect-data boto3 \
  app.py

echo
echo "Готово: dist/FolderAnalyzer  — портативный исполняемый файл."
echo "Запуск:  ./dist/FolderAnalyzer"
echo
echo "Зависимости системы (если PySide6 не стартует): sudo apt install libxcb-cursor0 libegl1"
