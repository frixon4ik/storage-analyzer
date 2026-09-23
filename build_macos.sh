#!/usr/bin/env bash
# macOS build: dist/FolderAnalyzer.app + disk image dist/FolderAnalyzer-<version>.dmg
# Run ON macOS (PyInstaller builds only for the current OS and CPU architecture).
#
#   ./build_macos.sh                         # regular build (ad-hoc signature)
#   CODESIGN_IDENTITY="Developer ID Application: …" ./build_macos.sh   # sign with a certificate
#   TARGET_ARCH=universal2 ./build_macos.sh  # only with a universal Python build
set -euo pipefail
cd "$(dirname "$0")"

VERSION="2.1"
VENV=".venv"

# --- environment: Python 3.10+ is required (the system /usr/bin/python3 on macOS is 3.9)
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
      echo "Python 3.10+ is required (python.org, Homebrew: brew install python, or uv)." >&2
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

# --- icon on the macOS grid
"$VENV/bin/python" make_icon.py --macos

# --- build the .app
rm -rf build/FolderAnalyzer-macOS dist/FolderAnalyzer dist/FolderAnalyzer.app
"$VENV/bin/python" -m PyInstaller --noconfirm --clean FolderAnalyzer-macOS.spec

APP="dist/FolderAnalyzer.app"
codesign --verify --deep --strict "$APP" && echo "App signature is valid."

# --- disk image (drag the app into Applications)
DMG="dist/FolderAnalyzer-$VERSION.dmg"
STAGE="$(mktemp -d)"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
rm -f "$DMG"
hdiutil create -volname "Storage Analyzer" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null 2>&1
rm -rf "$STAGE" build dist/FolderAnalyzer

echo
echo "Done:"
echo "  $APP  — the application (drag it into Applications)"
echo "  $DMG  — disk image"
echo
echo "First launch of an unsigned build: right-click the app → Open,"
echo "or run: xattr -dr com.apple.quarantine /Applications/FolderAnalyzer.app"
