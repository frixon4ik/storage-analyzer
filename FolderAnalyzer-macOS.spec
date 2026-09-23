# -*- mode: python ; coding: utf-8 -*-
# Сборка macOS: .app-бандл (onedir — рекомендуемый для macOS режим PyInstaller).
# Запуск:  ./build_macos.sh   (или: pyinstaller --noconfirm FolderAnalyzer-macOS.spec)
import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

APP_NAME = "Анализатор хранилищ"
BUNDLE_ID = "com.folderanalyzer.app"
VERSION = "2.0"
# Архитектура: None — как у текущего Python (arm64 на Apple Silicon);
# "universal2" — только с universal-сборкой Python и зависимостей.
TARGET_ARCH = os.environ.get("TARGET_ARCH") or None

datas = [("app_icon.png", ".")]
datas += collect_data_files("botocore")
datas += collect_data_files("boto3")
hiddenimports = collect_submodules("botocore")

a = Analysis(
    ["app.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Windows-модули и ненужные части Qt/Python — не тянем в бандл
    excludes=[
        "win32com", "pythoncom", "pywintypes", "win32security",
        "tkinter", "unittest", "pydoc_data",
        "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtQml",
        "PySide6.QtQuick", "PySide6.Qt3DCore", "PySide6.QtMultimedia",
        "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtPdf",
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="FolderAnalyzer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    argv_emulation=False,
    target_arch=TARGET_ARCH,
    codesign_identity=os.environ.get("CODESIGN_IDENTITY") or None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="FolderAnalyzer",
)

app = BUNDLE(
    coll,
    name="FolderAnalyzer.app",
    icon="app_icon.icns",
    bundle_identifier=BUNDLE_ID,
    version=VERSION,
    info_plist={
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleShortVersionString": VERSION,
        "CFBundleVersion": VERSION,
        "CFBundleDevelopmentRegion": "ru",
        "CFBundleLocalizations": ["ru"],
        "LSMinimumSystemVersion": "12.0",
        "LSApplicationCategoryType": "public.app-category.utilities",
        "NSHighResolutionCapable": True,
        "NSRequiresAquaSystemAppearance": False,  # поддержка тёмной темы
        "NSHumanReadableCopyright": "Анализатор хранилищ: диски, SMB и S3",
        # тексты системных запросов доступа (TCC) при анализе защищённых папок
        "NSDesktopFolderUsageDescription":
            "Нужен доступ, чтобы проанализировать содержимое папки «Рабочий стол».",
        "NSDocumentsFolderUsageDescription":
            "Нужен доступ, чтобы проанализировать содержимое папки «Документы».",
        "NSDownloadsFolderUsageDescription":
            "Нужен доступ, чтобы проанализировать содержимое папки «Загрузки».",
        "NSRemovableVolumesUsageDescription":
            "Нужен доступ, чтобы проанализировать содержимое внешних дисков.",
        "NSNetworkVolumesUsageDescription":
            "Нужен доступ, чтобы проанализировать содержимое сетевых папок (SMB).",
    },
)
