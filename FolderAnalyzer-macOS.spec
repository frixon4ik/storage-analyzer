# -*- mode: python ; coding: utf-8 -*-
# macOS build: .app bundle (onedir, the mode PyInstaller recommends for macOS).
# Run:  ./build_macos.sh   (or: pyinstaller --noconfirm FolderAnalyzer-macOS.spec)
import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

APP_NAME = "Storage Analyzer"
BUNDLE_ID = "com.folderanalyzer.app"
VERSION = "2.1.1"
# Architecture: None — same as the current Python (arm64 on Apple Silicon);
# "universal2" — only with a universal Python build and universal dependencies.
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
    # Windows-only modules and unused parts of Qt/Python stay out of the bundle
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
        "CFBundleDevelopmentRegion": "en",
        "CFBundleLocalizations": ["en"],
        "LSMinimumSystemVersion": "12.0",
        "LSApplicationCategoryType": "public.app-category.utilities",
        "NSHighResolutionCapable": True,
        "NSRequiresAquaSystemAppearance": False,  # dark mode support
        "NSHumanReadableCopyright": "Storage Analyzer: local disks, SMB shares and S3",
        # texts of the system (TCC) access prompts shown when analyzing protected folders
        "NSDesktopFolderUsageDescription":
            "Access is needed to analyze the contents of your Desktop folder.",
        "NSDocumentsFolderUsageDescription":
            "Access is needed to analyze the contents of your Documents folder.",
        "NSDownloadsFolderUsageDescription":
            "Access is needed to analyze the contents of your Downloads folder.",
        "NSRemovableVolumesUsageDescription":
            "Access is needed to analyze the contents of external drives.",
        "NSNetworkVolumesUsageDescription":
            "Access is needed to analyze the contents of network shares (SMB).",
    },
)
