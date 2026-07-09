"""Настройки приложения (в т.ч. данные Telegram) — файл settings.json.

Хранится рядом с базой: %LOCALAPPDATA%\\FolderAnalyzer\\settings.json.
Токен бота хранится локально в открытом виде — это локальный файл пользователя.
"""

from __future__ import annotations

import json
import os
import sys


def app_data_dir() -> str:
    """Каталог данных приложения, зависящий от ОС (Windows/macOS/Linux)."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    folder = os.path.join(base, "FolderAnalyzer")
    os.makedirs(folder, exist_ok=True)
    return folder


def default_settings_path() -> str:
    return os.path.join(app_data_dir(), "settings.json")


def load_settings(path: str | None = None) -> dict:
    p = path or default_settings_path()
    if not os.path.exists(p):
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_settings(data: dict, path: str | None = None) -> None:
    p = path or default_settings_path()
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def get_db_path(path: str | None = None) -> str:
    """Путь к файлу базы из настроек (пусто — используется путь по умолчанию)."""
    return load_settings(path).get("db_path", "")


def set_db_path(db_path: str, path: str | None = None) -> None:
    s = load_settings(path)
    s["db_path"] = db_path or ""
    save_settings(s, path)


def get_s3(path: str | None = None) -> dict:
    """Сохранённый профиль подключения S3 (секрет хранится локально)."""
    return load_settings(path).get("s3", {})


def set_s3(data: dict, path: str | None = None) -> None:
    s = load_settings(path)
    s["s3"] = data
    save_settings(s, path)


def get_telegram(path: str | None = None) -> tuple[str, str]:
    s = load_settings(path)
    return s.get("telegram_token", ""), s.get("telegram_chat_id", "")


def set_telegram(token: str, chat_id: str, path: str | None = None) -> None:
    s = load_settings(path)
    s["telegram_token"] = (token or "").strip()
    s["telegram_chat_id"] = str(chat_id or "").strip()
    save_settings(s, path)
