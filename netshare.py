"""Подключение к сетевым SMB-ресурсам с учётными данными (Windows).

Использует Win32 API WNetAddConnection2 через ctypes — это устанавливает
аутентифицированную сессию к ресурсу `\\\\server\\share`, после чего обычный
доступ к файлам (os.scandir и т.п.) работает прозрачно. Пароль передаётся
в API напрямую и не попадает в командную строку или историю.

Пароль нигде не сохраняется на диск: он живёт только в памяти на время вызова.
"""

from __future__ import annotations

import ctypes
import os
import string
from ctypes import wintypes

try:
    _mpr = ctypes.WinDLL("mpr", use_last_error=True)
    _AVAILABLE = True
except (OSError, AttributeError):  # не Windows / нет mpr.dll
    _mpr = None
    _AVAILABLE = False

RESOURCETYPE_DISK = 0x00000001
CONNECT_UPDATE_PROFILE = 0x00000001  # «запомнить» подключение между сессиями ОС

# Понятные пояснения к частым кодам ошибок WNet.
_ERROR_HINTS = {
    5: "Отказано в доступе.",
    53: "Сетевой путь не найден. Проверьте имя сервера и доступность хранилища.",
    66: "Тип сетевого ресурса не поддерживается.",
    67: "Сетевое имя (share) не найдено. Проверьте имя общей папки.",
    86: "Неверный пароль.",
    1219: "Уже есть подключение к этому серверу под другими учётными данными.",
    1326: "Неверный логин или пароль.",
    2202: "Указано неверное имя пользователя.",
}


class NETRESOURCE(ctypes.Structure):
    _fields_ = [
        ("dwScope", wintypes.DWORD),
        ("dwType", wintypes.DWORD),
        ("dwDisplayType", wintypes.DWORD),
        ("dwUsage", wintypes.DWORD),
        ("lpLocalName", wintypes.LPWSTR),
        ("lpRemoteName", wintypes.LPWSTR),
        ("lpComment", wintypes.LPWSTR),
        ("lpProvider", wintypes.LPWSTR),
    ]


if _AVAILABLE:
    _add = _mpr.WNetAddConnection2W
    _add.argtypes = [ctypes.POINTER(NETRESOURCE), wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    _add.restype = wintypes.DWORD

    _cancel = _mpr.WNetCancelConnection2W
    _cancel.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.BOOL]
    _cancel.restype = wintypes.DWORD


def is_available() -> bool:
    """Доступен ли механизм подключения (т.е. это Windows с mpr.dll)."""
    return _AVAILABLE


def share_root(path: str) -> str | None:
    """Извлекает корень ресурса `\\\\server\\share` из UNC-пути.

    Подключаться нужно именно к корню общей папки, а не к вложенной подпапке.
    Возвращает None, если путь не UNC.
    """
    if not path:
        return None
    p = path.replace("/", "\\").strip()
    if not p.startswith("\\\\"):
        return None
    parts = [x for x in p[2:].split("\\") if x]
    if len(parts) >= 2:
        return "\\\\" + parts[0] + "\\" + parts[1]
    if len(parts) == 1:
        return "\\\\" + parts[0]
    return None


def free_drive_letters() -> list[str]:
    """Список свободных букв дисков (от Z к D) для возможного подключения."""
    used = set()
    bitmask = ctypes.windll.kernel32.GetLogicalDrives() if _AVAILABLE else 0
    for i, letter in enumerate(string.ascii_uppercase):
        if bitmask & (1 << i):
            used.add(letter)
    return [f"{c}:" for c in reversed(string.ascii_uppercase[3:]) if c not in used]


def _describe(code: int) -> str:
    hint = _ERROR_HINTS.get(code)
    try:
        sys_msg = ctypes.FormatError(code).strip()
    except Exception:  # noqa: BLE001
        sys_msg = ""
    if hint and sys_msg:
        return f"{hint} (код {code}: {sys_msg})"
    if hint:
        return f"{hint} (код {code})"
    return f"Ошибка подключения, код {code}: {sys_msg}" if sys_msg else f"Ошибка подключения, код {code}"


def connect(
    remote: str,
    username: str,
    password: str,
    drive_letter: str | None = None,
    persistent: bool = False,
) -> tuple[bool, str, str | None]:
    """Подключает SMB-ресурс с учётными данными.

    remote        — UNC-путь к ресурсу или вложенной папке (берётся корень share).
    drive_letter  — например "Z:" чтобы подключить как диск, иначе None.
    persistent    — запомнить подключение между перезагрузками ОС.

    Возвращает (успех, сообщение, путь_для_сканирования).
    Путь для сканирования = буква диска (если задана) либо исходный UNC-путь.
    """
    if not _AVAILABLE:
        return False, "Подключение по SMB доступно только на Windows.", None

    root = share_root(remote)
    if root is None:
        return False, (
            "Неверный сетевой путь. Используйте формат \\\\server\\share или "
            "\\\\server\\share\\папка."
        ), None

    local = drive_letter.rstrip("\\") if drive_letter else None

    nr = NETRESOURCE()
    nr.dwType = RESOURCETYPE_DISK
    nr.lpLocalName = local
    nr.lpRemoteName = root
    nr.lpProvider = None
    flags = CONNECT_UPDATE_PROFILE if persistent else 0

    code = _add(ctypes.byref(nr), password or None, username or None, flags)

    # Конфликт с уже существующей сессией под другими кредами — снимаем и пробуем ещё раз.
    if code == 1219:
        _cancel(root, 0, True)
        code = _add(ctypes.byref(nr), password or None, username or None, flags)

    if code != 0:
        return False, _describe(code), None

    # Путь, который дальше передадим в сканер.
    if local:
        scan_path = local + "\\"
    else:
        # сохраняем исходный путь пользователя (может указывать на подпапку)
        scan_path = remote.replace("/", "\\")
    return True, "Подключение установлено.", scan_path


def disconnect(remote_or_drive: str, force: bool = True) -> tuple[bool, str]:
    """Отключает ранее подключённый ресурс (по UNC-корню или букве диска)."""
    if not _AVAILABLE:
        return False, "Недоступно."
    target = remote_or_drive
    if not target.endswith(":") and target.startswith("\\\\"):
        target = share_root(target) or target
    code = _cancel(target, 0, force)
    if code == 0:
        return True, "Отключено."
    return False, _describe(code)
