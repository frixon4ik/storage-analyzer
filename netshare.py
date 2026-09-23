"""Подключение к сетевым SMB-ресурсам с учётными данными (Windows, macOS).

Windows: Win32 API WNetAddConnection2 через ctypes — устанавливает
аутентифицированную сессию к ресурсу `\\\\server\\share`, после чего обычный
доступ к файлам (os.scandir и т.п.) работает прозрачно. Пароль передаётся
в API напрямую и не попадает в командную строку или историю.

macOS: системный фреймворк NetFS (NetFSMountURLSync — тот же механизм, что
«Подключение к серверу» в Finder) монтирует ресурс в /Volumes/<share>. Пароль
передаётся в API напрямую (не в командную строку). С паролем — без системных
окон; без пароля macOS сама покажет окно входа (с сохранением в Связке ключей).

Пароль нигде не сохраняется на диск: он живёт только в памяти на время вызова.
"""

from __future__ import annotations

import ctypes
import os
import re
import string
import subprocess
import sys
from ctypes import wintypes
from urllib.parse import quote, unquote

_MACOS = sys.platform == "darwin"

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
    """Доступен ли механизм подключения (Windows с mpr.dll или macOS)."""
    return _AVAILABLE or _MACOS


def supports_drive_letters() -> bool:
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
    if not _AVAILABLE:
        return []
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


def connect(remote: str, username: str, password: str,
            drive_letter: str | None = None, persistent: bool = False):
    """Подключает SMB-ресурс. Возвращает (успех, сообщение, путь_для_сканирования)."""
    if _MACOS:
        return _mac_connect(remote, username, password)
    return _win_connect(remote, username, password, drive_letter, persistent)


def disconnect(target: str, force: bool = True) -> tuple[bool, str]:
    """Отключает ресурс: буква диска / UNC (Windows) или точка монтирования (macOS)."""
    if _MACOS:
        return _mac_disconnect(target, force)
    return _win_disconnect(target, force)


def connection_target(remote: str, drive_letter: str | None, scan_path: str | None) -> str:
    """Что отключать при выходе: буква диска, корень share или точка монтирования."""
    if _MACOS:
        return mount_point_for(remote) or (scan_path or "")
    return drive_letter if drive_letter else (share_root(remote) or remote)


def _win_connect(
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


def _win_disconnect(remote_or_drive: str, force: bool = True) -> tuple[bool, str]:
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


# ------------------------------------------------------------------- macOS
def parse_smb(path: str):
    """(server, share, subpath) из smb://[user@]srv/share/sub, //srv/share, \\\\srv\\share."""
    if not path:
        return None
    p = path.strip().strip('"')
    if p.lower().startswith("smb://"):
        p = p[6:]
    p = p.replace("\\", "/").lstrip("/")
    parts = [unquote(x) for x in p.split("/") if x]
    if len(parts) < 2:
        return None
    server = parts[0].rsplit("@", 1)[-1]  # логин в URL не нужен — он в отдельном поле
    return server, parts[1], "/".join(parts[2:])


def smb_mounts() -> list[tuple[str, str, str]]:
    """Смонтированные SMB-ресурсы: [(server, share, точка_монтирования)]."""
    try:
        out = subprocess.run(["mount"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    res = []
    for ln in out.splitlines():
        m = re.match(r"^//(?:[^@/]*@)?([^/]+)/(.+?) on (.+) \(smbfs", ln)
        if m:
            res.append((unquote(m.group(1)), unquote(m.group(2)), m.group(3)))
    return res


def mount_point_for(remote: str) -> str:
    info = parse_smb(remote)
    if not info:
        return ""
    server, share, _sub = info
    for srv, shr, mp in smb_mounts():
        if srv.lower() == server.lower() and shr.lower() == share.lower():
            return mp
    return ""


class _NetFS:
    """Минимальная обёртка CoreFoundation + NetFS через ctypes."""

    UTF8 = 0x08000100  # kCFStringEncodingUTF8

    def __init__(self) -> None:
        cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        nf = ctypes.CDLL("/System/Library/Frameworks/NetFS.framework/NetFS")
        vp = ctypes.c_void_p
        cf.CFStringCreateWithCString.argtypes = [vp, ctypes.c_char_p, ctypes.c_uint32]
        cf.CFStringCreateWithCString.restype = vp
        cf.CFURLCreateWithString.argtypes = [vp, vp, vp]
        cf.CFURLCreateWithString.restype = vp
        cf.CFDictionaryCreateMutable.argtypes = [vp, ctypes.c_long, vp, vp]
        cf.CFDictionaryCreateMutable.restype = vp
        cf.CFDictionarySetValue.argtypes = [vp, vp, vp]
        cf.CFArrayGetCount.argtypes = [vp]
        cf.CFArrayGetCount.restype = ctypes.c_long
        cf.CFArrayGetValueAtIndex.argtypes = [vp, ctypes.c_long]
        cf.CFArrayGetValueAtIndex.restype = vp
        cf.CFStringGetCString.argtypes = [vp, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32]
        cf.CFStringGetCString.restype = ctypes.c_bool
        cf.CFRelease.argtypes = [vp]
        nf.NetFSMountURLSync.argtypes = [vp, vp, vp, vp, vp, vp, ctypes.POINTER(vp)]
        nf.NetFSMountURLSync.restype = ctypes.c_int32
        self.cf, self.nf = cf, nf
        self.key_cb = ctypes.c_void_p.in_dll(cf, "kCFTypeDictionaryKeyCallBacks")
        self.val_cb = ctypes.c_void_p.in_dll(cf, "kCFTypeDictionaryValueCallBacks")

    def s(self, text: str):
        return self.cf.CFStringCreateWithCString(None, text.encode("utf-8"), self.UTF8)

    def to_py(self, ref) -> str:
        buf = ctypes.create_string_buffer(4096)
        if ref and self.cf.CFStringGetCString(ref, buf, len(buf), self.UTF8):
            return buf.value.decode("utf-8")
        return ""

    def mount(self, url: str, user: str, password: str, allow_ui: bool):
        cf = self.cf
        refs = []

        def keep(r):
            if r:
                refs.append(r)
            return r

        try:
            cfurl = keep(cf.CFURLCreateWithString(None, keep(self.s(url)), None))
            opts = keep(cf.CFDictionaryCreateMutable(
                None, 0, ctypes.addressof(self.key_cb), ctypes.addressof(self.val_cb)))
            # kNAUIOptionKey = "UIOption": NoUI / AllowUI
            cf.CFDictionarySetValue(opts, keep(self.s("UIOption")),
                                    keep(self.s("AllowUI" if allow_ui else "NoUI")))
            cf_user = keep(self.s(user)) if user else None
            cf_pass = keep(self.s(password)) if password else None
            points = ctypes.c_void_p()
            code = self.nf.NetFSMountURLSync(cfurl, None, cf_user, cf_pass, opts, None,
                                             ctypes.byref(points))
            mp = ""
            if points.value:
                refs.append(points.value)
                if cf.CFArrayGetCount(points.value) > 0:
                    mp = self.to_py(cf.CFArrayGetValueAtIndex(points.value, 0))
            return code, mp
        finally:
            for r in refs:
                cf.CFRelease(r)


_netfs = None


def _mac_connect(remote, username, password):
    global _netfs
    info = parse_smb(remote)
    if info is None:
        return False, ("Неверный сетевой путь. Используйте формат smb://server/share "
                       "или smb://server/share/папка."), None
    server, share, sub = info
    mp = mount_point_for(remote)  # уже подключено (например, через Finder)
    if not mp:
        try:
            if _netfs is None:
                _netfs = _NetFS()
            url = f"smb://{quote(server)}/{quote(share)}"
            # без пароля разрешаем системное окно входа (и Связку ключей)
            code, mp = _netfs.mount(url, username, password, allow_ui=not password)
        except (OSError, AttributeError, ValueError) as exc:
            return False, f"NetFS недоступен: {exc}", None
        if code == 17:  # EEXIST — уже смонтировано
            mp = mount_point_for(remote)
        elif code != 0:
            return False, _mac_error(code), None
        mp = mp or mount_point_for(remote)
        if not mp:
            return False, "Ресурс подключён, но точка монтирования не найдена.", None
    scan_path = os.path.join(mp, sub) if sub else mp
    return True, "Подключение установлено.", scan_path


_MAC_ERRORS = {
    -128: "Подключение отменено.",
    1: "Операция не разрешена.",
    2: "Сетевое имя (share) не найдено.",
    13: "Отказано в доступе.",
    60: "Сервер не ответил (тайм-аут).",
    61: "Сервер отклонил подключение (SMB не включён?).",
    64: "Сервер недоступен.",
    65: "Нет маршрута до сервера.",
    80: "Неверный логин или пароль.",
    -5045: "Сервер не найден или недоступен.",
    -6600: "Сервер не найден или недоступен.",
    -6602: "Неверный логин или пароль.",
    -6003: "Сетевое имя (share) не найдено.",
    -5999: "Подключение отменено.",
}


def _mac_error(code: int) -> str:
    hint = _MAC_ERRORS.get(code)
    if hint is None and code > 0:
        try:
            hint = os.strerror(code)
        except ValueError:
            hint = None
    return f"{hint or 'Не удалось подключиться.'} (код {code})"


def _mac_disconnect(mount_point: str, force: bool = True) -> tuple[bool, str]:
    if not mount_point or not mount_point.startswith("/Volumes/"):
        return False, "Недоступно."
    cmd = ["diskutil", "unmount"] + (["force"] if force else []) + [mount_point]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    return r.returncode == 0, (r.stdout or r.stderr).strip()
