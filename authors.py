"""Чтение «автора» файла из его свойств (как в Проводнике).

Логика как в диалоге «Свойства → Подробно»:
  1. System.Author («Авторы») — читается через Shell.Application (COM);
  2. если автор пуст — берётся «Владелец» (поле Owner), т.е. учётная запись,
     которой принадлежит/которой создан файл (например ``DOMAIN\\user``).

Владелец читается напрямую из дескриптора безопасности файла через Security API
(win32security) — это тот же источник, что и поле «Owner» в свойствах, надёжнее
и быстрее Shell-колонки и работает по UNC для SMB-хранилищ.

ВАЖНО: объект Shell.Application — STA COM, поэтому читать нужно в том же потоке,
где вызван CoInitialize. Класс рассчитан на использование как контекст-менеджер
внутри рабочего потока сканирования.
"""

from __future__ import annotations

import os
import sys

_WINDOWS = sys.platform == "win32"

_AVAILABLE = False
_HAS_SECURITY = False
_HAS_PWD = False

if _WINDOWS:
    try:
        import pythoncom
        import win32com.client

        _AVAILABLE = True
    except ImportError:  # pywin32 не установлен
        _AVAILABLE = False
    try:
        import win32security

        _HAS_SECURITY = True
    except ImportError:
        _HAS_SECURITY = False
else:
    try:
        import pwd  # владелец по uid на Unix (Linux/macOS)

        _HAS_PWD = True
    except ImportError:
        _HAS_PWD = False

_AUTHOR_HEADERS = {"authors", "author", "авторы", "автор"}
_OWNER_HEADERS = {"owner", "owners", "владелец", "владельцы"}


def is_available() -> bool:
    return _AVAILABLE or _HAS_PWD


class AuthorReader:
    """Читает автора файлов. Кэширует Shell-папки и индекс столбца «Авторы»."""

    def __init__(self) -> None:
        self.ok = False
        self._shell = None
        self._folders: dict[str, object] = {}
        self._author_col: int | None = None
        self._owner_col: int | None = None
        self._cols_done = False
        self._co_init = False
        self._sid_cache: dict[str, str] = {}  # кэш SID -> "DOMAIN\\user"
        self._uid_cache: dict[int, str] = {}  # кэш uid -> имя (Unix)

    def __enter__(self) -> "AuthorReader":
        if not _AVAILABLE:
            return self
        try:
            pythoncom.CoInitialize()
            self._co_init = True
            self._shell = win32com.client.Dispatch("Shell.Application")
            self.ok = True
        except Exception:  # noqa: BLE001
            self.ok = False
        return self

    def __exit__(self, *exc) -> None:
        self._folders.clear()
        self._shell = None
        if self._co_init:
            try:
                pythoncom.CoUninitialize()
            except Exception:  # noqa: BLE001
                pass
            self._co_init = False

    def _folder(self, directory: str):
        f = self._folders.get(directory)
        if f is None and directory not in self._folders:
            try:
                f = self._shell.NameSpace(directory)
            except Exception:  # noqa: BLE001
                f = None
            self._folders[directory] = f
            if f is not None and not self._cols_done:
                self._discover_columns(f)
        return f

    def _discover_columns(self, folder) -> None:
        self._cols_done = True
        for i in range(0, 320):
            try:
                name = folder.GetDetailsOf(None, i)
            except Exception:  # noqa: BLE001
                continue
            if not name:
                continue
            key = name.strip().lower()
            if self._author_col is None and key in _AUTHOR_HEADERS:
                self._author_col = i
            elif self._owner_col is None and key in _OWNER_HEADERS:
                self._owner_col = i

    def _detail(self, folder, item, col) -> str:
        if col is None:
            return ""
        try:
            value = folder.GetDetailsOf(item, col)
            return value.strip() if value else ""
        except Exception:  # noqa: BLE001
            return ""

    def _shell_details(self, directory: str, filename: str) -> tuple[str, str]:
        """(автор, владелец-из-Shell) через Shell.Application."""
        if not self.ok:
            return "", ""
        folder = self._folder(directory)
        if folder is None:
            return "", ""
        try:
            item = folder.ParseName(filename)
        except Exception:  # noqa: BLE001
            item = None
        if item is None:
            return "", ""
        return (self._detail(folder, item, self._author_col),
                self._detail(folder, item, self._owner_col))

    def _security_owner(self, path: str) -> str:
        """Владелец файла из дескриптора безопасности (как поле «Owner» свойств)."""
        if not _HAS_SECURITY:
            return ""
        try:
            sd = win32security.GetFileSecurity(
                path, win32security.OWNER_SECURITY_INFORMATION
            )
            sid = sd.GetSecurityDescriptorOwner()
        except Exception:  # noqa: BLE001 — нет доступа к дескриптору и т.п.
            return ""

        key = None
        try:
            key = win32security.ConvertSidToStringSid(sid)
            if key in self._sid_cache:
                return self._sid_cache[key]
        except Exception:  # noqa: BLE001
            pass

        owner = ""
        try:
            name, domain, _ = win32security.LookupAccountSid(None, sid)
            owner = f"{domain}\\{name}" if domain else name
        except Exception:  # noqa: BLE001 — SID не резолвится (чужой домен/NAS)
            owner = key or ""

        if key is not None:
            self._sid_cache[key] = owner
        return owner

    def _unix_owner(self, path: str) -> str:
        """Владелец файла на Unix (имя по uid)."""
        if not _HAS_PWD:
            return ""
        try:
            uid = os.stat(path).st_uid
        except OSError:
            return ""
        name = self._uid_cache.get(uid)
        if name is None:
            try:
                name = pwd.getpwuid(uid).pw_name
            except (KeyError, OSError):
                name = str(uid)
            self._uid_cache[uid] = name
        return name

    def author_of(self, directory: str, filename: str) -> str:
        """Автор файла; если автор не задан — владелец (Owner) из свойств файла.

        На Windows: System.Author, иначе владелец из дескриптора безопасности.
        На macOS/Linux: имя владельца файла (по uid)."""
        if not _WINDOWS:
            return self._unix_owner(os.path.join(directory, filename))
        author, shell_owner = self._shell_details(directory, filename)
        if author:
            return author
        owner = self._security_owner(os.path.join(directory, filename))
        return owner or shell_owner
