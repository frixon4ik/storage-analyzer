"""Локальная база данных результатов анализа (SQLite).

Хранит снимок содержимого каждой проанализированной папки. Позволяет при
повторном анализе делать инкрементное обновление: неизменённые файлы (по
размеру и дате изменения) берутся из базы, а дорогие операции (например чтение
автора/владельца) для них не повторяются.

Схема компактная: хранится только то, что нельзя вывести из пути. Имя, родитель,
формат и категория восстанавливаются при загрузке из path; автор вынесен в
справочник (одна строка на уникального владельца). Это даёт примерно 3× меньший
размер по сравнению с «плоским» хранением всех полей.

База — один файл, по умолчанию в %LOCALAPPDATA%\\FolderAnalyzer\\analyzer.db.
Каждый экземпляр FileDatabase открывает собственное соединение.
"""

from __future__ import annotations

import os
import sqlite3

from scanner import FileEntry, category_for, _ext_of

_SCHEMA_VERSION = 2


def default_db_path() -> str:
    import settings
    return os.path.join(settings.app_data_dir(), "analyzer.db")


def norm_root(root: str) -> str:
    """Нормализованный ключ папки (для совпадения путей независимо от регистра)."""
    return os.path.normpath(root).rstrip("\\/").lower()


def db_size_bytes(path: str) -> int:
    """Суммарный размер файла базы вместе с WAL/SHM."""
    total = 0
    for suffix in ("", "-wal", "-shm"):
        p = path + suffix
        if os.path.exists(p):
            total += os.path.getsize(p)
    return total


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    root       TEXT PRIMARY KEY,
    root_orig  TEXT,
    last_scan  REAL,
    item_count INTEGER
);
CREATE TABLE IF NOT EXISTS authors (
    id   INTEGER PRIMARY KEY,
    name TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS files (
    root      TEXT,
    path      TEXT,
    is_dir    INTEGER,
    size      INTEGER,
    created   REAL,
    modified  REAL,
    accessed  REAL,
    author_id INTEGER,
    PRIMARY KEY (root, path)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_files_root ON files(root);
"""


class FileDatabase:
    def __init__(self, db_path: str | None = None) -> None:
        self.path = db_path or default_db_path()
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        ver = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if ver and ver != _SCHEMA_VERSION:
            # схема изменилась — база это кэш, пересоздаём (снимки восстановятся сканом)
            self.conn.executescript(
                "DROP TABLE IF EXISTS files; DROP TABLE IF EXISTS authors; "
                "DROP TABLE IF EXISTS scans;"
            )
        self.conn.executescript(_SCHEMA)
        self.conn.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
        self.conn.commit()

    # ----------------------------------------------------------------- чтение
    def load_entries(self, root: str) -> dict[str, FileEntry]:
        """Снимок предыдущего анализа: {абсолютный_путь: FileEntry}.

        Имя/родитель/формат/категория восстанавливаются из path."""
        key = norm_root(root)
        cur = self.conn.execute(
            "SELECT f.path, f.is_dir, f.size, f.created, f.modified, f.accessed, a.name "
            "FROM files f LEFT JOIN authors a ON a.id = f.author_id WHERE f.root=?",
            (key,),
        )
        result: dict[str, FileEntry] = {}
        for path, is_dir, size, created, modified, accessed, author in cur:
            is_dir = bool(is_dir)
            name = os.path.basename(path.rstrip("\\/")) or path
            parent = os.path.dirname(path.rstrip("\\/"))
            ext = "" if is_dir else _ext_of(name)
            result[path] = FileEntry(
                name=name, path=path, parent=parent, is_dir=is_dir,
                extension=ext, category=("Folder" if is_dir else category_for(ext)),
                size=size, created=created, modified=modified, accessed=accessed,
                author=author or "",
            )
        return result

    def get_scan_info(self, root: str):
        cur = self.conn.execute(
            "SELECT root_orig, last_scan, item_count FROM scans WHERE root=?",
            (norm_root(root),),
        )
        return cur.fetchone()

    def list_scans(self) -> list[tuple[str, float, int]]:
        cur = self.conn.execute(
            "SELECT root_orig, last_scan, item_count FROM scans ORDER BY last_scan DESC"
        )
        return cur.fetchall()

    # ----------------------------------------------------------------- запись
    def _author_ids(self, entries) -> dict[str, int]:
        names = {e.author for e in entries if e.author}
        if names:
            self.conn.executemany(
                "INSERT OR IGNORE INTO authors(name) VALUES(?)", [(n,) for n in names]
            )
        rows = self.conn.execute("SELECT id, name FROM authors").fetchall()
        return {name: aid for aid, name in rows}

    def save_scan(self, root: str, entries: list[FileEntry], scan_time: float) -> None:
        """Полностью заменяет снимок папки текущим набором."""
        key = norm_root(root)
        with self.conn:  # транзакция
            amap = self._author_ids(entries)
            rows = [
                (key, e.path, int(e.is_dir), e.size, e.created, e.modified,
                 e.accessed, amap.get(e.author) if e.author else None)
                for e in entries
            ]
            self.conn.execute("DELETE FROM files WHERE root=?", (key,))
            self.conn.executemany(
                "INSERT OR REPLACE INTO files "
                "(root, path, is_dir, size, created, modified, accessed, author_id) "
                "VALUES (?,?,?,?,?,?,?,?)",
                rows,
            )
            self.conn.execute(
                "INSERT INTO scans (root, root_orig, last_scan, item_count) "
                "VALUES (?,?,?,?) "
                "ON CONFLICT(root) DO UPDATE SET "
                "root_orig=excluded.root_orig, last_scan=excluded.last_scan, "
                "item_count=excluded.item_count",
                (key, os.path.normpath(root), scan_time, len(entries)),
            )

    def delete_scan(self, root: str) -> None:
        key = norm_root(root)
        with self.conn:
            self.conn.execute("DELETE FROM files WHERE root=?", (key,))
            self.conn.execute("DELETE FROM scans WHERE root=?", (key,))

    def vacuum(self) -> None:
        """Сжать базу: вернуть свободные страницы в ОС и подчистить справочник."""
        # удаляем авторов, на которых больше нет ссылок
        self.conn.execute(
            "DELETE FROM authors WHERE id NOT IN (SELECT DISTINCT author_id FROM files "
            "WHERE author_id IS NOT NULL)"
        )
        self.conn.commit()
        # в режиме WAL VACUUM пишет в WAL и файл не усекается; на время VACUUM
        # переключаемся на DELETE-журнал, чтобы основной файл реально сжался
        self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.conn.execute("PRAGMA journal_mode=DELETE")
        self.conn.execute("VACUUM")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.commit()

    def size_bytes(self) -> int:
        return db_size_bytes(self.path)

    def close(self) -> None:
        try:
            # сливаем и усекаем WAL, чтобы файл не оставался раздутым
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:  # noqa: BLE001
            pass
        try:
            self.conn.close()
        except Exception:  # noqa: BLE001
            pass
