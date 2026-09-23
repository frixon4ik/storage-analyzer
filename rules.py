"""Движок правил: условия отбора файлов + действие над совпавшими.

Условие (Condition) проверяется для каждого файла; несколько условий
объединяются по И. Действие сейчас одно — перенос в папку (безопасно, работает
по сети). Модуль не зависит от Qt, поэтому пригоден и для headless-запуска.
"""

from __future__ import annotations

import csv
import fnmatch
import json
import os
import re
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime

# Типы условий: (подпись, ключ)
CONDITION_TYPES = [
    ("Age", "age"),
    ("Size", "size"),
    ("Format", "ext"),
    ("Category", "category"),
    ("Name", "name"),
    ("Author / owner", "author"),
    ("Junk files", "junk"),
    ("Empty (0 bytes)", "empty"),
]

AGE_UNITS = {"days": 86400, "months": 86400 * 30, "years": 86400 * 365}
SIZE_UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}
AGE_DATE_FIELDS = [("by modification", "modified"), ("by creation", "created"), ("by access", "accessed")]

_JUNK_EXACT = {"thumbs.db", ".ds_store", "desktop.ini"}
_JUNK_GLOBS = ("~$*", "*.tmp", "*.temp", "*.bak", "*.~*")


@dataclass
class Condition:
    kind: str
    op: str = ""              # older/newer, gt/lt, contains/wildcard/regex
    number: float = 0.0
    unit: str = ""
    date_field: str = "modified"
    text: str = ""

    def describe(self) -> str:
        if self.kind == "age":
            field = dict((v, k) for k, v in AGE_DATE_FIELDS).get(self.date_field, self.date_field)
            word = "older than" if self.op == "older" else "newer than"
            return f"Age {word} {self.number:g} {self.unit} ({field})"
        if self.kind == "size":
            word = "larger than" if self.op == "gt" else "smaller than"
            return f"Size {word} {self.number:g} {self.unit}"
        if self.kind == "ext":
            return f"Format: {self.text}"
        if self.kind == "category":
            return f"Category: {self.text}"
        if self.kind == "name":
            word = {"contains": "contains", "wildcard": "wildcard", "regex": "regex"}.get(self.op, self.op)
            return f"Name {word}: {self.text}"
        if self.kind == "author":
            return f"Author/owner contains: {self.text}"
        if self.kind == "junk":
            return "Junk files (Thumbs.db, ~$*, *.tmp, …)"
        if self.kind == "empty":
            return "Empty files (0 bytes)"
        return self.kind


def _entry_date(e, field: str) -> float:
    return {"modified": e.modified, "created": e.created, "accessed": e.accessed}.get(field, e.modified)


def match_condition(e, c: Condition, now: float) -> bool:
    k = c.kind
    if k == "age":
        secs = c.number * AGE_UNITS.get(c.unit, 86400)
        cutoff = now - secs
        d = _entry_date(e, c.date_field)
        return d < cutoff if c.op == "older" else d > cutoff
    if k == "size":
        threshold = c.number * SIZE_UNITS.get(c.unit, 1)
        return e.size > threshold if c.op == "gt" else e.size < threshold
    if k == "ext":
        exts = {x.strip().lstrip(".").lower()
                for x in c.text.replace(";", ",").split(",") if x.strip()}
        return e.extension.lower() in exts
    if k == "category":
        return e.category == c.text
    if k == "name":
        name = e.name
        if c.op == "contains":
            return c.text.lower() in name.lower()
        if c.op == "wildcard":
            return fnmatch.fnmatch(name.lower(), c.text.lower())
        if c.op == "regex":
            try:
                return re.search(c.text, name, re.IGNORECASE) is not None
            except re.error:
                return False
        return False
    if k == "author":
        return c.text.lower() in (e.author or "").lower()
    if k == "junk":
        n = e.name.lower()
        return n in _JUNK_EXACT or any(fnmatch.fnmatch(n, g) for g in _JUNK_GLOBS)
    if k == "empty":
        return e.size == 0
    return False


def evaluate(entries, conditions: list[Condition], now: float, include_dirs: bool = False):
    """Возвращает список файлов, удовлетворяющих ВСЕМ условиям."""
    if not conditions:
        return []
    matched = []
    for e in entries:
        if e.is_dir and not include_dirs:
            continue
        if all(match_condition(e, c, now) for c in conditions):
            matched.append(e)
    return matched


def _unique_path(path: str) -> str:
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    i = 1
    while os.path.exists(f"{base} ({i}){ext}"):
        i += 1
    return f"{base} ({i}){ext}"


def execute_move(entries, root: str, target_dir: str):
    """Переносит файлы в target_dir, сохраняя относительную структуру папок.

    Возвращает (перемещено, освобождено_байт, [ошибки])."""
    moved = 0
    freed = 0
    errors: list[str] = []
    os.makedirs(target_dir, exist_ok=True)
    for e in entries:
        try:
            rel = os.path.relpath(e.path, root)
            if rel.startswith(".."):
                rel = e.name
        except ValueError:
            rel = e.name
        dest = _unique_path(os.path.join(target_dir, rel))
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.move(e.path, dest)
            moved += 1
            freed += e.size
        except OSError as exc:
            errors.append(f"{e.path}: {exc}")
    return moved, freed, errors


# Правила, сохранённые версиями с русским интерфейсом: единицы и категории
# хранились по-русски — переводим, чтобы «6 месяцев» не стали «6 днями».
_LEGACY_UNITS = {
    "дней": "days", "месяцев": "months", "лет": "years",
    "Б": "B", "КБ": "KB", "МБ": "MB", "ГБ": "GB", "ТБ": "TB",
}
_LEGACY_CATEGORIES = {
    "Изображения": "Images", "Видео": "Video", "Аудио": "Audio", "Документы": "Documents",
    "Архивы": "Archives", "Код": "Code", "Исполняемые": "Executables", "Шрифты": "Fonts",
    "Прочее": "Other", "Без расширения": "No extension", "Папка": "Folder",
}


def _upgrade_condition(c: Condition) -> Condition:
    c.unit = _LEGACY_UNITS.get(c.unit, c.unit)
    if c.kind == "category":
        c.text = _LEGACY_CATEGORIES.get(c.text, c.text)
    return c


# --------------------------------------------------------- сохранение правил
@dataclass
class Rule:
    """Сохраняемое правило: что отбирать в какой папке и что делать."""

    name: str
    root: str
    conditions: list = field(default_factory=list)   # list[Condition]
    target: str = ""
    action: str = "move"          # file: move(в папку); s3: move(под префикс)/delete
    recursive: bool = True
    include_dirs: bool = False
    read_authors: bool = False
    source: str = "file"          # "file" | "s3"
    s3: dict = field(default_factory=dict)  # профиль S3 для source=="s3"

    def to_dict(self) -> dict:
        return {
            "name": self.name, "root": self.root, "target": self.target,
            "action": self.action, "recursive": self.recursive,
            "include_dirs": self.include_dirs, "read_authors": self.read_authors,
            "source": self.source, "s3": self.s3,
            "conditions": [asdict(c) for c in self.conditions],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        conds = [_upgrade_condition(Condition(**c)) for c in d.get("conditions", [])]
        return cls(
            name=d["name"], root=d.get("root", ""), conditions=conds,
            target=d.get("target", ""), action=d.get("action", "move"),
            recursive=d.get("recursive", True),
            include_dirs=d.get("include_dirs", False),
            read_authors=d.get("read_authors", False),
            source=d.get("source", "file"), s3=d.get("s3", {}),
        )


def default_rules_path() -> str:
    import settings
    return os.path.join(settings.app_data_dir(), "rules.json")


def load_rules(path: str | None = None) -> dict[str, Rule]:
    p = path or default_rules_path()
    if not os.path.exists(p):
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {k: Rule.from_dict(v) for k, v in data.items()}
    except (OSError, ValueError, KeyError):
        return {}


def _write_rules(rules_map: dict[str, Rule], path: str | None = None) -> None:
    p = path or default_rules_path()
    with open(p, "w", encoding="utf-8") as f:
        json.dump({k: v.to_dict() for k, v in rules_map.items()}, f,
                  ensure_ascii=False, indent=2)


def save_rule(rule: Rule, path: str | None = None) -> None:
    rules_map = load_rules(path)
    rules_map[rule.name] = rule
    _write_rules(rules_map, path)


def get_rule(name: str, path: str | None = None) -> Rule | None:
    return load_rules(path).get(name)


def delete_rule(name: str, path: str | None = None) -> None:
    rules_map = load_rules(path)
    if name in rules_map:
        del rules_map[name]
        _write_rules(rules_map, path)


def apply_rule(rule: Rule, now: float, on_log=None) -> dict:
    """Headless-применение правила: отбор по условиям → действие.

    Поддерживает файловый источник (перенос в папку) и S3 (удаление/перенос
    под префикс)."""
    log = on_log or (lambda _m: None)
    result = {"matched": 0, "moved": 0, "freed": 0, "errors": []}

    if rule.source == "s3":
        import s3client
        cfg = s3client.S3Config(**rule.s3)
        try:
            entries = s3client.list_entries(cfg)
        except Exception as exc:  # noqa: BLE001
            log(f"S3 error: {s3client.err_text(exc)}")
            result["errors"].append(s3client.err_text(exc))
            return result
        matched = evaluate(entries, rule.conditions, now, include_dirs=False)
        result["matched"] = len(matched)
        log(f"Matched objects: {len(matched)}")
        keys = [s3client.key_from_path(e.path, cfg.bucket) for e in matched]
        if not keys:
            return result
        if rule.action == "move":
            if not rule.target:
                log("No target prefix — action skipped.")
                return result
            moved, _f, errors = s3client.move_to_prefix(cfg, keys, rule.target)
            result.update(moved=moved, errors=errors)
            log(f"Moved: {moved}, errors: {len(errors)}")
        else:  # delete
            deleted, errors = s3client.delete_keys(cfg, keys)
            result.update(moved=deleted, errors=errors)
            log(f"Deleted: {deleted}, errors: {len(errors)}")
        return result

    from scanner import run_scan  # импорт здесь — модуль rules не тянет Qt без нужды

    results, _info = run_scan(
        rule.root, recursive=rule.recursive, include_dirs=rule.include_dirs,
        read_authors=rule.read_authors, db_path=None, incremental=False,
    )
    matched = evaluate(results, rule.conditions, now, include_dirs=False)
    result["matched"] = len(matched)
    log(f"Matched files: {len(matched)}")

    if rule.action == "move":
        if not rule.target:
            log("No destination folder — action skipped.")
            return result
        moved, freed, errors = execute_move(matched, rule.root, rule.target)
        result.update(moved=moved, freed=freed, errors=errors)
        log(f"Moved: {moved}, freed: {freed} bytes, errors: {len(errors)}")
    return result


def export_csv(entries, path: str) -> None:
    def dt(ts):
        if not ts or ts <= 0:
            return ""
        try:
            return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, ValueError):
            return ""

    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["Name", "Type", "Format", "Category", "Author",
                    "Size (bytes)", "Created", "Modified", "Path"])
        for e in entries:
            w.writerow([e.name, e.kind, e.extension, e.category, e.author,
                        e.size, dt(e.created), dt(e.modified), e.path])
