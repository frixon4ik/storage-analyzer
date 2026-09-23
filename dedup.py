"""Поиск дубликатов файлов по выбранным полям сравнения.

Поля: имя, размер, автор, дата создания, хэш содержимого. Хэш считается лениво
и только внутри групп-кандидатов (совпавших по дешёвым полям), чтобы не читать
содержимое всех файлов. Не зависит от Qt.
"""

from __future__ import annotations

import hashlib
import os
from collections import defaultdict

# доступные поля сравнения: (ключ, подпись)
FIELDS = [
    ("name", "File name"),
    ("size", "Size"),
    ("author", "Author/owner"),
    ("created", "Creation date"),
    ("hash", "Content hash"),
]


def _field_value(e, field):
    if field == "name":
        return e.name.lower()
    if field == "size":
        return e.size
    if field == "author":
        return (e.author or "").lower()
    if field == "created":
        return round(e.created or 0)
    return None


def compute_hash(path: str, algo: str = "blake2b", chunk: int = 1 << 20) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def find_duplicates(entries, fields, cancel=None, on_progress=None):
    """Возвращает список групп дубликатов (каждая группа — список FileEntry, ≥2).

    fields — множество ключей из FIELDS. Если включён 'hash', содержимое читается
    только внутри групп, совпавших по остальным полям и размеру."""
    files = [e for e in entries if not e.is_dir]
    want_hash = "hash" in fields
    nonhash = [f for f in ("name", "size", "author", "created") if f in fields]

    # предварительная группировка по дешёвым полям
    groups: dict[tuple, list] = defaultdict(list)
    for e in files:
        key = tuple(_field_value(e, f) for f in nonhash)
        if want_hash:
            key = key + (e.size,)  # одинаковое содержимое => одинаковый размер
        groups[key].append(e)
    candidates = [g for g in groups.values() if len(g) >= 2]

    if not want_hash:
        result = candidates
    else:
        result = []
        total = sum(len(g) for g in candidates)
        done = 0
        for g in candidates:
            by_hash: dict[str, list] = defaultdict(list)
            for e in g:
                if cancel and cancel():
                    return _sort_groups(result)
                try:
                    hv = compute_hash(e.path)
                except OSError:
                    hv = None
                if hv is not None:
                    by_hash[hv].append(e)
                done += 1
                if on_progress and done % 20 == 0:
                    on_progress(done, total)
            for hg in by_hash.values():
                if len(hg) >= 2:
                    result.append(hg)
        if on_progress:
            on_progress(total, total)
    return _sort_groups(result)


def _kept_first(group):
    """«Оригинал», который оставляем — самый старый по дате изменения."""
    return min(group, key=lambda e: (e.modified or 0, e.path))


def duplicates_to_move(groups):
    """Плоский список файлов-дублей (все, кроме оставляемого в каждой группе)."""
    out = []
    for g in groups:
        keep = _kept_first(g)
        out.extend(e for e in g if e is not keep)
    return out


def wasted_bytes(groups) -> int:
    total = 0
    for g in groups:
        keep = _kept_first(g)
        total += sum(e.size for e in g if e is not keep)
    return total


def _sort_groups(groups):
    def w(g):
        keep = _kept_first(g)
        return sum(e.size for e in g if e is not keep)
    return sorted(groups, key=w, reverse=True)
