"""Модели для результатов сканирования: плоская таблица и дерево по папкам,
плюс прокси-модели с фильтрами по всем параметрам.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime

import sys

from PySide6.QtCore import (
    QAbstractItemModel,
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
)
from PySide6.QtGui import QStandardItem, QStandardItemModel

from scanner import FileEntry

# глубокая вложенность папок -> рекурсия по дереву; поднимем лимит на всякий случай
sys.setrecursionlimit(max(sys.getrecursionlimit(), 20000))

# Роль для хранения объекта FileEntry в элементах дерева.
ENTRY_ROLE = Qt.UserRole + 1

# Иконки файлов как в Finder/Проводнике: запрашиваются у ОС один раз на
# расширение (а не на каждый файл) — дёшево даже для 100k+ строк.
_icon_provider = None
_icon_cache: dict = {}


def entry_icon(entry):
    global _icon_provider
    from PySide6.QtCore import QFileInfo
    from PySide6.QtWidgets import QFileIconProvider
    if _icon_provider is None:
        _icon_provider = QFileIconProvider()
        # не лезть в сетевые/медленные тома за иконками конкретных файлов
        _icon_provider.setOptions(QFileIconProvider.DontUseCustomDirectoryIcons)
    if entry.is_dir:
        key = "/dir"
        if key not in _icon_cache:
            _icon_cache[key] = _icon_provider.icon(QFileIconProvider.Folder)
        return _icon_cache[key]
    key = entry.extension
    icon = _icon_cache.get(key)
    if icon is None:
        info = QFileInfo(entry.path)
        icon = _icon_provider.icon(info) if key and info.exists() else None
        if icon is None or icon.isNull():
            icon = _icon_provider.icon(QFileIconProvider.File)
        _icon_cache[key] = icon
    return icon


def human_size(num: int) -> str:
    """Размер в байтах -> читаемый вид (КБ, МБ, ...)."""
    if num <= 0:
        return "—" if num == 0 else str(num)
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(num)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{num} B"


def fmt_dt(ts: float) -> str:
    if not ts or ts <= 0:
        return ""
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


# (заголовок, ключ-атрибут, выравнивание-справа?)
COLUMNS = [
    ("Name", "name", False),
    ("Type", "kind", False),
    ("Format", "extension", False),
    ("Category", "category", False),
    ("Author", "author", False),
    ("Size", "size", True),
    ("Created", "created", False),
    ("Modified", "modified", False),
    ("Path", "parent", False),
]

(COL_NAME, COL_KIND, COL_EXT, COL_CAT, COL_AUTHOR,
 COL_SIZE, COL_CREATED, COL_MODIFIED, COL_PATH) = range(9)

COLUMN_COUNT = len(COLUMNS)


def cell_display(entry: FileEntry, col: int) -> str:
    """Текст ячейки для заданного столбца (общий для таблицы и дерева)."""
    if col == COL_NAME:
        return entry.name
    if col == COL_KIND:
        return entry.kind
    if col == COL_EXT:
        return entry.extension.upper() if entry.extension else ("" if entry.is_dir else "—")
    if col == COL_CAT:
        return entry.category
    if col == COL_AUTHOR:
        return entry.author or ""
    if col == COL_SIZE:
        return "" if entry.is_dir else human_size(entry.size)
    if col == COL_CREATED:
        return fmt_dt(entry.created)
    if col == COL_MODIFIED:
        return fmt_dt(entry.modified)
    if col == COL_PATH:
        return entry.parent
    return ""


def cell_sort_value(entry: FileEntry, col: int):
    """Значение для корректной сортировки (числа/даты — как числа)."""
    if col == COL_SIZE:
        return entry.size
    if col == COL_CREATED:
        return entry.created
    if col == COL_MODIFIED:
        return entry.modified
    return cell_display(entry, col).lower()


# --------------------------------------------------------------------- фильтры
@dataclass
class FilterCriteria:
    """Набор условий фильтрации вывода."""

    name_text: str = ""
    extensions: set[str] = field(default_factory=set)
    category: str = "All"
    kind: str = "All"                         # "Все" / "Файл" / "Папка"
    author_text: str = ""
    min_size: int | None = None
    max_size: int | None = None
    modified_from: float | None = None
    modified_to: float | None = None

    def is_empty(self) -> bool:
        return (
            not self.name_text
            and not self.extensions
            and self.category == "All"
            and self.kind == "All"
            and not self.author_text
            and self.min_size is None
            and self.max_size is None
            and self.modified_from is None
            and self.modified_to is None
        )


def entry_matches(entry: FileEntry, c: FilterCriteria) -> bool:
    """Проверяет, проходит ли элемент через фильтр (общая логика)."""
    if c.is_empty():
        return True

    if c.kind != "All" and entry.kind != c.kind:
        return False
    if c.name_text and c.name_text.lower() not in entry.name.lower():
        return False
    if c.extensions and entry.extension.lower() not in c.extensions:
        return False
    if c.category != "All" and entry.category != c.category:
        return False
    if c.author_text and c.author_text.lower() not in (entry.author or "").lower():
        return False

    # Размер применяем только к файлам; если фильтр по размеру задан — папки прячем.
    if not entry.is_dir:
        if c.min_size is not None and entry.size < c.min_size:
            return False
        if c.max_size is not None and entry.size > c.max_size:
            return False
    elif c.min_size is not None or c.max_size is not None:
        return False

    if c.modified_from is not None and entry.modified < c.modified_from:
        return False
    if c.modified_to is not None and entry.modified > c.modified_to:
        return False
    return True


# ---------------------------------------------------------------- плоская модель
class FileTableModel(QAbstractTableModel):
    """Хранит плоский список FileEntry и отдаёт его таблице."""

    def __init__(self) -> None:
        super().__init__()
        self._rows: list[FileEntry] = []

    def set_entries(self, entries: list[FileEntry]) -> None:
        self.beginResetModel()
        self._rows = entries
        self.endResetModel()

    def entry_at(self, source_row: int) -> FileEntry:
        return self._rows[source_row]

    def all_entries(self) -> list[FileEntry]:
        return self._rows

    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return COLUMN_COUNT

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLUMNS[section][0]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        entry = self._rows[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            return cell_display(entry, col)
        if role == Qt.UserRole:
            return cell_sort_value(entry, col)
        if role == Qt.TextAlignmentRole:
            align = Qt.AlignRight if COLUMNS[col][2] else Qt.AlignLeft
            return int(align | Qt.AlignVCenter)
        if role == Qt.ToolTipRole:
            return entry.path
        return None


class FileFilterProxy(QSortFilterProxyModel):
    """Прокси для плоской таблицы: фильтрация по всем параметрам + сортировка."""

    def __init__(self) -> None:
        super().__init__()
        self.criteria = FilterCriteria()
        self.setSortRole(Qt.UserRole)

    def set_criteria(self, criteria: FilterCriteria) -> None:
        self.criteria = criteria
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):  # noqa: N802
        entry: FileEntry = self.sourceModel().entry_at(source_row)
        return entry_matches(entry, self.criteria)


class FileListModel(QAbstractTableModel):
    """Быстрая модель плоского списка: хранит полный список и видимый (отфильтр.
    + отсортированный) подсписок. Фильтрация и сортировка делаются прямо над
    Python-списком — на порядки быстрее QSortFilterProxyModel на больших объёмах.
    """

    def __init__(self) -> None:
        super().__init__()
        self._all: list[FileEntry] = []
        self._visible: list[FileEntry] = []
        self.criteria = FilterCriteria()
        self._sort_col = -1
        self._sort_desc = False

    # --- наполнение/доступ
    def set_entries(self, entries: list[FileEntry]) -> None:
        self.beginResetModel()
        self._all = entries
        self._rebuild()
        self.endResetModel()

    def all_entries(self) -> list[FileEntry]:
        return self._all

    def all_count(self) -> int:
        return len(self._all)

    def entry_at_row(self, row: int):
        return self._visible[row] if 0 <= row < len(self._visible) else None

    def visible_entries(self) -> list[FileEntry]:
        return self._visible

    def set_criteria(self, criteria: FilterCriteria) -> None:
        self.beginResetModel()
        self.criteria = criteria
        self._rebuild()
        self.endResetModel()

    def _rebuild(self) -> None:
        if self.criteria.is_empty():
            vis = list(self._all)
        else:
            c = self.criteria
            vis = [e for e in self._all if entry_matches(e, c)]
        if self._sort_col >= 0:
            col = self._sort_col
            vis.sort(key=lambda e: cell_sort_value(e, col), reverse=self._sort_desc)
        self._visible = vis

    # --- интерфейс модели
    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._visible)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return COLUMN_COUNT

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLUMNS[section][0]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        entry = self._visible[index.row()]
        col = index.column()
        if role == Qt.DisplayRole:
            return cell_display(entry, col)
        if role == Qt.DecorationRole and col == COL_NAME:
            return entry_icon(entry)
        if role == Qt.TextAlignmentRole:
            align = Qt.AlignRight if COLUMNS[col][2] else Qt.AlignLeft
            return int(align | Qt.AlignVCenter)
        if role == Qt.ToolTipRole:
            return entry.path
        return None

    def sort(self, column, order=Qt.AscendingOrder):  # noqa: N802
        self.layoutAboutToBeChanged.emit()
        self._sort_col = column
        self._sort_desc = order == Qt.DescendingOrder
        self._visible.sort(key=lambda e: cell_sort_value(e, column), reverse=self._sort_desc)
        self.layoutChanged.emit()


# --------------------------------------------------------------- модель-дерево
def _make_dir_entry(path: str, existing: FileEntry | None) -> FileEntry:
    """FileEntry для узла-папки (реальный или синтетический промежуточный)."""
    if existing is not None:
        return existing
    return FileEntry(
        name=os.path.basename(path.rstrip("\\/")) or path,
        path=path,
        parent=os.path.dirname(path.rstrip("\\/")),
        is_dir=True,
        extension="",
        category="Folder",
        size=0,
        created=0.0,
        modified=0.0,
        accessed=0.0,
        author="",
    )


def _make_row(entry: FileEntry, name_override: str | None = None) -> list[QStandardItem]:
    """Создаёт строку (список QStandardItem по столбцам) для дерева."""
    items: list[QStandardItem] = []
    for col in range(COLUMN_COUNT):
        text = name_override if (col == COL_NAME and name_override) else cell_display(entry, col)
        item = QStandardItem(text)
        item.setEditable(False)
        item.setData(cell_sort_value(entry, col), Qt.UserRole)
        if COLUMNS[col][2]:
            item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        if col == COL_NAME:
            item.setData(entry, ENTRY_ROLE)
            item.setToolTip(entry.path)
        items.append(item)
    return items


class TreeModelBuilder:
    """Пошаговое построение дерева по папкам — чтобы показывать прогресс.

    Вызывайте step(batch) пока not done(); готовая модель — в self.model.
    Возвращаемое step() — число обработанных элементов (для прогресс-бара).
    """

    def __init__(self, root: str, entries: list[FileEntry]) -> None:
        self.entries = entries
        self.total = len(entries)
        self._i = 0
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels([c[0] for c in COLUMNS])
        self._node_map: dict[str, QStandardItem] = {}

        if not root:
            self.root_norm = ""
            self.root_key = ""
            self._dir_entry_map = {}
            self._i = self.total  # нечего строить
            return

        self.root_norm = os.path.normpath(root)
        self.root_key = self.root_norm.lower()
        self._dir_entry_map = {
            os.path.normpath(e.path).lower(): e for e in entries if e.is_dir
        }
        self._get_dir_node(self.root_norm)  # корневой узел

    def _get_dir_node(self, path: str) -> QStandardItem:
        norm = os.path.normpath(path)
        key = norm.lower()
        node = self._node_map.get(key)
        if node is not None:
            return node

        existing = self._dir_entry_map.get(key)
        if key == self.root_key:
            entry = _make_dir_entry(self.root_norm, existing)
            row = _make_row(entry, name_override=self.root_norm)  # у корня — полный путь
            self.model.invisibleRootItem().appendRow(row)
        else:
            parent_path = os.path.dirname(norm)
            if len(norm) <= len(self.root_norm) or not key.startswith(self.root_key):
                parent_item = self._get_dir_node(self.root_norm)
            else:
                parent_item = self._get_dir_node(parent_path)
            entry = _make_dir_entry(norm, existing)
            row = _make_row(entry)
            parent_item.appendRow(row)
        self._node_map[key] = row[0]
        return row[0]

    def step(self, batch: int = 800) -> int:
        end = min(self._i + batch, self.total)
        for i in range(self._i, end):
            e = self.entries[i]
            if e.is_dir:
                self._get_dir_node(e.path)
            else:
                self._get_dir_node(e.parent).appendRow(_make_row(e))
        self._i = end
        return self._i

    def done(self) -> bool:
        return self._i >= self.total


def build_tree_model(root: str, entries: list[FileEntry]) -> QStandardItemModel:
    """Строит иерархическую модель за один проход (для не-интерактивных вызовов)."""
    builder = TreeModelBuilder(root, entries)
    while not builder.done():
        builder.step(1_000_000)
    return builder.model


class TreeFilterProxy(QSortFilterProxyModel):
    """Прокси для дерева: фильтрует по тем же критериям; родители видны,
    если совпадает любой потомок (рекурсивная фильтрация)."""

    def __init__(self) -> None:
        super().__init__()
        self.criteria = FilterCriteria()
        self.setSortRole(Qt.UserRole)
        self.setRecursiveFilteringEnabled(True)

    def set_criteria(self, criteria: FilterCriteria) -> None:
        self.criteria = criteria
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):  # noqa: N802
        if self.criteria.is_empty():
            return True
        idx = self.sourceModel().index(source_row, COL_NAME, source_parent)
        entry = self.sourceModel().data(idx, ENTRY_ROLE)
        if entry is None:
            return True
        return entry_matches(entry, self.criteria)


# ----------------------------- быстрое дерево на лёгких узлах (без QStandardItem)
class _Node:
    __slots__ = ("entry", "children", "parent", "vchildren", "vrow", "name_override")

    def __init__(self, entry, parent, name_override=None):
        self.entry = entry
        self.parent = parent
        self.children: list = []
        self.vchildren: list = []   # видимые (после фильтра/сортировки)
        self.vrow = 0
        self.name_override = name_override


class NodeTreeBuilder:
    """Пошаговое построение дерева узлов (для прогресса). Узлы — лёгкие Python-
    объекты вместо QStandardItem, поэтому построение в разы быстрее и экономнее."""

    def __init__(self, root: str, entries: list[FileEntry]) -> None:
        self.entries = entries
        self.total = len(entries)
        self._i = 0
        self._node_map: dict[str, _Node] = {}
        self.roots: list[_Node] = []
        if not root:
            self.root_norm = ""
            self.root_key = ""
            self._dir_entry_map = {}
            self._i = self.total
            return
        self.root_norm = os.path.normpath(root)
        self.root_key = self.root_norm.lower()
        self._dir_entry_map = {
            os.path.normpath(e.path).lower(): e for e in entries if e.is_dir
        }
        self._get_dir_node(self.root_norm)

    def _get_dir_node(self, path: str) -> _Node:
        norm = os.path.normpath(path)
        key = norm.lower()
        node = self._node_map.get(key)
        if node is not None:
            return node
        existing = self._dir_entry_map.get(key)
        if key == self.root_key:
            entry = _make_dir_entry(self.root_norm, existing)
            node = _Node(entry, None, name_override=self.root_norm)
            self.roots.append(node)
        else:
            parent_path = os.path.dirname(norm)
            if len(norm) <= len(self.root_norm) or not key.startswith(self.root_key):
                parent_node = self._get_dir_node(self.root_norm)
            else:
                parent_node = self._get_dir_node(parent_path)
            entry = _make_dir_entry(norm, existing)
            node = _Node(entry, parent_node)
            parent_node.children.append(node)
        self._node_map[key] = node
        return node

    def step(self, batch: int = 4000) -> int:
        end = min(self._i + batch, self.total)
        for i in range(self._i, end):
            e = self.entries[i]
            if e.is_dir:
                self._get_dir_node(e.path)
            else:
                parent = self._get_dir_node(e.parent)
                parent.children.append(_Node(e, parent))
        self._i = end
        return self._i

    def done(self) -> bool:
        return self._i >= self.total

    def model(self) -> "FileTreeModel":
        return FileTreeModel(self.roots)


class FileTreeModel(QAbstractItemModel):
    """Иерархическая модель по узлам. Фильтрация и сортировка — внутри модели
    (рекурсивно над Python-списками), без прокси: быстро на больших объёмах."""

    def __init__(self, roots: list[_Node] | None = None) -> None:
        super().__init__()
        self._roots = roots or []
        self.criteria = FilterCriteria()
        self._sort_col = -1
        self._sort_desc = False
        self._apply()

    # --- навигация
    def index(self, row, column, parent=QModelIndex()):
        if column < 0 or column >= COLUMN_COUNT or row < 0:
            return QModelIndex()
        kids = self._roots if not parent.isValid() else parent.internalPointer().vchildren
        if row < len(kids):
            return self.createIndex(row, column, kids[row])
        return QModelIndex()

    def parent(self, index):
        if not index.isValid():
            return QModelIndex()
        node = index.internalPointer()
        p = node.parent
        if p is None:
            return QModelIndex()
        return self.createIndex(p.vrow, 0, p)

    def rowCount(self, parent=QModelIndex()):  # noqa: N802
        if parent.column() > 0:
            return 0
        if not parent.isValid():
            return len(self._roots)
        return len(parent.internalPointer().vchildren)

    def columnCount(self, parent=QModelIndex()):  # noqa: N802
        return COLUMN_COUNT

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLUMNS[section][0]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        node = index.internalPointer()
        if role == ENTRY_ROLE:
            return node.entry
        col = index.column()
        if role == Qt.DisplayRole:
            if col == COL_NAME and node.name_override:
                return node.name_override
            return cell_display(node.entry, col)
        if role == Qt.TextAlignmentRole:
            align = Qt.AlignRight if COLUMNS[col][2] else Qt.AlignLeft
            return int(align | Qt.AlignVCenter)
        if role == Qt.ToolTipRole:
            return node.entry.path
        return None

    # --- фильтр/сортировка
    def set_criteria(self, criteria: FilterCriteria) -> None:
        self.beginResetModel()
        self.criteria = criteria
        self._apply()
        self.endResetModel()

    def sort(self, column, order=Qt.AscendingOrder):  # noqa: N802
        self.beginResetModel()
        self._sort_col = column
        self._sort_desc = order == Qt.DescendingOrder
        self._apply()
        self.endResetModel()

    def _apply(self) -> None:
        empty = self.criteria.is_empty()
        crit = self.criteria

        def filt(node) -> bool:
            vis = []
            for ch in node.children:
                if filt(ch):
                    vis.append(ch)
            node.vchildren = list(node.children) if empty else vis
            if empty:
                return True
            return entry_matches(node.entry, crit) or bool(vis)

        for r in self._roots:
            filt(r)

        if self._sort_col >= 0:
            col = self._sort_col
            rev = self._sort_desc

            def srt(node):
                node.vchildren.sort(key=lambda n: cell_sort_value(n.entry, col), reverse=rev)
                for ch in node.vchildren:
                    srt(ch)

            for r in self._roots:
                srt(r)

        for i, r in enumerate(self._roots):
            r.vrow = i

        def setrows(node):
            for i, ch in enumerate(node.vchildren):
                ch.vrow = i
                setrows(ch)

        for r in self._roots:
            setrows(r)


# -------------------------- ленивое дерево: узлы строятся только при раскрытии
def _tkey(path: str) -> str:
    """Ключ пути для дерева: нормализуем и срезаем хвостовой разделитель.

    Важно для UNC: os.path.normpath сохраняет «\\» у корня share (как у «C:\\»),
    из-за чего \\\\srv\\share и \\\\srv\\share\\ дали бы разные ключи."""
    return os.path.normpath(path).rstrip("\\/").lower()


class _LazyNode:
    __slots__ = ("entry", "parent", "children", "vrow", "fetched", "name_override")

    def __init__(self, entry, parent, name_override=None):
        self.entry = entry
        self.parent = parent
        self.children = None      # None — ещё не загружены
        self.vrow = 0
        self.fetched = False
        self.name_override = name_override


class LazyFileTreeModel(QAbstractItemModel):
    """Иерархия с ленивой подгрузкой: индексируем структуру (группировка по
    папкам — только ссылки на FileEntry), а узлы создаём по мере раскрытия
    (fetchMore). Память — лишь под видимые/раскрытые ветки."""

    def __init__(self, root: str = "", entries: list[FileEntry] | None = None) -> None:
        super().__init__()
        self.criteria = FilterCriteria()
        self._sort_col = -1
        self._sort_desc = False
        self._entries = entries or []
        self._build_index(root, self._entries)
        self._recompute_show()

    # --- индекс структуры (дёшево: только ссылки и пути папок)
    def _build_index(self, root, entries):
        self.file_children: dict[str, list] = {}
        self.dir_children: dict[str, set] = {}
        self.dir_norm: dict[str, str] = {}
        self.dir_entry: dict[str, FileEntry] = {}
        self.dir_size: dict[str, int] = {}   # суммарный размер папки (рекурсивно)
        self.root_norm = os.path.normpath(root) if root else ""
        self.root_key = _tkey(self.root_norm) if root else ""
        self._roots: list[_LazyNode] = []
        if not root:
            return

        def ensure_dir(pathnorm: str) -> str:
            pathnorm = os.path.normpath(pathnorm)
            key = _tkey(pathnorm)   # срезаем хвостовой разделитель (важно для UNC)
            if key in self.dir_norm:
                return key
            self.dir_norm[key] = pathnorm.rstrip("\\/") or pathnorm
            if key == self.root_key:
                return key
            if key.startswith(self.root_key + os.sep) or key.startswith(self.root_key + "/"):
                pkey = ensure_dir(os.path.dirname(pathnorm))
            else:
                pkey = ensure_dir(self.root_norm)
            self.dir_children.setdefault(pkey, set()).add(key)
            return key

        ensure_dir(self.root_norm)
        for e in entries:
            pnorm = os.path.normpath(e.parent) if e.parent else self.root_norm
            pkey = ensure_dir(pnorm)
            if e.is_dir:
                dkey = ensure_dir(os.path.normpath(e.path))
                self.dir_entry[dkey] = e
            else:
                self.file_children.setdefault(pkey, []).append(e)
                # накапливаем размер вверх по дереву (папка = сумма содержимого)
                k = pkey
                while True:
                    self.dir_size[k] = self.dir_size.get(k, 0) + e.size
                    if k == self.root_key:
                        break
                    norm = self.dir_norm.get(k)
                    if not norm:
                        break
                    pk = _tkey(os.path.dirname(norm))
                    if pk == k:
                        break
                    k = pk

        root_entry = self.dir_entry.get(self.root_key) or _make_dir_entry(self.root_norm, None)
        self._roots = [_LazyNode(root_entry, None, name_override=self.root_norm)]

    def _mark(self, dkey, show):
        k = dkey
        while k and k not in show:
            show.add(k)
            if k == self.root_key:
                break
            norm = self.dir_norm.get(k)
            if not norm:
                break
            pk = _tkey(os.path.dirname(norm))
            if pk == k:
                break
            k = pk

    def _recompute_show(self):
        if self.criteria.is_empty():
            self._show_dirs = None      # None — фильтра нет, всё видимо
            return
        show: set = set()
        crit = self.criteria
        for e in self._entries:
            if entry_matches(e, crit):
                pk = _tkey(e.parent) if e.parent else self.root_key
                self._mark(pk, show)
                if e.is_dir:
                    self._mark(_tkey(e.path), show)
        self._show_dirs = show

    def _dir_key(self, node) -> str:
        return _tkey(node.entry.path)

    def _has_children(self, node) -> bool:
        if not node.entry.is_dir:
            return False
        dk = self._dir_key(node)
        subs = self.dir_children.get(dk, ())
        files = self.file_children.get(dk, ())
        if self._show_dirs is None:
            return bool(subs) or bool(files)
        if any(s in self._show_dirs for s in subs):
            return True
        crit = self.criteria
        return any(entry_matches(f, crit) for f in files)

    def _build_children(self, node) -> list:
        dk = self._dir_key(node)
        crit = self.criteria
        show = self._show_dirs
        out: list = []
        for sk in self.dir_children.get(dk, ()):
            if show is None or sk in show:
                de = self.dir_entry.get(sk) or _make_dir_entry(self.dir_norm[sk], None)
                out.append(_LazyNode(de, node))
        for f in self.file_children.get(dk, ()):
            if show is None or entry_matches(f, crit):
                out.append(_LazyNode(f, node))
        if self._sort_col >= 0:
            col = self._sort_col
            out.sort(key=lambda n: self._sort_value(n, col), reverse=self._sort_desc)
        for i, n in enumerate(out):
            n.vrow = i
        return out

    def _sort_value(self, node, col):
        # папки сортируются по агрегированному размеру
        if col == COL_SIZE and node.entry.is_dir:
            return self.dir_size.get(self._dir_key(node), 0)
        return cell_sort_value(node.entry, col)

    # --- интерфейс модели
    def index(self, row, column, parent=QModelIndex()):
        if column < 0 or column >= COLUMN_COUNT or row < 0:
            return QModelIndex()
        if not parent.isValid():
            kids = self._roots
        else:
            kids = parent.internalPointer().children or []
        if row < len(kids):
            return self.createIndex(row, column, kids[row])
        return QModelIndex()

    def parent(self, index):
        if not index.isValid():
            return QModelIndex()
        p = index.internalPointer().parent
        if p is None:
            return QModelIndex()
        return self.createIndex(p.vrow, 0, p)

    def rowCount(self, parent=QModelIndex()):  # noqa: N802
        if parent.column() > 0:
            return 0
        if not parent.isValid():
            return len(self._roots)
        node = parent.internalPointer()
        return len(node.children) if node.children is not None else 0

    def columnCount(self, parent=QModelIndex()):  # noqa: N802
        return COLUMN_COUNT

    def hasChildren(self, parent=QModelIndex()):  # noqa: N802
        if not parent.isValid():
            return len(self._roots) > 0
        node = parent.internalPointer()
        if node.fetched:
            return bool(node.children)
        return self._has_children(node)

    def canFetchMore(self, parent):  # noqa: N802
        if not parent.isValid():
            return False
        node = parent.internalPointer()
        return (not node.fetched) and self._has_children(node)

    def fetchMore(self, parent):  # noqa: N802
        if not parent.isValid():
            return
        node = parent.internalPointer()
        if node.fetched:
            return
        kids = self._build_children(node)
        if kids:
            self.beginInsertRows(parent, 0, len(kids) - 1)
            node.children = kids
            node.fetched = True
            self.endInsertRows()
        else:
            node.children = []
            node.fetched = True

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLUMNS[section][0]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        node = index.internalPointer()
        if role == ENTRY_ROLE:
            return node.entry
        col = index.column()
        if role == Qt.DisplayRole:
            if col == COL_NAME and node.name_override:
                return node.name_override
            if col == COL_SIZE and node.entry.is_dir:
                return human_size(self.dir_size.get(self._dir_key(node), 0))
            return cell_display(node.entry, col)
        if role == Qt.DecorationRole and col == COL_NAME:
            return entry_icon(node.entry)
        if role == Qt.TextAlignmentRole:
            align = Qt.AlignRight if COLUMNS[col][2] else Qt.AlignLeft
            return int(align | Qt.AlignVCenter)
        if role == Qt.ToolTipRole:
            return node.entry.path
        return None

    def _reset_lazy(self):
        # сбрасываем загруженные узлы — память освобождается, ветки построятся заново
        for r in self._roots:
            r.children = None
            r.fetched = False

    def set_criteria(self, criteria: FilterCriteria) -> None:
        self.beginResetModel()
        self.criteria = criteria
        self._recompute_show()
        self._reset_lazy()
        self.endResetModel()

    def sort(self, column, order=Qt.AscendingOrder):  # noqa: N802
        self.beginResetModel()
        self._sort_col = column
        self._sort_desc = order == Qt.DescendingOrder
        self._reset_lazy()
        self.endResetModel()
