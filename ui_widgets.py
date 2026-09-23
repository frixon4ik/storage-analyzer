"""Виджеты и платформенные помощники интерфейса.

* иконки (SF Symbols на macOS / Fluent на Windows через тему Qt, с запасными
  стандартными иконками стиля);
* боковая панель источников в стиле Finder (избранное, диски, S3, недавние);
* панель сводки с «карточками» и полосами долей по категориям;
* «пустое» состояние окна с подсказкой;
* интеграция с файловым менеджером: показать в Finder/Проводнике, Quick Look.
"""

from __future__ import annotations

import os
import subprocess
import sys

from PySide6.QtCore import QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QFileIconProvider,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QStyle,
    QStyledItemDelegate,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from model import human_size

MACOS = sys.platform == "darwin"
WINDOWS = sys.platform == "win32"

FILE_MANAGER = "Finder" if MACOS else ("Explorer" if WINDOWS else "File Manager")

if WINDOWS:
    PATH_HINT = r"C:\Folder  or  \\server\share\folder"
    TARGET_HINT = r"e.g.  D:\Quarantine"
    AUTHOR_HINT = "DOMAIN\\user"
    SMB_HINT = r"\\synology\share  or  \\192.168.1.10\share\folder"
elif MACOS:
    PATH_HINT = "/Users/name/Folder  or  /Volumes/share  (you can drop a folder onto the window)"
    TARGET_HINT = "e.g.  ~/Quarantine"
    AUTHOR_HINT = "user name"
    SMB_HINT = "smb://nas.local/share  or  smb://192.168.1.10/share/folder"
else:
    PATH_HINT = "/home/name/Folder  or  /mnt/share"
    TARGET_HINT = "e.g.  ~/Quarantine"
    AUTHOR_HINT = "user name"
    SMB_HINT = "smb://server/share"


# ------------------------------------------------------------------ иконки
_FALLBACK = {
    "FolderOpen": QStyle.SP_DirOpenIcon,
    "MediaPlaybackStart": QStyle.SP_MediaPlay,
    "ProcessStop": QStyle.SP_BrowserStop,
    "NetworkWired": QStyle.SP_DriveNetIcon,
    "SyncSynchronizing": QStyle.SP_DriveNetIcon,
    "EditFind": QStyle.SP_FileDialogContentsView,
    "EditCopy": QStyle.SP_FileDialogDetailedView,
    "AppointmentSoon": QStyle.SP_FileDialogInfoView,
    "DocumentProperties": QStyle.SP_FileDialogInfoView,
    "FormatIndentMore": QStyle.SP_FileDialogListView,
    "SystemSearch": QStyle.SP_FileDialogContentsView,
    "ViewRefresh": QStyle.SP_BrowserReload,
    "DocumentSaveAs": QStyle.SP_DialogSaveButton,
    "GoHome": QStyle.SP_DirHomeIcon,
    "DriveHarddisk": QStyle.SP_DriveHDIcon,
    "MediaEject": QStyle.SP_ArrowUp,
    "ListAdd": QStyle.SP_FileDialogNewFolder,
}


def icon(name: str) -> QIcon:
    """Системная иконка темы по имени QIcon.ThemeIcon, иначе — стандартная стиля."""
    ic = QIcon()
    theme = getattr(QIcon.ThemeIcon, name, None)
    if theme is not None:
        ic = QIcon.fromTheme(theme)
    if ic.isNull():
        sp = _FALLBACK.get(name)
        if sp is not None:
            ic = QApplication.style().standardIcon(sp)
    return ic


# --------------------------------------------- интеграция с файловым менеджером
def reveal_in_file_manager(path: str) -> None:
    """Показать объект в Finder/Проводнике (с выделением)."""
    try:
        if MACOS:
            subprocess.Popen(["open", "-R", path])
        elif WINDOWS:
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        else:
            target = path if os.path.isdir(path) else os.path.dirname(path)
            subprocess.Popen(["xdg-open", target])
    except OSError:
        pass


def quick_look(paths: list[str]) -> None:
    """Быстрый просмотр (Quick Look) — только macOS."""
    if not MACOS or not paths:
        return
    try:
        subprocess.Popen(["qlmanage", "-p", *paths[:20]],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass


# ------------------------------------------------------ боковая панель
KIND_ROLE = Qt.UserRole + 10     # "path" | "s3" | "s3-setup" | "smb" | "section"
VALUE_ROLE = Qt.UserRole + 11    # путь для "path"


def _volumes() -> list[tuple[str, str, bool]]:
    """Тома для боковой панели: [(название, путь, сетевой?)]."""
    from PySide6.QtCore import QStorageInfo
    out = []
    seen = set()
    for v in QStorageInfo.mountedVolumes():
        if not v.isValid() or not v.isReady():
            continue
        root = v.rootPath()
        fs = bytes(v.fileSystemType()).decode(errors="ignore").lower()
        if MACOS:
            if not (root == "/" or root.startswith("/Volumes/")):
                continue
        elif not WINDOWS:
            if not (root == "/" or root.startswith(("/media/", "/mnt/", "/run/media/"))):
                continue
        if root in seen:
            continue
        seen.add(root)
        name = v.displayName() or os.path.basename(root.rstrip("/\\")) or root
        if MACOS and root == "/":
            name = v.name() or "Macintosh HD"
        network = fs in ("smbfs", "nfs", "afpfs", "webdav", "cifs", "smb2", "smb3")
        out.append((name, root, network))
    return out


class Sidebar(QTreeWidget):
    """Источники в стиле Finder: избранное, расположения, облако S3, недавние."""

    location_chosen = Signal(str)      # путь папки/тома
    s3_chosen = Signal()               # выбран сохранённый бакет
    s3_setup = Signal()                # «Настроить S3…»
    smb_connect = Signal()             # «Подключиться к серверу…»
    recent_remove = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setHeaderHidden(True)
        self.setRootIsDecorated(False)
        self.setIndentation(10)
        self.setIconSize(QSize(18, 18))
        self.setFrameShape(QFrame.NoFrame)
        self.setUniformRowHeights(True)
        self.setMinimumWidth(170)
        self.setAttribute(Qt.WA_MacShowFocusRect, False)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._menu)
        self.itemClicked.connect(self._clicked)
        self.setStyleSheet(
            "QTreeWidget { background: transparent; show-decoration-selected: 0; }"
            "QTreeWidget::item { padding: 3px 2px; }"
            "QTreeWidget::item:selected { border-radius: 5px;"
            " background: palette(highlight); color: palette(highlighted-text); }"
            "QTreeWidget::branch, QTreeWidget::branch:selected { background: transparent; }"
        )
        self._provider = QFileIconProvider()
        self._vol_sig = None
        self._recent: list[str] = []
        self._s3_label = ""
        self._smb = False
        self.rebuild()

    # --- данные
    def set_recent(self, paths: list[str]) -> None:
        self._recent = list(paths)
        self.rebuild()

    def set_s3(self, label: str) -> None:
        self._s3_label = label
        self.rebuild()

    def set_smb_available(self, on: bool) -> None:
        self._smb = on
        self.rebuild()

    def refresh_volumes(self) -> None:
        """Перестроить, только если набор томов изменился (вызывается по таймеру)."""
        sig = tuple(_volumes())
        if sig != self._vol_sig:
            self.rebuild()

    # --- построение
    def _section(self, title: str) -> QTreeWidgetItem:
        it = QTreeWidgetItem(self, [title.upper()])
        it.setFlags(Qt.ItemIsEnabled)
        f = it.font(0)
        f.setPointSizeF(max(8.0, f.pointSizeF() - 2))
        f.setBold(True)
        it.setFont(0, f)
        it.setForeground(0, self.palette().color(QPalette.PlaceholderText))
        it.setData(0, KIND_ROLE, "section")
        it.setExpanded(True)
        return it

    def _item(self, parent, text, ic, kind, value="", tip="") -> QTreeWidgetItem:
        it = QTreeWidgetItem(parent, [text])
        it.setIcon(0, ic)
        it.setData(0, KIND_ROLE, kind)
        it.setData(0, VALUE_ROLE, value)
        it.setToolTip(0, tip or value or text)
        return it

    def _dir_icon(self, path: str) -> QIcon:
        from PySide6.QtCore import QFileInfo
        ic = self._provider.icon(QFileInfo(path))
        return ic if not ic.isNull() else self._provider.icon(QFileIconProvider.Folder)

    def rebuild(self) -> None:
        current = self.currentItem()
        cur_key = (current.data(0, KIND_ROLE), current.data(0, VALUE_ROLE)) if current else None
        self.clear()
        home = os.path.expanduser("~")

        fav = self._section("Favorites")
        places = [("Home", home)]
        for label, sub in (("Desktop", "Desktop"), ("Documents", "Documents"),
                           ("Downloads", "Downloads"), ("Pictures", "Pictures"),
                           ("Movies" if MACOS else "Videos", "Movies" if MACOS else "Videos"), ("Music", "Music")):
            p = os.path.join(home, sub)
            if os.path.isdir(p):
                places.append((label, p))
        for label, p in places:
            self._item(fav, label, self._dir_icon(p), "path", p)

        vols = _volumes()
        self._vol_sig = tuple(vols)
        loc = self._section("Locations")
        for name, root, network in vols:
            ic = icon("NetworkWired") if network else self._dir_icon(root)
            self._item(loc, name, ic, "path", root)
        if self._smb:
            self._item(loc, "Connect to Server…", icon("NetworkWired"), "smb",
                       tip="Connect an SMB network share with a user name and password")

        cloud = self._section("S3 Cloud")
        if self._s3_label:
            self._item(cloud, self._s3_label, icon("SyncSynchronizing"), "s3",
                       tip="Analyze the saved S3 bucket")
        self._item(cloud, "Set Up S3…" if not self._s3_label else "Another Bucket…",
                   icon("DocumentProperties"), "s3-setup",
                   tip="AWS S3 or compatible storage (MinIO, Ceph, Wasabi, B2)")

        if self._recent:
            rec = self._section("Recent")
            for p in self._recent:
                name = os.path.basename(p.rstrip("/\\")) or p
                self._item(rec, name, self._dir_icon(p), "path", p)

        self.expandAll()
        if cur_key:
            self.select(*cur_key, emit=False)

    def select(self, kind: str, value: str = "", emit: bool = False) -> None:
        """Подсветить пункт (без запуска действия)."""
        for i in range(self.topLevelItemCount()):
            sec = self.topLevelItem(i)
            for j in range(sec.childCount()):
                it = sec.child(j)
                if it.data(0, KIND_ROLE) == kind and (kind != "path" or it.data(0, VALUE_ROLE) == value):
                    self.blockSignals(not emit)
                    self.setCurrentItem(it)
                    self.blockSignals(False)
                    return
        self.blockSignals(True)
        self.setCurrentItem(None)
        self.clearSelection()
        self.blockSignals(False)

    # --- события
    def _clicked(self, item, _col) -> None:
        kind = item.data(0, KIND_ROLE)
        if kind == "path":
            self.location_chosen.emit(item.data(0, VALUE_ROLE))
        elif kind == "s3":
            self.s3_chosen.emit()
        elif kind == "s3-setup":
            self.s3_setup.emit()
        elif kind == "smb":
            self.smb_connect.emit()

    def _menu(self, pos) -> None:
        from PySide6.QtWidgets import QMenu
        item = self.itemAt(pos)
        if item is None or item.data(0, KIND_ROLE) != "path":
            return
        path = item.data(0, VALUE_ROLE)
        menu = QMenu(self)
        menu.addAction("Analyze", lambda: self.location_chosen.emit(path))
        menu.addAction(f"Show in {FILE_MANAGER}", lambda: reveal_in_file_manager(path))
        if item.parent() is not None and item.parent().text(0) == "RECENT":
            menu.addSeparator()
            menu.addAction("Remove from Recent", lambda: self.recent_remove.emit(path))
        menu.exec(self.viewport().mapToGlobal(pos))


# ----------------------------------------------------------- сводка
CATEGORY_COLORS = {
    "Video": "#e5484d",
    "Images": "#f76b15",
    "Audio": "#d6409f",
    "Documents": "#0090ff",
    "Archives": "#ffb224",
    "Code": "#30a46c",
    "Executables": "#8e4ec6",
    "Fonts": "#12a594",
    "3D / CAD": "#a18072",
    "Other": "#8b8d98",
    "No extension": "#b0b4ba",
    "Folder": "#5b9bd5",
}
SHARE_ROLE = Qt.UserRole + 20
CAT_ROLE = Qt.UserRole + 21


class _CategoryDelegate(QStyledItemDelegate):
    """Первая колонка: цветная точка + имя + тонкая полоса доли объёма."""

    def sizeHint(self, option, index):
        s = super().sizeHint(option, index)
        return QSize(s.width(), max(s.height(), 22) + 8)

    def paint(self, painter: QPainter, option, index) -> None:
        opt = option
        self.initStyleOption(opt, index)
        text = opt.text
        opt.text = ""
        style = opt.widget.style() if opt.widget else QApplication.style()
        style.drawControl(QStyle.CE_ItemViewItem, opt, painter, opt.widget)

        cat = index.data(CAT_ROLE) or text
        share = float(index.data(SHARE_ROLE) or 0.0)
        color = QColor(CATEGORY_COLORS.get(cat, "#8b8d98"))
        r = opt.rect.adjusted(8, 3, -6, -3)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        # точка
        painter.setPen(Qt.NoPen)
        painter.setBrush(color)
        dot = QRectF(r.left(), r.top() + (r.height() - 8) / 2 - 3, 8, 8)
        painter.drawEllipse(dot)
        # текст
        painter.setPen(opt.palette.color(
            QPalette.HighlightedText if opt.state & QStyle.State_Selected else QPalette.Text))
        painter.setFont(opt.font)
        tr = r.adjusted(14, 0, 0, -6)
        painter.drawText(tr, Qt.AlignLeft | Qt.AlignVCenter,
                         painter.fontMetrics().elidedText(text, Qt.ElideRight, tr.width()))
        # полоса доли
        track = QRectF(r.left() + 14, r.bottom() - 3, r.width() - 14, 3)
        bg = QColor(opt.palette.color(QPalette.Text))
        bg.setAlphaF(0.08)
        painter.setBrush(bg)
        painter.drawRoundedRect(track, 1.5, 1.5)
        if share > 0:
            fill = QRectF(track.left(), track.top(), max(3.0, track.width() * share), track.height())
            painter.setBrush(color)
            painter.drawRoundedRect(fill, 1.5, 1.5)
        painter.restore()


class _StatCard(QFrame):
    def __init__(self, title: str) -> None:
        super().__init__()
        self.setObjectName("statCard")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 7, 10, 8)
        lay.setSpacing(1)
        self.value = QLabel("—")
        f = self.value.font()
        f.setPointSizeF(f.pointSizeF() + 5)
        f.setWeight(QFont.DemiBold)
        self.value.setFont(f)
        self.title = QLabel(title)
        tf = self.title.font()
        tf.setPointSizeF(max(8.0, tf.pointSizeF() - 1))
        self.title.setFont(tf)
        self.title.setForegroundRole(QPalette.PlaceholderText)
        lay.addWidget(self.value)
        lay.addWidget(self.title)


class SummaryPanel(QWidget):
    """Итоги + разбивка по категориям (клик по категории — фильтр)."""

    category_clicked = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumWidth(240)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(8)

        head = QLabel("Summary")
        hf = head.font()
        hf.setPointSizeF(hf.pointSizeF() + 2)
        hf.setBold(True)
        head.setFont(hf)
        lay.addWidget(head)

        grid = QGridLayout()
        grid.setSpacing(6)
        self.card_size = _StatCard("total size")
        self.card_files = _StatCard("files")
        self.card_dirs = _StatCard("folders")
        self.card_shown = _StatCard("shown")
        grid.addWidget(self.card_size, 0, 0, 1, 2)
        grid.addWidget(self.card_files, 1, 0)
        grid.addWidget(self.card_dirs, 1, 1)
        grid.addWidget(self.card_shown, 2, 0, 1, 2)
        lay.addLayout(grid)

        cat_head = QHBoxLayout()
        lbl = QLabel("By category")
        lf = lbl.font()
        lf.setBold(True)
        lbl.setFont(lf)
        cat_head.addWidget(lbl)
        cat_head.addStretch(1)
        self.reset_btn = QPushButton("Reset")
        self.reset_btn.setFlat(True)
        self.reset_btn.setCursor(Qt.PointingHandCursor)
        self.reset_btn.setVisible(False)
        self.reset_btn.clicked.connect(lambda: self.category_clicked.emit(""))
        cat_head.addWidget(self.reset_btn)
        lay.addLayout(cat_head)

        hint = QLabel("Click a category to filter the list")
        hint.setForegroundRole(QPalette.PlaceholderText)
        hf2 = hint.font()
        hf2.setPointSizeF(max(8.0, hf2.pointSizeF() - 1))
        hint.setFont(hf2)
        lay.addWidget(hint)

        self.cats = QTreeWidget()
        self.cats.setColumnCount(3)
        self.cats.setHeaderLabels(["Category", "Count", "Size"])
        self.cats.setRootIsDecorated(False)
        self.cats.setUniformRowHeights(True)
        self.cats.setFrameShape(QFrame.NoFrame)
        self.cats.setAttribute(Qt.WA_MacShowFocusRect, False)
        self.cats.setItemDelegateForColumn(0, _CategoryDelegate(self.cats))
        h = self.cats.header()
        h.setSectionResizeMode(0, QHeaderView.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        h.setStretchLastSection(False)
        self.cats.setCursor(Qt.PointingHandCursor)
        self.cats.itemClicked.connect(
            lambda it, _c: self.category_clicked.emit(it.data(0, CAT_ROLE)))
        lay.addWidget(self.cats, 1)

        self.setStyleSheet(
            "#statCard { border-radius: 8px; background: palette(base);"
            " border: 1px solid palette(midlight); }"
        )

    def update_data(self, shown: int, total: int, files: int, dirs: int, size: int,
                    by_count: dict, by_size: dict, active: str) -> None:
        sp = lambda n: f"{n:,}"  # noqa: E731
        self.card_size.value.setText(human_size(size) if size else "—")
        self.card_files.value.setText(sp(files))
        self.card_dirs.value.setText(sp(dirs))
        self.card_shown.value.setText(f"{sp(shown)} of {sp(total)}" if total else "—")
        self.reset_btn.setVisible(active not in ("", "All"))

        total_size = sum(by_size.values()) or 1
        rows = sorted(by_count, key=lambda c: (by_size.get(c, 0), by_count[c]), reverse=True)
        self.cats.clear()
        for cat in rows:
            it = QTreeWidgetItem(self.cats, [cat, sp(by_count[cat]),
                                             human_size(by_size[cat]) if by_size.get(cat) else "—"])
            it.setData(0, CAT_ROLE, cat)
            it.setData(0, SHARE_ROLE, by_size.get(cat, 0) / total_size)
            it.setTextAlignment(1, int(Qt.AlignRight | Qt.AlignVCenter))
            it.setTextAlignment(2, int(Qt.AlignRight | Qt.AlignVCenter))
            if cat == active:
                for c in range(3):
                    f = it.font(c)
                    f.setBold(True)
                    it.setFont(c, f)
                self.cats.setCurrentItem(it)


# ----------------------------------------------------- пустое состояние
class EmptyState(QWidget):
    """Подсказка вместо пустой таблицы."""

    open_clicked = Signal()
    s3_clicked = Signal()
    smb_clicked = Signal()

    def __init__(self, smb_available: bool, parent=None) -> None:
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.addStretch(1)
        ic = QLabel()
        ic.setPixmap(icon("FolderOpen").pixmap(56, 56))
        ic.setAlignment(Qt.AlignCenter)
        lay.addWidget(ic)
        self.title = QLabel("Choose what to analyze")
        tf = self.title.font()
        tf.setPointSizeF(tf.pointSizeF() + 6)
        tf.setWeight(QFont.DemiBold)
        self.title.setFont(tf)
        self.title.setAlignment(Qt.AlignCenter)
        lay.addWidget(self.title)
        key = "⌘" if MACOS else "Ctrl+"
        self.sub = QLabel(
            "Pick a folder or drive in the sidebar, drop a folder onto this window\n"
            f"or press {key}O. Use SMB for network shares and S3 for cloud storage."
        )
        self.sub.setAlignment(Qt.AlignCenter)
        self.sub.setForegroundRole(QPalette.PlaceholderText)
        lay.addWidget(self.sub)
        lay.addSpacing(10)
        row = QHBoxLayout()
        row.addStretch(1)
        b1 = QPushButton(icon("FolderOpen"), "Choose Folder…")
        b1.setDefault(True)
        b1.clicked.connect(self.open_clicked)
        row.addWidget(b1)
        if smb_available:
            b2 = QPushButton(icon("NetworkWired"), "Connect SMB…")
            b2.clicked.connect(self.smb_clicked)
            row.addWidget(b2)
        b3 = QPushButton(icon("SyncSynchronizing"), "Connect S3…")
        b3.clicked.connect(self.s3_clicked)
        row.addWidget(b3)
        row.addStretch(1)
        lay.addLayout(row)
        lay.addStretch(2)
