"""Анализатор папок — графический интерфейс (PySide6).

Возможности:
  * выбор папки на локальном диске или в сетевом хранилище (SMB: \\\\server\\share);
  * анализ содержимого: имя, тип, формат, категория, размер, даты;
  * наглядная таблица с сортировкой;
  * фильтры по всем параметрам (имя, формат, категория, тип, размер, дата);
  * сводка: количество элементов, общий размер, разбивка по категориям.

Запуск:  python app.py
"""

from __future__ import annotations

import os
import sys
from collections import defaultdict

from PySide6.QtCore import (
    QDate,
    QDateTime,
    QDir,
    QEventLoop,
    QObject,
    QSettings,
    QSize,
    Qt,
    QThread,
    QTime,
    QTimer,
    QUrl,
    Signal,
)
from PySide6.QtGui import QAction, QActionGroup, QDesktopServices, QIcon, QKeySequence, QPalette


def _icon_path() -> str:
    """Путь к иконке приложения (работает из исходников и из сборки; .ico/.png)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    names = ("app_icon.png", "app_icon.ico") if sys.platform != "win32" else ("app_icon.ico", "app_icon.png")
    for name in names:
        p = os.path.join(base, name)
        if os.path.exists(p):
            return p
    return ""
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QCompleter,
    QComboBox,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QFileSystemModel,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QTimeEdit,
    QToolBar,
    QToolButton,
    QTreeView,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

import dedup
import netshare
import notify
import rules
import s3client
import schedule_task
import settings as app_settings
import ui_widgets as ui

from db import FileDatabase, db_size_bytes, default_db_path
from model import (
    COL_AUTHOR,
    COL_CAT,
    COL_CREATED,
    COL_EXT,
    COL_KIND,
    COL_MODIFIED,
    COL_NAME,
    COL_SIZE,
    ENTRY_ROLE,
    FileListModel,
    FilterCriteria,
    LazyFileTreeModel,
    human_size,
)
from scanner import ScanController


class S3ListController:
    """Фоновое перечисление объектов S3 (тот же безопасный поток-паттерн)."""

    def __init__(self) -> None:
        self.thread = None
        self.worker = None

    def start(self, cfg, include_dirs, db_path, incremental,
              on_progress, on_finished, on_error, on_info=None):
        self.stop()
        self.thread = QThread()
        self.worker = _S3Worker(cfg, include_dirs, db_path, incremental)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(on_progress)
        self.worker.error.connect(on_error)
        self.worker.finished.connect(on_finished)
        if on_info is not None:
            self.worker.info.connect(on_info)
        self.worker.finished.connect(self.thread.quit)
        self.worker.error.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(self._cleanup)
        self.thread.start()

    def _cleanup(self):
        self.thread = None
        self.worker = None

    def stop(self):
        if self.worker is not None:
            self.worker.cancel()
            self.worker.blockSignals(True)
        thread = self.thread
        if thread is not None:
            thread.quit()
            if QThread.currentThread() is not thread:
                thread.wait(3000)
        self.thread = None
        self.worker = None


class _S3Worker(QObject):
    progress = Signal(int, int)      # получено, 0 (всего неизвестно)
    info = Signal(dict)
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, cfg, include_dirs, db_path, incremental):
        super().__init__()
        self.cfg = cfg
        self.include_dirs = include_dirs
        self.db_path = db_path
        self.incremental = incremental
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            import time as _time

            from scanner import incremental_stats
            prior = {}
            db = None
            root = self.cfg.bucket
            if self.db_path:
                try:
                    from db import FileDatabase
                    db = FileDatabase(self.db_path)
                    if self.incremental:
                        prior = db.load_entries(root)
                except Exception:  # noqa: BLE001
                    db = None
            entries = s3client.list_entries(
                self.cfg, on_progress=lambda n: self.progress.emit(n, 0),
                cancel=lambda: self._cancelled, include_dirs=self.include_dirs,
            )
            info = incremental_stats(entries, prior)
            if db is not None and not self._cancelled:
                try:
                    db.save_scan(root, entries, _time.time())
                except Exception:  # noqa: BLE001
                    pass
                db.close()
            if not self._cancelled:
                self.info.emit(info)
            self.finished.emit(entries)
        except Exception as exc:  # noqa: BLE001
            self.error.emit(s3client.err_text(exc))

SIZE_UNITS = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
APP_TITLE = "Storage Analyzer"
APP_VERSION = "2.1.1"
MAX_RECENT = 8


def _form() -> QFormLayout:
    """Форма, поля которой растягиваются по ширине (на macOS по умолчанию — нет)."""
    f = QFormLayout()
    f.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
    return f


def _is_inside(target: str, root: str) -> bool:
    """Лежит ли target внутри root (или совпадает с ним) — с учётом регистра ОС."""
    if not target or not root:
        return False
    t = os.path.normcase(os.path.abspath(os.path.expanduser(target)))
    r = os.path.normcase(os.path.abspath(os.path.expanduser(root)))
    if sys.platform == "darwin":  # APFS/HFS+ по умолчанию нечувствительны к регистру
        t, r = t.lower(), r.lower()
    try:
        return os.path.commonpath([t, r]) == r
    except ValueError:  # разные диски (Windows)
        return False


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1320, 820)
        self.setMinimumSize(900, 560)
        self.setUnifiedTitleAndToolBarOnMac(True)
        self.setAcceptDrops(True)
        _ip = _icon_path()
        if _ip and sys.platform != "darwin":  # на macOS иконку даёт .app-бандл
            self.setWindowIcon(QIcon(_ip))

        self.qsettings = QSettings("FolderAnalyzer", "FolderAnalyzer")
        self.controller = ScanController()
        self.s3_controller = S3ListController()
        self.mode = "file"  # "file" | "s3"
        self.s3cfg = s3client.S3Config(**app_settings.get_s3()) if app_settings.get_s3() else s3client.S3Config()
        self.db_path = app_settings.get_db_path() or default_db_path()
        self._last_info: dict = {}
        self._scanning = False
        # ресурсы, подключённые за время сессии (для отключения при выходе)
        self._smb_connections: list[tuple[str, bool]] = []  # (адрес, persistent)
        self.model = FileListModel()  # быстрый фильтр+сортировка над списком

        # древовидное представление (по папкам) — ленивая модель
        self.tree_model = LazyFileTreeModel("", [])
        self._last_root = ""
        self._tree_built = False   # дерево строится по запросу при переключении вида
        self._tree_root = None     # для какого корня построено дерево (для переиспользования)
        self._building_tree = False

        # фильтры применяются «вживую» с небольшой задержкой
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(220)
        self._filter_timer.timeout.connect(self.apply_filters)

        self._build_actions()
        self._build_ui()
        self._build_menus()
        self._restore_state()
        self._update_actions()
        self._update_summary()

        # тома появляются/исчезают (флешки, SMB) — обновляем боковую панель
        self._vol_timer = QTimer(self)
        self._vol_timer.timeout.connect(self.sidebar.refresh_volumes)
        self._vol_timer.start(4000)

    # ------------------------------------------------------------ действия
    def _act(self, text, slot=None, shortcut=None, icon_name=None, tip=None,
             checkable=False) -> QAction:
        a = QAction(text, self)
        if icon_name:
            a.setIcon(ui.icon(icon_name))
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
        if tip:
            a.setToolTip(tip)
            a.setStatusTip(tip)
        a.setCheckable(checkable)
        if slot is not None:
            (a.toggled if checkable else a.triggered).connect(slot)
        return a

    def _build_actions(self) -> None:
        smb = netshare.is_available()
        self.act_open = self._act("Open", self.browse_folder, QKeySequence.Open,
                                  "FolderOpen", "Choose a folder or drive to analyze (⌘O)")
        self.act_smb = self._act("SMB", self.connect_smb, "Ctrl+K", "NetworkWired",
                                 "Connect to an SMB network share with a user name and password (⌘K)")
        self.act_smb.setVisible(smb)
        self.act_s3 = self._act("S3", self.open_connect_s3, "Ctrl+Shift+K",
                                "SyncSynchronizing", "Connect to an S3 bucket (⇧⌘K)")
        self.act_scan = self._act("Analyze", self.start_scan, "Ctrl+R", "MediaPlaybackStart",
                                  "Analyze the selected folder/bucket (⌘R)")
        self.act_stop = self._act("Stop", self.cancel_scan, "Ctrl+.", "ProcessStop",
                                  "Stop the analysis (⌘.)")
        self.act_filters = self._act("Filters", self._toggle_filters, "Ctrl+Alt+F",
                                     "FormatIndentMore", "Show/hide filters (⌥⌘F)",
                                     checkable=True)
        self.act_rules = self._act("Rules", self.open_rules, "Ctrl+Shift+R", "EditFind",
                                   "Select files by conditions and run an action (⇧⌘R)")
        self.act_dups = self._act("Duplicates", self.open_duplicates, "Ctrl+Shift+D", "EditCopy",
                                  "Find duplicates and move them away (⇧⌘D)")
        self.act_schedule = self._act("Schedule", self.open_schedule, "Ctrl+Shift+T",
                                      "AppointmentSoon", "Scheduled analysis and auto-archiving (⇧⌘T)")
        self.act_settings = self._act("Settings…", self.open_settings, QKeySequence.Preferences,
                                      "DocumentProperties", "Database and Telegram notifications")
        self.act_settings.setMenuRole(QAction.PreferencesRole)
        if not self.act_settings.shortcut().toString():
            self.act_settings.setShortcut(QKeySequence("Ctrl+,"))
        self.act_export = self._act("Export List to CSV…", self.export_visible, "Ctrl+E",
                                    "DocumentSaveAs", "Save the rows shown to a CSV file (⌘E)")
        self.act_copy = self._act("Copy Path", self._copy_selected_paths, QKeySequence.Copy)
        self.act_find = self._act("Search", lambda: (self.search.setFocus(), self.search.selectAll()),
                                  QKeySequence.Find)
        self.act_reset = self._act("Reset Filters", self.reset_filters, "Ctrl+Alt+R")
        self.act_quicklook = self._act("Quick Look", self._quick_look, "Space")
        self.act_quicklook.setShortcutContext(Qt.WidgetWithChildrenShortcut)
        self.act_reveal = self._act(f"Show in {ui.FILE_MANAGER}", self._reveal_selected,
                                    "Ctrl+Shift+F")
        self.act_view_list = self._act("List", lambda on: on and self._set_view(False),
                                       "Ctrl+1", checkable=True)
        self.act_view_tree = self._act("Folders (tree)", lambda on: on and self._set_view(True),
                                       "Ctrl+2", checkable=True)
        self._view_group = QActionGroup(self)  # ссылка обязательна, иначе группу соберёт GC
        self._view_group.addAction(self.act_view_list)
        self._view_group.addAction(self.act_view_tree)
        self._suppress_view = True   # не перестраивать вид при программном переключении
        self.act_view_list.setChecked(True)
        self._suppress_view = False
        self.act_expand = self._act("Expand All", lambda: self.tree.expandAll(), "Ctrl+Alt+Right")
        self.act_collapse = self._act("Collapse All", lambda: self.tree.collapseAll(), "Ctrl+Alt+Left")
        self.act_sidebar = self._act("Sidebar", lambda on: self.sidebar.setVisible(on),
                                     "Meta+Ctrl+S", checkable=True)
        self.act_summary = self._act("Summary", lambda on: self.summary.setVisible(on),
                                     "Ctrl+Alt+S", checkable=True)
        self.act_about = self._act(f"About {APP_TITLE}", self._about)
        self.act_about.setMenuRole(QAction.AboutRole)

    def _build_menus(self) -> None:
        mb = self.menuBar()
        m = mb.addMenu("File")
        for a in (self.act_open, self.act_smb, self.act_s3):
            m.addAction(a)
        self.recent_menu = m.addMenu("Recent Folders")
        self.recent_menu.aboutToShow.connect(self._fill_recent_menu)
        m.addSeparator()
        m.addAction(self.act_scan)
        m.addAction(self.act_stop)
        m.addSeparator()
        m.addAction(self.act_export)
        m.addSeparator()
        m.addAction(self.act_settings)
        m.addAction(self.act_about)
        close = self._act("Close Window", self.close, QKeySequence.Close)
        m.addAction(close)

        m = mb.addMenu("Edit")
        m.addAction(self.act_copy)
        sel_all = self._act("Select All", lambda: self._current_view().selectAll(),
                            QKeySequence.SelectAll)
        m.addAction(sel_all)
        m.addSeparator()
        m.addAction(self.act_find)
        m.addAction(self.act_reset)

        m = mb.addMenu("View")
        m.addAction(self.act_view_list)
        m.addAction(self.act_view_tree)
        m.addSeparator()
        m.addAction(self.act_expand)
        m.addAction(self.act_collapse)
        m.addSeparator()
        m.addAction(self.act_filters)
        m.addAction(self.act_sidebar)
        m.addAction(self.act_summary)

        m = mb.addMenu("Item")
        m.addAction(self._act("Open", lambda: self._open_entry(self._first_selected()),
                              "Ctrl+Down"))
        if sys.platform == "darwin":
            # пункт меню без клавиши: пробел работает только в списке/дереве
            m.addAction(self._act("Quick Look (Space)", self._quick_look))
        m.addAction(self.act_reveal)
        m.addAction(self.act_copy)

        m = mb.addMenu("Tools")
        m.addAction(self.act_rules)
        m.addAction(self.act_dups)
        m.addAction(self.act_schedule)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        tb = QToolBar("Toolbar")
        tb.setObjectName("main_toolbar")
        tb.setMovable(False)
        tb.setFloatable(False)
        tb.setIconSize(QSize(18, 18))
        tb.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        tb.setContextMenuPolicy(Qt.PreventContextMenu)
        self.addToolBar(tb)
        for a in (self.act_open, self.act_smb, self.act_s3):
            tb.addAction(a)
        tb.addSeparator()
        tb.addAction(self.act_scan)
        tb.addAction(self.act_stop)
        tb.addSeparator()

        # переключатель вида (сегменты)
        seg = QWidget()
        sl = QHBoxLayout(seg)
        sl.setContentsMargins(4, 0, 4, 0)
        sl.setSpacing(0)
        self.seg_list = QToolButton()
        self.seg_list.setText("List")
        self.seg_list.setObjectName("segL")
        self.seg_tree = QToolButton()
        self.seg_tree.setText("Tree")
        self.seg_tree.setObjectName("segR")
        for b, act in ((self.seg_list, self.act_view_list), (self.seg_tree, self.act_view_tree)):
            b.setCheckable(True)
            b.setToolTip(act.text() + " (" + act.shortcut().toString(QKeySequence.NativeText) + ")")
            b.clicked.connect(lambda _=False, a=act: a.setChecked(True))
            act.toggled.connect(b.setChecked)
            act.changed.connect(lambda b=b, a=act: b.setEnabled(a.isEnabled()))
            b.setChecked(act.isChecked())
            sl.addWidget(b)
        seg.setStyleSheet(
            "QToolButton { border: 1px solid palette(mid); background: palette(button);"
            " padding: 3px 14px; margin: 0; }"
            "QToolButton#segL { border-top-left-radius: 6px; border-bottom-left-radius: 6px; }"
            "QToolButton#segR { border-left: none; border-top-right-radius: 6px;"
            " border-bottom-right-radius: 6px; }"
            "QToolButton:checked { background: palette(highlight); color: palette(highlighted-text);"
            " border-color: palette(highlight); }"
            "QToolButton:disabled { color: palette(mid); }"
        )
        tb.addWidget(seg)
        tb.addAction(self.act_filters)
        tb.addSeparator()
        for a in (self.act_rules, self.act_dups, self.act_schedule):
            tb.addAction(a)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        tb.addWidget(spacer)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search by name")
        self.search.setClearButtonEnabled(True)
        self.search.addAction(ui.icon("SystemSearch"), QLineEdit.LeadingPosition)
        self.search.setFixedWidth(230)
        self.search.setAttribute(Qt.WA_MacShowFocusRect, False)
        self.search.textChanged.connect(lambda _t: self._filter_timer.start())
        tb.addWidget(self.search)
        tail = QWidget()
        tail.setFixedWidth(10)
        tb.addWidget(tail)

        # --- основная область: боковая панель | содержимое | сводка
        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.setObjectName("main_splitter")
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setHandleWidth(1)
        self.setCentralWidget(self.splitter)

        self.sidebar = ui.Sidebar()
        self.sidebar.set_smb_available(netshare.is_available())
        self.sidebar.location_chosen.connect(self._choose_location)
        self.sidebar.s3_chosen.connect(self._choose_s3)
        self.sidebar.s3_setup.connect(self.open_connect_s3)
        self.sidebar.smb_connect.connect(self.connect_smb)
        self.sidebar.recent_remove.connect(self._remove_recent)
        self.splitter.addWidget(self.sidebar)

        self.splitter.addWidget(self._build_center())

        self.summary = ui.SummaryPanel()
        self.summary.category_clicked.connect(self._on_category_clicked)
        self.splitter.addWidget(self.summary)
        self.splitter.setStretchFactor(0, 0)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setStretchFactor(2, 0)
        self.splitter.setSizes([210, 820, 290])
        self.act_sidebar.setChecked(True)
        self.act_summary.setChecked(True)

        # --- строка состояния + прогресс
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        self.progress.setMaximumWidth(220)
        self.progress.setTextVisible(False)
        self.count_label = QLabel("Choose a folder to analyze")
        self.statusBar().addWidget(self.count_label, 1)
        self.statusBar().addPermanentWidget(self.progress)
        self.statusBar().setSizeGripEnabled(False)

    def _build_center(self) -> QWidget:
        wrap = QWidget()
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(10, 8, 10, 4)
        lay.setSpacing(6)

        # --- строка расположения
        loc = QHBoxLayout()
        loc.setSpacing(6)
        self.path_label = QLabel("Folder:")
        loc.addWidget(self.path_label)
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(ui.PATH_HINT)
        self.path_edit.setClearButtonEnabled(True)
        self.path_edit.returnPressed.connect(self.start_scan)
        self._fs_completer_model = QFileSystemModel(self)
        self._fs_completer_model.setFilter(QDir.AllDirs | QDir.NoDotAndDotDot | QDir.Drives)
        self._fs_completer_model.setRootPath("")
        self._path_completer = QCompleter(self._fs_completer_model, self)
        self._path_completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.path_edit.setCompleter(self._path_completer)
        loc.addWidget(self.path_edit, 1)
        self.browse_btn = QPushButton("Choose…")
        self.browse_btn.clicked.connect(self.browse_folder)
        loc.addWidget(self.browse_btn)
        self.s3_btn = QPushButton("S3 Connection…")
        self.s3_btn.clicked.connect(self.open_connect_s3)
        self.s3_btn.setVisible(False)
        loc.addWidget(self.s3_btn)
        self.scan_btn = QPushButton("Analyze")
        self.scan_btn.setDefault(True)
        self.scan_btn.clicked.connect(self.start_scan)
        loc.addWidget(self.scan_btn)
        lay.addLayout(loc)

        # --- параметры анализа
        opts = QHBoxLayout()
        opts.setSpacing(14)
        self.recursive_cb = QCheckBox("Include subfolders")
        self.recursive_cb.setChecked(True)
        self.dirs_cb = QCheckBox("Show folders")
        self.dirs_cb.setChecked(True)
        self.authors_cb = QCheckBox("Detect author")
        self.authors_cb.setToolTip(
            "Read the file's Author property (as in Explorer), otherwise the file owner.\n"
            "Slows down scanning, especially on network shares."
            if sys.platform == "win32" else
            "Show the file owner (user account).\n"
            "Slightly slows down scanning, especially on network shares."
        )
        self.incremental_cb = QCheckBox("Incremental (database)")
        self.incremental_cb.setChecked(True)
        self.incremental_cb.setToolTip(
            "Save the result to the database and, on the next analysis, re-read only\n"
            "changed files (unchanged ones come from the database — faster)."
        )
        for cb in (self.recursive_cb, self.dirs_cb, self.authors_cb, self.incremental_cb):
            f = cb.font()
            f.setPointSizeF(max(9.0, f.pointSizeF() - 1))
            cb.setFont(f)
            opts.addWidget(cb)
        opts.addStretch(1)
        lay.addLayout(opts)

        self.filter_box = self._build_filter_box()
        self.filter_box.setVisible(False)
        lay.addWidget(self.filter_box)

        # --- заголовок результата
        head = QHBoxLayout()
        self.result_title = QLabel("")
        tf = self.result_title.font()
        tf.setPointSizeF(tf.pointSizeF() + 1)
        tf.setBold(True)
        self.result_title.setFont(tf)
        self.result_title.setTextInteractionFlags(Qt.TextSelectableByMouse)
        head.addWidget(self.result_title, 1)
        self.expand_btn = QPushButton("Expand All")
        self.expand_btn.clicked.connect(lambda: self.tree.expandAll())
        self.collapse_btn = QPushButton("Collapse All")
        self.collapse_btn.clicked.connect(lambda: self.tree.collapseAll())
        for b in (self.expand_btn, self.collapse_btn):
            b.setVisible(False)
            head.addWidget(b)
        lay.addLayout(head)

        self.stack = QStackedWidget()
        lay.addWidget(self.stack, 1)

        # --- вид «Список» (плоская таблица)
        self.table = QTableView()
        self.table.setModel(self.model)
        self._setup_view(self.table)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(24)
        self.table.doubleClicked.connect(self._open_selected)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setHighlightSections(False)
        self._default_widths(self.table, 300)
        self.stack.addWidget(self.table)

        # --- вид «Папки» (дерево)
        self.tree = QTreeView()
        self.tree.setModel(self.tree_model)
        self._setup_view(self.tree)
        self.tree.setSortingEnabled(True)
        self.tree.setUniformRowHeights(True)
        self.tree.doubleClicked.connect(self._tree_double_clicked)
        self.tree.header().setSectionResizeMode(QHeaderView.Interactive)
        self.tree.header().setStretchLastSection(True)
        self.tree.header().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self._default_widths(self.tree, 360)
        self.stack.addWidget(self.tree)

        # --- пустое состояние
        self.empty = ui.EmptyState(netshare.is_available())
        self.empty.open_clicked.connect(self.browse_folder)
        self.empty.s3_clicked.connect(self.open_connect_s3)
        self.empty.smb_clicked.connect(self.connect_smb)
        self.stack.addWidget(self.empty)
        self.stack.setCurrentWidget(self.empty)
        return wrap

    @staticmethod
    def _default_widths(view, name_width: int) -> None:
        """Компактные колонки, чтобы «Размер» и даты были видны без прокрутки."""
        widths = {COL_NAME: name_width, COL_KIND: 64, COL_EXT: 70, COL_CAT: 118,
                  COL_AUTHOR: 110, COL_SIZE: 92, COL_CREATED: 152, COL_MODIFIED: 152}
        for col, wd in widths.items():
            view.setColumnWidth(col, wd)
        # порядок колонок как в Finder: имя, размер, дата изменения, … (только визуально)
        header = view.header() if isinstance(view, QTreeView) else view.horizontalHeader()
        order = [COL_NAME, COL_SIZE, COL_MODIFIED, COL_CAT, COL_EXT, COL_KIND,
                 COL_AUTHOR, COL_CREATED]
        for pos, col in enumerate(order):
            cur = header.visualIndex(col)
            if cur != pos and cur >= 0:
                header.moveSection(cur, pos)

    def _setup_view(self, view) -> None:
        view.setSelectionMode(QAbstractItemView.ExtendedSelection)
        view.setAlternatingRowColors(True)
        view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        view.setContextMenuPolicy(Qt.CustomContextMenu)
        view.customContextMenuRequested.connect(self._show_menu)
        view.setIconSize(QSize(16, 16))
        view.setFrameShape(QFrame.NoFrame)
        view.setAttribute(Qt.WA_MacShowFocusRect, False)
        view.setTextElideMode(Qt.ElideRight)
        view.addAction(self.act_quicklook)  # пробел — Quick Look (как в Finder)

    def _build_filter_box(self) -> QWidget:
        group = QFrame()
        group.setObjectName("filterBox")
        group.setStyleSheet(
            "#filterBox { border-radius: 8px; background: palette(base);"
            " border: 1px solid palette(midlight); }"
        )
        grid = QGridLayout(group)
        grid.setContentsMargins(12, 8, 12, 8)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(6)

        def lbl(t):
            w = QLabel(t)
            w.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            return w

        self.f_ext = QLineEdit()
        self.f_ext.setPlaceholderText("jpg, png, pdf")
        self.f_category = QComboBox()
        self.f_category.addItem("All")
        self.f_kind = QComboBox()
        self.f_kind.addItems(["All", "File", "Folder"])
        self.f_author = QLineEdit()
        self.f_author.setPlaceholderText("contains…")
        grid.addWidget(lbl("Format:"), 0, 0)
        grid.addWidget(self.f_ext, 0, 1)
        grid.addWidget(lbl("Category:"), 0, 2)
        grid.addWidget(self.f_category, 0, 3)
        grid.addWidget(lbl("Type:"), 0, 4)
        grid.addWidget(self.f_kind, 0, 5)
        grid.addWidget(lbl("Author:"), 0, 6)
        grid.addWidget(self.f_author, 0, 7)

        size_w = QWidget()
        sz = QHBoxLayout(size_w)
        sz.setContentsMargins(0, 0, 0, 0)
        self.f_min_size = QLineEdit()
        self.f_min_size.setPlaceholderText("from")
        self.f_max_size = QLineEdit()
        self.f_max_size.setPlaceholderText("to")
        self.f_size_unit = QComboBox()
        self.f_size_unit.addItems(list(SIZE_UNITS.keys()))
        self.f_size_unit.setCurrentText("MB")
        sz.addWidget(self.f_min_size)
        sz.addWidget(QLabel("–"))
        sz.addWidget(self.f_max_size)
        sz.addWidget(self.f_size_unit)
        grid.addWidget(lbl("Size:"), 1, 0)
        grid.addWidget(size_w, 1, 1, 1, 3)

        date_w = QWidget()
        dl = QHBoxLayout(date_w)
        dl.setContentsMargins(0, 0, 0, 0)
        self.f_date_on = QCheckBox("Modified from")
        self.f_date_from = QDateEdit()
        self.f_date_from.setCalendarPopup(True)
        self.f_date_from.setDisplayFormat("yyyy-MM-dd")
        self.f_date_from.setDate(QDate.currentDate().addMonths(-1))
        self.f_date_from.setEnabled(False)
        self.f_date_to = QDateEdit()
        self.f_date_to.setCalendarPopup(True)
        self.f_date_to.setDisplayFormat("yyyy-MM-dd")
        self.f_date_to.setDate(QDate.currentDate())
        self.f_date_to.setEnabled(False)
        self.f_date_on.toggled.connect(self.f_date_from.setEnabled)
        self.f_date_on.toggled.connect(self.f_date_to.setEnabled)
        dl.addWidget(self.f_date_on)
        dl.addWidget(self.f_date_from)
        dl.addWidget(QLabel("to"))
        dl.addWidget(self.f_date_to)
        dl.addStretch(1)
        grid.addWidget(date_w, 1, 4, 1, 3)

        reset_btn = QPushButton("Reset")
        reset_btn.clicked.connect(self.reset_filters)
        grid.addWidget(reset_btn, 1, 7, alignment=Qt.AlignRight)
        grid.setColumnStretch(1, 2)
        grid.setColumnStretch(7, 2)

        # фильтр применяется сразу при изменении любого поля
        kick = lambda *_: self._filter_timer.start()  # noqa: E731
        for w in (self.f_ext, self.f_author, self.f_min_size, self.f_max_size):
            w.textChanged.connect(kick)
        for w in (self.f_category, self.f_kind, self.f_size_unit):
            w.currentIndexChanged.connect(kick)
        self.f_date_on.toggled.connect(kick)
        self.f_date_from.dateChanged.connect(kick)
        self.f_date_to.dateChanged.connect(kick)
        return group

    # ------------------------------------------------------ состояние окна
    def _restore_state(self) -> None:
        s = self.qsettings
        geo = s.value("geometry")
        if geo is not None:
            self.restoreGeometry(geo)
        spl = s.value("splitter")
        if spl is not None:
            self.splitter.restoreState(spl)
        hdr = s.value("table_header_v2")
        if hdr is not None:
            self.table.horizontalHeader().restoreState(hdr)
        for key, cb in (("recursive", self.recursive_cb), ("dirs", self.dirs_cb),
                        ("authors", self.authors_cb), ("incremental", self.incremental_cb)):
            v = s.value(f"opt/{key}")
            if v is not None:
                cb.setChecked(str(v).lower() in ("true", "1"))
        side = s.value("view/sidebar")
        if side is not None:
            self.act_sidebar.setChecked(str(side).lower() in ("true", "1"))
        summ = s.value("view/summary")
        if summ is not None:
            self.act_summary.setChecked(str(summ).lower() in ("true", "1"))
        self.sidebar.setVisible(self.act_sidebar.isChecked())
        self.summary.setVisible(self.act_summary.isChecked())
        last = s.value("last_path", "")
        if last:
            self.path_edit.setText(str(last))
        self.sidebar.set_recent(self._recent())
        self._refresh_s3_sidebar()

    def _save_state(self) -> None:
        s = self.qsettings
        s.setValue("geometry", self.saveGeometry())
        s.setValue("splitter", self.splitter.saveState())
        s.setValue("table_header_v2", self.table.horizontalHeader().saveState())
        for key, cb in (("recursive", self.recursive_cb), ("dirs", self.dirs_cb),
                        ("authors", self.authors_cb), ("incremental", self.incremental_cb)):
            s.setValue(f"opt/{key}", cb.isChecked())
        s.setValue("view/sidebar", self.act_sidebar.isChecked())
        s.setValue("view/summary", self.act_summary.isChecked())
        if self.mode == "file":
            s.setValue("last_path", self.path_edit.text().strip())

    def _recent(self) -> list[str]:
        v = self.qsettings.value("recent", [])
        if isinstance(v, str):
            v = [v] if v else []
        return [p for p in (v or []) if p]

    def _add_recent(self, path: str) -> None:
        items = [p for p in self._recent() if os.path.normcase(p) != os.path.normcase(path)]
        items.insert(0, path)
        self.qsettings.setValue("recent", items[:MAX_RECENT])
        self.sidebar.set_recent(items[:MAX_RECENT])

    def _remove_recent(self, path: str) -> None:
        items = [p for p in self._recent() if p != path]
        self.qsettings.setValue("recent", items)
        self.sidebar.set_recent(items)

    def _fill_recent_menu(self) -> None:
        self.recent_menu.clear()
        items = self._recent()
        if not items:
            a = self.recent_menu.addAction("No recent folders")
            a.setEnabled(False)
            return
        for p in items:
            self.recent_menu.addAction(p, lambda p=p: self._choose_location(p))
        self.recent_menu.addSeparator()
        self.recent_menu.addAction("Clear List", lambda: (
            self.qsettings.setValue("recent", []), self.sidebar.set_recent([])))

    # ------------------------------------------------------ источник
    def _set_mode(self, mode: str) -> None:
        if mode == self.mode:
            return
        self.mode = mode
        s3 = mode == "s3"
        self.path_label.setText("S3:" if s3 else "Folder:")
        self.path_edit.setReadOnly(s3)
        self.path_edit.setClearButtonEnabled(not s3)
        self.path_edit.setCompleter(None if s3 else self._path_completer)
        self.browse_btn.setVisible(not s3)
        self.s3_btn.setVisible(s3)
        self.recursive_cb.setVisible(not s3)
        self.authors_cb.setVisible(not s3)
        self.dirs_cb.setText("Show folders (prefixes)" if s3 else "Show folders")
        if s3:
            self._refresh_s3_target()
        else:
            self.path_edit.setText(str(self.qsettings.value("last_path", "")))
            self.path_edit.setPlaceholderText(ui.PATH_HINT)

    def _s3_label(self) -> str:
        if not self.s3cfg.bucket:
            return ""
        who = self.s3cfg.endpoint.replace("https://", "").replace("http://", "") or "AWS"
        return f"{self.s3cfg.bucket}" + (f"/{self.s3cfg.prefix}" if self.s3cfg.prefix else "") + f"  ·  {who}"

    def _refresh_s3_sidebar(self) -> None:
        self.sidebar.set_s3(self._s3_label())

    def _refresh_s3_target(self) -> None:
        if self.s3cfg.bucket:
            self.path_edit.setText(self._s3_label())
        else:
            self.path_edit.setText("")
            self.path_edit.setPlaceholderText("click “S3 Connection…”")

    def _choose_location(self, path: str) -> None:
        if self._scanning:
            self.cancel_scan()
        self._set_mode("file")
        self.path_edit.setText(path)
        self.start_scan()

    def _choose_s3(self) -> None:
        if self._scanning:
            self.cancel_scan()
        self._set_mode("s3")
        self.start_scan()

    def open_connect_s3(self) -> None:
        if not s3client.is_available():
            QMessageBox.warning(self, "boto3 is missing", "Install boto3: pip install boto3")
            return
        dlg = S3ConnectDialog(self, self.s3cfg)
        if dlg.exec() == QDialog.Accepted:
            self.s3cfg = dlg.cfg
            self._refresh_s3_sidebar()
            self._set_mode("s3")
            self._refresh_s3_target()
            self.sidebar.select("s3")
            self.start_scan()

    def _toggle_filters(self, on: bool) -> None:
        self.filter_box.setVisible(on)
        if on:
            self.f_ext.setFocus()

    def _set_view(self, tree_mode: bool) -> None:
        if getattr(self, "_suppress_view", False) or not hasattr(self, "stack"):
            return
        if tree_mode and not self._tree_built and self.model.all_count() > 0:
            # ленивое дерево: индексация мгновенная, узлы строятся при раскрытии
            self.tree_model = LazyFileTreeModel(self._last_root, self.model.all_entries())
            self.tree_model.set_criteria(self.model.criteria)
            self.tree.setModel(self.tree_model)
            self._default_widths(self.tree, 360)
            self.tree.expandToDepth(0)
            self._tree_built = True
            self._tree_root = self._last_root
        if self.model.all_count() > 0:
            self.stack.setCurrentWidget(self.tree if tree_mode else self.table)
        self.expand_btn.setVisible(tree_mode and self._tree_built)
        self.collapse_btn.setVisible(tree_mode and self._tree_built)
        self._update_summary()

    def _current_view(self):
        return self.tree if self.act_view_tree.isChecked() else self.table

    # --------------------------------------------------------- drag & drop
    def dragEnterEvent(self, event):  # noqa: N802
        md = event.mimeData()
        if md.hasUrls() and any(u.isLocalFile() and os.path.isdir(u.toLocalFile()) for u in md.urls()):
            event.acceptProposedAction()

    def dropEvent(self, event):  # noqa: N802
        for u in event.mimeData().urls():
            p = u.toLocalFile()
            if u.isLocalFile() and os.path.isdir(p):
                event.acceptProposedAction()
                self._choose_location(os.path.normpath(p))
                return

    # -------------------------------------------------------------- actions
    def browse_folder(self) -> None:
        start = self.path_edit.text().strip() if self.mode == "file" else ""
        if not start or not os.path.isdir(start):
            start = os.path.expanduser("~")
        folder = QFileDialog.getExistingDirectory(self, "Choose a folder to analyze", start)
        if folder:
            self._choose_location(os.path.normpath(folder))

    def connect_smb(self, preset: str = "") -> None:
        if not netshare.is_available():
            QMessageBox.warning(
                self, "Not available",
                "SMB connections with credentials are available on Windows and macOS.\n"
                "Mount the share with your OS tools and enter the mount path.",
            )
            return
        preset = preset if isinstance(preset, str) else ""
        dlg = SmbConnectDialog(self, preset_path=preset or self.path_edit.text().strip())
        if dlg.exec() != QDialog.Accepted:
            return
        self._smb_connections.append((dlg.connected_target, dlg.persistent))
        self.sidebar.rebuild()
        # сразу запускаем анализ подключённого ресурса
        self._choose_location(dlg.scan_path)

    def open_schedule(self) -> None:
        if self.mode == "s3":
            if not self.s3cfg.bucket:
                QMessageBox.warning(self, "Not connected", "Set up the S3 connection first.")
                return
            dlg = ScheduleDialog(
                self, mode="s3", path=self.s3cfg.bucket, db_path=self.db_path,
                include_dirs=self.dirs_cb.isChecked(),
            )
        else:
            dlg = ScheduleDialog(
                self, path=self.path_edit.text().strip().strip('"'),
                db_path=self.db_path,
                recursive=self.recursive_cb.isChecked(),
                include_dirs=self.dirs_cb.isChecked(),
                read_authors=self.authors_cb.isChecked(),
            )
        dlg.exec()

    def open_rules(self) -> None:
        entries = self.model.all_entries()
        if not entries:
            QMessageBox.information(
                self, "No data",
                "Analyze a folder first — rules are applied to its contents.",
            )
            return
        cats = sorted({e.category for e in entries})
        if self.mode == "s3":
            S3RulesDialog(self, entries=entries, cats=cats, cfg=self.s3cfg).exec()
            return
        dlg = RulesDialog(
            self, entries=entries, root=self._last_root, categories=cats,
            recursive=self.recursive_cb.isChecked(),
            include_dirs=self.dirs_cb.isChecked(),
            read_authors=self.authors_cb.isChecked(),
        )
        dlg.exec()

    def open_duplicates(self) -> None:
        entries = self.model.all_entries()
        if not entries:
            QMessageBox.information(self, "No data", "Analyze a folder/bucket first.")
            return
        DuplicatesDialog(self, entries=entries, mode=self.mode,
                         root=self._last_root, s3cfg=self.s3cfg).exec()

    def open_settings(self) -> None:
        SettingsDialog(self).exec()
        # путь к базе мог измениться
        self.db_path = app_settings.get_db_path() or default_db_path()

    def export_visible(self) -> None:
        rows = self.model.visible_entries()
        if not rows:
            QMessageBox.information(self, "No data", "The list is empty — nothing to export.")
            return
        base = os.path.basename(self._last_root.rstrip("/\\")) or "list"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export List", os.path.join(os.path.expanduser("~"), f"{base}.csv"),
            "CSV (*.csv)")
        if not path:
            return
        try:
            rules.export_csv(rows, path)
        except OSError as exc:
            QMessageBox.critical(self, "Error", str(exc))
            return
        self.count_label.setText(f"Exported rows: {len(rows):,} → {path}")

    def _about(self) -> None:
        QMessageBox.about(
            self, f"About {APP_TITLE}",
            f"<h3>{APP_TITLE} {APP_VERSION}</h3>"
            "<p>Analyzes the contents of local disks, SMB network shares and "
            "S3 object storage: list and tree views, filters, summary, "
            "rules, duplicates, scheduling and Telegram notifications.</p>"
            f"<p>Database: <code>{self.db_path}</code></p>",
        )

    def start_scan(self) -> None:
        if self._building_tree or self._scanning:
            return
        import time

        if self.mode == "s3":
            if not self.s3cfg.bucket:
                self.open_connect_s3()
                return
            self._last_root = self.s3cfg.bucket
        else:
            path = os.path.expanduser(self.path_edit.text().strip().strip('"'))
            if not path:
                self.browse_folder()
                return
            if path.lower().startswith("smb://") or (sys.platform != "win32" and path.startswith("//")):
                # сетевой адрес — предлагаем подключить его
                self.connect_smb(path)
                return
            if not os.path.isdir(path):
                QMessageBox.warning(
                    self, "Folder not found",
                    f"The path is not available or is not a folder:\n{path}\n\n"
                    + ("For network shares use the \\\\server\\share\\... format "
                       "and make sure the share is connected." if sys.platform == "win32" else
                       "For a network share click “SMB” (⌘K) or enter an address like "
                       "smb://server/share."),
                )
                return
            self._last_root = path
            self._add_recent(path)
            self.qsettings.setValue("last_path", path)
            self.sidebar.select("path", path)

        self._scanning = True
        self._update_actions()
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.count_label.setText("Listing objects…" if self.mode == "s3" else "Scanning…")
        self.model.set_entries([])
        self.result_title.setText(self._root_title() + " — analyzing…")
        self.stack.setCurrentWidget(self.table)
        # дерево НЕ очищаем здесь — если по БД ничего не изменилось, переиспользуем
        # его в _on_finished (без перестроения)
        self._update_summary()
        self._last_info = {}

        db_path = self.db_path if self.incremental_cb.isChecked() else None
        if self.mode == "s3":
            self.s3_controller.start(
                cfg=self.s3cfg,
                include_dirs=self.dirs_cb.isChecked(),
                db_path=db_path,
                incremental=self.incremental_cb.isChecked(),
                on_progress=self._on_progress,
                on_finished=self._on_finished,
                on_error=self._on_error,
                on_info=self._on_info,
            )
        else:
            self.controller.start(
                root=self._last_root,
                recursive=self.recursive_cb.isChecked(),
                include_dirs=self.dirs_cb.isChecked(),
                on_progress=self._on_progress,
                on_finished=self._on_finished,
                on_error=self._on_error,
                read_authors=self.authors_cb.isChecked(),
                db_path=db_path,
                incremental=self.incremental_cb.isChecked(),
                scan_time=time.time(),
                on_phase=self._on_phase,
                on_total=self._on_total,
                on_info=self._on_info,
            )

    def _root_title(self) -> str:
        if self.mode == "s3":
            return f"S3: {self._s3_label()}"
        return os.path.basename(self._last_root.rstrip("/\\")) or self._last_root

    def cancel_scan(self) -> None:
        self.controller.stop()
        self.s3_controller.stop()
        self._finish_state()
        self.count_label.setText("Stopped.")
        self.result_title.setText(self._root_title() + " — stopped")

    def _on_phase(self, text: str) -> None:
        self.count_label.setText(text)
        if text.startswith("Counting"):
            self.progress.setRange(0, 0)  # неопределённый

    def _on_total(self, total: int) -> None:
        if total > 0:
            self.progress.setRange(0, total)
            self.progress.setValue(0)
        else:
            self.progress.setRange(0, 0)

    def _on_progress(self, done: int, total: int) -> None:
        if total > 0:
            self.progress.setValue(min(done, total))
            pct = int(done * 100 / total)
            self.count_label.setText(
                f"Processed: {done:,} of {total:,} ({pct}%)"
            )
        else:
            self.count_label.setText(f"Processed: {done:,}")

    def _on_info(self, info: dict) -> None:
        self._last_info = info

    def _on_finished(self, entries) -> None:
        self.model.set_entries(entries)
        info = self._last_info or {}
        # если по данным БД ничего не изменилось — переиспользуем уже построенное
        # дерево (не тратим время на перестроение)
        reuse_tree = (
            self._tree_built
            and getattr(self, "_tree_root", None) == self._last_root
            and info.get("had_prior")
            and info.get("changed") == 0
            and info.get("deleted") == 0
        )
        if not reuse_tree:
            # дерево строится по запросу — помечаем устаревшим и очищаем
            self._tree_built = False
            self.tree_model = LazyFileTreeModel("", [])
            self.tree.setModel(self.tree_model)
            # показываем «Список» (без неявного построения дерева)
            self._suppress_view = True
            self.act_view_list.setChecked(True)
            self._suppress_view = False
            self.expand_btn.setVisible(False)
            self.collapse_btn.setVisible(False)
        self._populate_categories(entries)
        self._finish_state()
        self.apply_filters()
        if entries:
            self.stack.setCurrentWidget(self.tree if self.act_view_tree.isChecked() else self.table)
        else:
            self.stack.setCurrentWidget(self.empty)
            self.empty.title.setText("The folder is empty")

        info = self._last_info
        if info and info.get("had_prior"):
            self.count_label.setText(
                f"Done: {info['total']:,} items · "
                + f"new/changed: {info['changed']:,}"
                + f" · deleted: {info['deleted']:,} (incremental, from database)"
            )
        elif info and self.incremental_cb.isChecked():
            self.count_label.setText(
                f"Done: {info['total']:,} items (saved to database)"
            )
        else:
            self.count_label.setText(f"Done: {len(entries):,} items")

    def _on_error(self, message: str) -> None:
        self._finish_state()
        self.count_label.setText("Error.")
        self.result_title.setText(self._root_title() + " — error")
        QMessageBox.critical(self, "Scan Error", message)

    def _finish_state(self) -> None:
        self._scanning = False
        self.progress.setVisible(False)
        self._update_actions()

    def _update_actions(self) -> None:
        has = self.model.all_count() > 0
        self.act_scan.setEnabled(not self._scanning)
        self.scan_btn.setEnabled(not self._scanning)
        self.act_stop.setEnabled(self._scanning)
        for a in (self.act_rules, self.act_dups, self.act_export, self.act_view_tree,
                  self.act_expand, self.act_collapse):
            a.setEnabled(has and not self._scanning)
        self.act_schedule.setEnabled(not self._scanning)
        title = APP_TITLE
        if self._last_root:
            title = f"{self._root_title()} — {APP_TITLE}"
        self.setWindowTitle(title)

    # -------------------------------------------------------------- filters
    def _populate_categories(self, entries) -> None:
        cats = sorted({e.category for e in entries})
        current = self.f_category.currentText()
        self.f_category.blockSignals(True)
        self.f_category.clear()
        self.f_category.addItem("All")
        self.f_category.addItems(cats)
        idx = self.f_category.findText(current)
        self.f_category.setCurrentIndex(idx if idx >= 0 else 0)
        self.f_category.blockSignals(False)

    def _parse_size(self, text: str) -> int | None:
        text = text.strip().replace(",", ".")
        if not text:
            return None
        try:
            value = float(text)
        except ValueError:
            return None
        return int(value * SIZE_UNITS[self.f_size_unit.currentText()])

    def _criteria(self) -> FilterCriteria:
        exts = {
            e.strip().lstrip(".").lower()
            for e in self.f_ext.text().replace(";", ",").split(",")
            if e.strip()
        }
        crit = FilterCriteria(
            name_text=self.search.text().strip(),
            extensions=exts,
            category=self.f_category.currentText() or "All",
            kind=self.f_kind.currentText(),
            author_text=self.f_author.text().strip(),
            min_size=self._parse_size(self.f_min_size.text()),
            max_size=self._parse_size(self.f_max_size.text()),
        )
        if self.f_date_on.isChecked():
            # с начала дня «от» по конец дня «по»
            crit.modified_from = QDateTime(self.f_date_from.date(), QTime(0, 0)).toSecsSinceEpoch()
            crit.modified_to = QDateTime(self.f_date_to.date(), QTime(0, 0)).toSecsSinceEpoch() + 86399
        return crit

    def apply_filters(self) -> None:
        self._filter_timer.stop()
        crit = self._criteria()
        self.model.set_criteria(crit)
        if self._tree_built:
            self.tree_model.set_criteria(crit)
        # индикатор активного фильтра на кнопке (без учёта строки поиска)
        panel_active = not FilterCriteria(**{**crit.__dict__, "name_text": ""}).is_empty()
        self.act_filters.setText("Filters •" if panel_active else "Filters")
        self._update_summary()

    def reset_filters(self) -> None:
        widgets = (self.search, self.f_ext, self.f_category, self.f_kind, self.f_author,
                   self.f_min_size, self.f_max_size, self.f_date_on)
        for w in widgets:
            w.blockSignals(True)
        self.search.clear()
        self.f_ext.clear()
        self.f_category.setCurrentIndex(0)
        self.f_kind.setCurrentIndex(0)
        self.f_author.clear()
        self.f_min_size.clear()
        self.f_max_size.clear()
        self.f_date_on.setChecked(False)
        self.f_date_from.setEnabled(False)
        self.f_date_to.setEnabled(False)
        for w in widgets:
            w.blockSignals(False)
        self.apply_filters()

    # -------------------------------------------------------------- summary
    def _update_summary(self) -> None:
        # разбивка и итоги — по всему набору (чтобы список категорий был стабилен
        # и кликабелен); «Показано» отражает текущий фильтр
        total_size = 0
        files = 0
        dirs = 0
        by_cat_count: dict[str, int] = defaultdict(int)
        by_cat_size: dict[str, int] = defaultdict(int)

        for e in self.model.all_entries():
            if e.is_dir:
                dirs += 1
            else:
                files += 1
                total_size += e.size
            by_cat_count[e.category] += 1
            by_cat_size[e.category] += e.size

        all_rows = self.model.all_count()
        shown = self.model.rowCount()
        self.summary.update_data(shown, all_rows, files, dirs, total_size,
                                 by_cat_count, by_cat_size, self.f_category.currentText())
        if all_rows and not self._scanning:
            sp = lambda n: f"{n:,}"  # noqa: E731
            extra = "" if shown == all_rows else f" · {sp(shown)} shown"
            self.result_title.setText(
                f"{self._root_title()} — {sp(all_rows)} items, {human_size(total_size)}" + extra)
        elif not self._scanning and not self._last_root:
            self.result_title.setText("")

    def _on_category_clicked(self, cat: str) -> None:
        # показываем список, чтобы были видны файлы
        if self.act_view_tree.isChecked():
            self.act_view_list.setChecked(True)
        # тоггл: повторный клик по активной категории (или «Сбросить») — сброс
        if not cat or self.f_category.currentText() == cat:
            self.f_category.setCurrentIndex(0)  # «Все»
        else:
            idx = self.f_category.findText(cat)
            if idx >= 0:
                self.f_category.setCurrentIndex(idx)
        self.apply_filters()

    # ------------------------------------------------- открытие / контекст-меню
    def _entry_at(self, view, index):
        """FileEntry по индексу в заданном представлении."""
        if not index.isValid():
            return None
        if view is self.tree:
            return self.tree_model.data(index.siblingAtColumn(COL_NAME), ENTRY_ROLE)
        return self.model.entry_at_row(index.row())

    def _open_entry(self, entry) -> None:
        """Открыть объект: локальный файл — в программе по умолчанию; S3 — по ссылке."""
        if entry is None:
            return
        if self.mode == "s3":
            if entry.is_dir:
                return
            try:
                url = s3client.presigned_url(self.s3cfg, s3client.key_from_path(entry.path, self.s3cfg.bucket))
                QDesktopServices.openUrl(QUrl(url))
            except Exception as exc:  # noqa: BLE001
                QMessageBox.critical(self, "S3 Error", s3client.err_text(exc))
            return
        if not os.path.exists(entry.path):
            QMessageBox.warning(self, "Not available", f"Item not found:\n{entry.path}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(entry.path))

    def _open_location(self, entry) -> None:
        if entry is None or self.mode == "s3":
            return
        ui.reveal_in_file_manager(entry.path)

    def _open_selected(self, index) -> None:
        self._open_entry(self._entry_at(self.table, index))

    def _tree_double_clicked(self, index) -> None:
        entry = self._entry_at(self.tree, index)
        if entry is not None and not entry.is_dir:
            self._open_entry(entry)

    def _selected_entries(self):
        view = self._current_view()
        out = []
        sel = view.selectionModel()
        if sel is None:
            return out
        for idx in sel.selectedRows(COL_NAME):
            if view is self.tree:
                e = self.tree_model.data(idx.siblingAtColumn(COL_NAME), ENTRY_ROLE)
            else:
                e = self.model.entry_at_row(idx.row())
            if e is not None:
                out.append(e)
        return out

    def _first_selected(self):
        sel = self._selected_entries()
        return sel[0] if sel else None

    def _copy_selected_paths(self) -> None:
        focus = QApplication.focusWidget()
        if isinstance(focus, QLineEdit):  # ⌘C в поле ввода — обычное копирование
            focus.copy()
            return
        ents = self._selected_entries()
        if not ents:
            return
        if self.mode == "s3":
            text = "\n".join(s3client.key_from_path(e.path, self.s3cfg.bucket) for e in ents)
        else:
            text = "\n".join(e.path for e in ents)
        QApplication.clipboard().setText(text)
        self.count_label.setText(f"Paths copied: {len(ents)}")

    def _reveal_selected(self) -> None:
        if self.mode == "s3":
            return
        e = self._first_selected()
        if e is not None:
            ui.reveal_in_file_manager(e.path)

    def _quick_look(self) -> None:
        if self.mode == "s3":
            e = self._first_selected()
            if e is not None and not e.is_dir:
                self._open_entry(e)
            return
        ui.quick_look([e.path for e in self._selected_entries() if os.path.exists(e.path)])

    def _selected_s3_keys(self):
        return [s3client.key_from_path(e.path, self.s3cfg.bucket)
                for e in self._selected_entries() if not e.is_dir]

    def _show_menu(self, pos) -> None:
        view = self.sender()
        entry = self._entry_at(view, view.indexAt(pos))
        if entry is None:
            return
        menu = QMenu(self)
        if self.mode == "s3":
            files = [e for e in self._selected_entries() if not e.is_dir]
            n = len(files) or (0 if entry.is_dir else 1)
            if not entry.is_dir:
                menu.addAction("Open via Link", lambda: self._open_entry(entry))
            if n:
                menu.addAction(f"Download… ({n})", self._s3_download)
                menu.addAction(f"Move Under Prefix… ({n})", self._s3_move)
                menu.addSeparator()
                menu.addAction(f"Delete… ({n})", self._s3_delete)
                menu.addSeparator()
            menu.addAction("Copy Key",
                           lambda: QApplication.clipboard().setText(
                               s3client.key_from_path(entry.path, self.s3cfg.bucket)))
        else:
            menu.addAction("Open Folder" if entry.is_dir else "Open",
                           lambda: self._open_entry(entry))
            if sys.platform == "darwin":
                menu.addAction("Quick Look", self._quick_look)
            menu.addAction(f"Show in {ui.FILE_MANAGER}", lambda: self._open_location(entry))
            menu.addSeparator()
            menu.addAction("Copy Path", self._copy_selected_paths)
            if entry.is_dir:
                menu.addAction("Analyze This Folder",
                               lambda: self._choose_location(entry.path))
        if not menu.isEmpty():
            menu.exec(view.viewport().mapToGlobal(pos))

    # ---- действия S3
    def _s3_keys_or_warn(self):
        keys = self._selected_s3_keys()
        if not keys:
            QMessageBox.information(self, "Nothing selected", "Select objects (files) in the list.")
        return keys

    def _s3_download(self) -> None:
        keys = self._s3_keys_or_warn()
        if not keys:
            return
        dest = QFileDialog.getExistingDirectory(self, "Download to Folder",
                                                os.path.expanduser("~/Downloads"))
        if not dest:
            return
        self.setCursor(Qt.WaitCursor)
        ok, errors = s3client.download_keys(self.s3cfg, keys, dest)
        self.unsetCursor()
        msg = f"Downloaded: {ok} of {len(keys)}."
        if errors:
            msg += "\nErrors:\n" + "\n".join(errors[:5])
        QMessageBox.information(self, "Download", msg)

    def _s3_move(self) -> None:
        keys = self._s3_keys_or_warn()
        if not keys:
            return
        prefix, ok = QInputDialog.getText(self, "Move Under Prefix",
                                          "Target prefix (e.g. archive/2025):")
        if not ok or not prefix.strip():
            return
        if QMessageBox.question(self, "Confirm",
                                f"Move {len(keys)} objects under “{prefix.strip()}”?",
                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        self.setCursor(Qt.WaitCursor)
        moved, _f, errors = s3client.move_to_prefix(self.s3cfg, keys, prefix.strip())
        self.unsetCursor()
        msg = f"Moved: {moved} of {len(keys)}."
        if errors:
            msg += "\nErrors:\n" + "\n".join(errors[:5])
        QMessageBox.information(self, "Move", msg)
        self.start_scan()

    def _s3_delete(self) -> None:
        keys = self._s3_keys_or_warn()
        if not keys:
            return
        if QMessageBox.warning(self, "Delete",
                               f"Permanently delete {len(keys)} objects from “{self.s3cfg.bucket}”?",
                               QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        self.setCursor(Qt.WaitCursor)
        deleted, errors = s3client.delete_keys(self.s3cfg, keys)
        self.unsetCursor()
        msg = f"Deleted: {deleted} of {len(keys)}."
        if errors:
            msg += "\nErrors:\n" + "\n".join(errors[:5])
        QMessageBox.information(self, "Delete", msg)
        self.start_scan()

    def closeEvent(self, event):  # noqa: N802
        self._save_state()
        self.controller.stop()
        self.s3_controller.stop()
        # отключаем временные (не «запомненные») SMB-подключения этой сессии
        for target, persistent in self._smb_connections:
            if not persistent and target:
                netshare.disconnect(target, force=True)
        super().closeEvent(event)


class _DedupWorker(QObject):
    progress = Signal(int, int)
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, entries, fields):
        super().__init__()
        self.entries = entries
        self.fields = fields
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            groups = dedup.find_duplicates(
                self.entries, self.fields,
                cancel=lambda: self._cancelled,
                on_progress=lambda d, t: self.progress.emit(d, t),
            )
            self.finished.emit(groups)
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))


class _DedupController:
    def __init__(self):
        self.thread = None
        self.worker = None

    def start(self, entries, fields, on_progress, on_finished, on_error):
        self.stop()
        self.thread = QThread()
        self.worker = _DedupWorker(entries, fields)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(on_progress)
        self.worker.finished.connect(on_finished)
        self.worker.error.connect(on_error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.error.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(self._cleanup)
        self.thread.start()

    def _cleanup(self):
        self.thread = None
        self.worker = None

    def stop(self):
        if self.worker is not None:
            self.worker.cancel()
            self.worker.blockSignals(True)
        t = self.thread
        if t is not None:
            t.quit()
            if QThread.currentThread() is not t:
                t.wait(3000)
        self.thread = None
        self.worker = None


class DuplicatesDialog(QDialog):
    """Поиск дубликатов по выбранным полям + перенос дублей в папку."""

    def __init__(self, parent=None, entries=None, mode="file", root="", s3cfg=None):
        super().__init__(parent)
        self.setWindowTitle("Find Duplicates")
        self.resize(840, 640)
        self.entries = entries or []
        self.mode = mode
        self.root = root or ""
        self.s3cfg = s3cfg
        self.controller = _DedupController()
        self.groups = []

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Compare by (a duplicate is a file where all checked fields match):"))
        frow = QHBoxLayout()
        self.field_cbs = {}
        for key, label in dedup.FIELDS:
            cb = QCheckBox(label)
            if key == "size":
                cb.setChecked(True)
            if key == "hash" and mode == "s3":
                cb.setEnabled(False)
                cb.setToolTip("Hash comparison is not available for S3 (would require downloading)")
            self.field_cbs[key] = cb
            frow.addWidget(cb)
        frow.addStretch(1)
        layout.addLayout(frow)

        brow = QHBoxLayout()
        self.find_btn = QPushButton("Find Duplicates")
        self.find_btn.setDefault(True)
        self.find_btn.clicked.connect(self._find)
        self.cancel_btn = QPushButton("Stop")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._stop)
        brow.addWidget(self.find_btn)
        brow.addWidget(self.cancel_btn)
        brow.addStretch(1)
        layout.addLayout(brow)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        self.summary = QLabel("—")
        layout.addWidget(self.summary)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(2)
        self.tree.setHeaderLabels(["File / group", "Size"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        layout.addWidget(self.tree, 1)

        act = QGroupBox("Action: move duplicates (the oldest file in each group is kept)")
        al = QHBoxLayout(act)
        al.addWidget(QLabel("To:"))
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("prefix, e.g. duplicates/" if mode == "s3"
                                            else ui.TARGET_HINT.replace("Quarantine", "Duplicates"))
        al.addWidget(self.target_edit, 1)
        if mode != "s3":
            b = QPushButton("Browse…")
            b.clicked.connect(self._browse)
            al.addWidget(b)
        self.move_btn = QPushButton("Move Duplicates")
        self.move_btn.setEnabled(False)
        self.move_btn.clicked.connect(self._move)
        al.addWidget(self.move_btn)
        layout.addWidget(act)

        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        layout.addWidget(close, alignment=Qt.AlignRight)

    def _selected_fields(self):
        return {k for k, cb in self.field_cbs.items() if cb.isChecked() and cb.isEnabled()}

    def _find(self):
        fields = self._selected_fields()
        if not fields:
            QMessageBox.warning(self, "Fields", "Check at least one field to compare.")
            return
        self.find_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.move_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.summary.setText("Searching…")
        self.tree.clear()
        self.controller.start(self.entries, fields, self._on_progress,
                              self._on_found, self._on_error)

    def _stop(self):
        self.controller.stop()
        self._reset_state()
        self.summary.setText("Stopped.")

    def _on_progress(self, done, total):
        if total > 0:
            self.progress.setRange(0, total)
            self.progress.setValue(done)
            self.summary.setText(f"Hashing: {done:,} of {total:,}…")

    def _on_found(self, groups):
        self.groups = groups
        self._reset_state()
        self._fill(groups)

    def _on_error(self, msg):
        self._reset_state()
        QMessageBox.critical(self, "Error", msg)

    def _reset_state(self):
        self.find_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress.setVisible(False)

    def _fill(self, groups):
        self.tree.clear()
        wasted = dedup.wasted_bytes(groups)
        dup_files = sum(len(g) - 1 for g in groups)
        self.summary.setText(
            f"Groups: {len(groups):,} · extra files: {dup_files:,} · "
            f"can be freed: {human_size(wasted)}"
        )
        for g in groups:
            keep = dedup._kept_first(g)
            top = QTreeWidgetItem(
                self.tree, [f"Group of {len(g)} · {g[0].name}",
                            human_size(sum(e.size for e in g))]
            )
            for e in g:
                mark = "   ← keep" if e is keep else ""
                QTreeWidgetItem(top, [e.path + mark, human_size(e.size)])
        self.move_btn.setEnabled(bool(groups))

    def _browse(self):
        start = self.target_edit.text().strip() or os.path.expanduser("~")
        d = QFileDialog.getExistingDirectory(self, "Folder for Duplicates", start)
        if d:
            self.target_edit.setText(os.path.normpath(d))

    def _move(self):
        if not self.groups:
            return
        target = self.target_edit.text().strip().strip('"')
        if self.mode != "s3":
            target = os.path.expanduser(target)
        if not target:
            QMessageBox.warning(self, "Destination", "Specify the destination folder/prefix.")
            return
        dups = dedup.duplicates_to_move(self.groups)
        if not dups:
            QMessageBox.information(self, "No duplicates", "Nothing to move.")
            return
        if self.mode != "s3" and _is_inside(target, self.root):
            QMessageBox.warning(self, "Not allowed",
                                "The destination folder must not be inside the analyzed folder.")
            return
        total = sum(e.size for e in dups)
        if QMessageBox.question(
            self, "Confirm",
            f"Move {len(dups)} duplicate files ({human_size(total)}) to:\n{target}\n"
            "(the oldest file in each group is kept)\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        self.setCursor(Qt.WaitCursor)
        if self.mode == "s3":
            keys = [s3client.key_from_path(e.path, self.s3cfg.bucket) for e in dups]
            moved, _f, errors = s3client.move_to_prefix(self.s3cfg, keys, target.strip("/"))
        else:
            moved, _f, errors = rules.execute_move(dups, self.root, target)
        self.unsetCursor()
        msg = f"Moved: {moved} of {len(dups)}."
        if errors:
            msg += "\nErrors:\n" + "\n".join(errors[:5])
        QMessageBox.information(self, "Done", msg)
        self.groups = []
        self.tree.clear()
        self.move_btn.setEnabled(False)
        self.summary.setText("Done. Run the analysis again to refresh the list.")

    def closeEvent(self, event):  # noqa: N802
        self.controller.stop()
        super().closeEvent(event)


class S3ConnectDialog(QDialog):
    """Подключение к S3 (AWS или S3-совместимое)."""

    def __init__(self, parent=None, cfg=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("S3 Connection")
        self.setMinimumWidth(520)
        cfg = cfg or s3client.S3Config()
        self.cfg = cfg
        form = _form()
        self.endpoint = QLineEdit(cfg.endpoint)
        self.endpoint.setPlaceholderText("leave empty for AWS; otherwise https://minio:9000")
        form.addRow("Endpoint:", self.endpoint)
        self.region = QLineEdit(cfg.region)
        self.region.setPlaceholderText("e.g. us-east-1")
        form.addRow("Region:", self.region)
        self.access = QLineEdit(cfg.access_key)
        form.addRow("Access Key:", self.access)
        self.secret = QLineEdit(cfg.secret_key)
        self.secret.setEchoMode(QLineEdit.Password)
        show = QCheckBox("Show")
        show.toggled.connect(lambda on: self.secret.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password))
        srow = QHBoxLayout()
        srow.addWidget(self.secret, 1)
        srow.addWidget(show)
        sw = QWidget()
        sw.setLayout(srow)
        form.addRow("Secret Key:", sw)
        self.bucket = QLineEdit(cfg.bucket)
        form.addRow("Bucket:", self.bucket)
        self.prefix = QLineEdit(cfg.prefix)
        self.prefix.setPlaceholderText("optional: analyze only this prefix")
        form.addRow("Prefix:", self.prefix)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        form.addRow("", self.status)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        row = QHBoxLayout()
        test_btn = QPushButton("Test")
        test_btn.clicked.connect(self._test)
        save_btn = QPushButton("Save and Close")
        save_btn.clicked.connect(self._save)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        row.addWidget(test_btn)
        row.addStretch(1)
        row.addWidget(save_btn)
        row.addWidget(cancel)
        layout.addLayout(row)

    def _collect(self):
        return s3client.S3Config(
            endpoint=self.endpoint.text().strip(), region=self.region.text().strip(),
            access_key=self.access.text().strip(), secret_key=self.secret.text(),
            bucket=self.bucket.text().strip(), prefix=self.prefix.text().strip(),
        )

    def _test(self) -> None:
        self.setCursor(Qt.WaitCursor)
        ok, msg = s3client.test_connection(self._collect())
        self.unsetCursor()
        self.status.setText(("Success: " if ok else "Error: ") + msg)
        self.status.setStyleSheet("color:#27ae60;" if ok else "color:#c0392b;")

    def _save(self) -> None:
        cfg = self._collect()
        if not cfg.bucket:
            self.status.setText("Specify a bucket.")
            return
        self.cfg = cfg
        app_settings.set_s3({
            "endpoint": cfg.endpoint, "region": cfg.region, "access_key": cfg.access_key,
            "secret_key": cfg.secret_key, "bucket": cfg.bucket, "prefix": cfg.prefix,
        })
        self.accept()


class S3RulesDialog(QDialog):
    """Правила для S3: условия → действие (удалить / переместить под префикс)."""

    def __init__(self, parent=None, entries=None, cats=None, cfg=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("S3 Rules: condition → action")
        self.resize(840, 620)
        self.entries = entries or []
        self.cats = cats or []
        self.cfg = cfg
        self.matched = []
        self._rows = []

        layout = QVBoxLayout(self)
        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Rule name:"))
        self.name_edit = QLineEdit(_safe_task_name("rule_" + (cfg.bucket if cfg else "s3")))
        name_row.addWidget(self.name_edit, 1)
        layout.addLayout(name_row)

        layout.addWidget(QLabel("Conditions (combined with AND):"))
        self._cond_area = QVBoxLayout()
        wrap = QWidget()
        wrap.setLayout(self._cond_area)
        layout.addWidget(wrap)
        add_btn = QPushButton("+ Add Condition")
        add_btn.setAutoDefault(False)
        add_btn.clicked.connect(self._add_row)
        layout.addWidget(add_btn, alignment=Qt.AlignLeft)

        act = QGroupBox("Action")
        act_lay = QHBoxLayout(act)
        act_lay.addWidget(QLabel("Action:"))
        self.action_combo = QComboBox()
        self.action_combo.addItems(["Delete", "Move Under Prefix"])
        self.action_combo.currentIndexChanged.connect(self._upd_action)
        act_lay.addWidget(self.action_combo)
        self.prefix_edit = QLineEdit()
        self.prefix_edit.setPlaceholderText("target prefix, e.g. archive/2025")
        act_lay.addWidget(self.prefix_edit, 1)
        layout.addWidget(act)

        btns = QHBoxLayout()
        find_btn = QPushButton("Find Matches")
        find_btn.setDefault(True)
        find_btn.clicked.connect(self._find)
        self.run_btn = QPushButton("Run")
        self.run_btn.clicked.connect(self._run)
        self.run_btn.setEnabled(False)
        btns.addWidget(find_btn)
        btns.addStretch(1)
        btns.addWidget(self.run_btn)
        layout.addLayout(btns)

        self.summary = QLabel("—")
        layout.addWidget(self.summary)
        self.preview = QTableWidget(0, 4)
        self.preview.setHorizontalHeaderLabels(["Name", "Size", "Category", "Key"])
        self.preview.horizontalHeader().setStretchLastSection(True)
        self.preview.setEditTriggers(QTableWidget.NoEditTriggers)
        self.preview.verticalHeader().setVisible(False)
        layout.addWidget(self.preview, 1)

        # --- автоархивация по расписанию
        sched = QGroupBox("Scheduled auto-archiving (no confirmation)")
        sl = QHBoxLayout(sched)
        sl.addWidget(QLabel("Frequency:"))
        self.sched_freq = QComboBox()
        self.sched_freq.addItems(["Daily", "Every N hours", "Every N minutes"])
        self.sched_freq.currentIndexChanged.connect(self._upd_sched)
        sl.addWidget(self.sched_freq)
        sl.addWidget(QLabel("N:"))
        self.sched_interval = QSpinBox()
        self.sched_interval.setRange(1, 999)
        self.sched_interval.setValue(6)
        sl.addWidget(self.sched_interval)
        sl.addWidget(QLabel("Time:"))
        self.sched_time = QTimeEdit(QTime(3, 0))
        self.sched_time.setDisplayFormat("HH:mm")
        sl.addWidget(self.sched_time)
        self.sched_system_cb = QCheckBox("as a service (SYSTEM)")
        self.sched_system_cb.setVisible(sys.platform == "win32")
        sl.addWidget(self.sched_system_cb)
        sl.addStretch(1)
        self.sched_btn = QPushButton("Create Auto-Archiving Task")
        self.sched_btn.clicked.connect(self._schedule)
        sl.addWidget(self.sched_btn)
        layout.addWidget(sched)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)
        self._add_row()
        self._upd_action()
        self._upd_sched()

    def _add_row(self):
        row = ConditionRow(self.cats, self._remove_row)
        self._rows.append(row)
        self._cond_area.addWidget(row)

    def _remove_row(self, row):
        if len(self._rows) <= 1:
            return
        self._rows.remove(row)
        row.setParent(None)
        row.deleteLater()

    def _upd_action(self):
        self.prefix_edit.setEnabled(self.action_combo.currentIndex() == 1)

    def _conditions(self):
        conds = []
        for r in self._rows:
            c = r.condition()
            if c.kind in ("ext", "category", "name", "author") and not c.text:
                continue
            conds.append(c)
        return conds

    def _find(self):
        import time
        conds = self._conditions()
        if not conds:
            self.summary.setText("Add at least one condition.")
            return
        self.matched = rules.evaluate(self.entries, conds, time.time(), include_dirs=False)
        total = sum(e.size for e in self.matched)
        self.summary.setText(f"Matched objects: {len(self.matched)} · total: {human_size(total)}")
        self.preview.setRowCount(len(self.matched))
        for i, e in enumerate(self.matched):
            self.preview.setItem(i, 0, QTableWidgetItem(e.name))
            it = QTableWidgetItem(human_size(e.size))
            it.setTextAlignment(int(Qt.AlignRight | Qt.AlignVCenter))
            self.preview.setItem(i, 1, it)
            self.preview.setItem(i, 2, QTableWidgetItem(e.category))
            self.preview.setItem(i, 3, QTableWidgetItem(s3client.key_from_path(e.path, self.cfg.bucket)))
        self.preview.resizeColumnsToContents()
        self.run_btn.setEnabled(bool(self.matched))

    def _run(self):
        if not self.matched:
            return
        keys = [s3client.key_from_path(e.path, self.cfg.bucket) for e in self.matched]
        move = self.action_combo.currentIndex() == 1
        if move:
            target = self.prefix_edit.text().strip().strip("/")
            if not target:
                QMessageBox.warning(self, "Prefix", "Specify the target prefix.")
                return
            q = f"Move {len(keys)} objects under “{target}”?"
        else:
            q = f"Permanently delete {len(keys)} objects?"
        if QMessageBox.warning(self, "Confirm", q,
                               QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        self.setCursor(Qt.WaitCursor)
        if move:
            done, _f, errors = s3client.move_to_prefix(self.cfg, keys, target)
            word = "Moved"
        else:
            done, errors = s3client.delete_keys(self.cfg, keys)
            word = "Deleted"
        self.unsetCursor()
        msg = f"{word}: {done} of {len(keys)}."
        if errors:
            msg += "\nErrors:\n" + "\n".join(errors[:5])
        QMessageBox.information(self, "Done", msg)

    def _upd_sched(self):
        idx = self.sched_freq.currentIndex()
        self.sched_interval.setEnabled(idx in (1, 2))
        self.sched_time.setEnabled(idx in (0, 1))

    def _schedule(self):
        name = self.name_edit.text().strip()
        conds = self._conditions()
        move = self.action_combo.currentIndex() == 1
        target = self.prefix_edit.text().strip().strip("/")
        if not name:
            QMessageBox.warning(self, "Name", "Specify the rule name.")
            return
        if not conds:
            QMessageBox.warning(self, "Conditions", "Add at least one condition.")
            return
        if move and not target:
            QMessageBox.warning(self, "Prefix", "Specify the target prefix.")
            return
        act_word = f"move under “{target}”" if move else "DELETE"
        if QMessageBox.warning(
            self, "S3 Auto-Archiving",
            f"The task will {act_word} objects ON A SCHEDULE, without confirmation, "
            f"in bucket “{self.cfg.bucket}” that match the conditions.\n\nCreate the task?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        rule = rules.Rule(
            name=name, root=self.cfg.bucket, conditions=conds,
            target=(target if move else ""), action=("move" if move else "delete"),
            source="s3",
            s3={"endpoint": self.cfg.endpoint, "region": self.cfg.region,
                "access_key": self.cfg.access_key, "secret_key": self.cfg.secret_key,
                "bucket": self.cfg.bucket, "prefix": self.cfg.prefix},
        )
        rules.save_rule(rule)
        kind = {0: "DAILY", 1: "HOURLY", 2: "MINUTE"}[self.sched_freq.currentIndex()]
        ok, msg = schedule_task.create_rule_task(
            task_name=name, rule_name=name, kind=kind,
            time_str=self.sched_time.time().toString("HH:mm"),
            interval=self.sched_interval.value(),
            run_as_system=self.sched_system_cb.isChecked(),
        )
        if ok:
            QMessageBox.information(
                self, "Done",
                f"S3 auto-archiving task “{name}” created.\n"
                "Manage it with the “Schedule…” button.",
            )
        else:
            QMessageBox.critical(self, "Error", f"Could not create the task:\n{msg}")


class SmbConnectDialog(QDialog):
    """Диалог ввода учётных данных для подключения к сетевому хранилищу."""

    def __init__(self, parent=None, preset_path: str = "") -> None:
        super().__init__(parent)
        self.setWindowTitle("Connect to Network Share (SMB)")
        self.setMinimumWidth(480)
        mac = sys.platform == "darwin"

        self.scan_path: str = ""
        self.connected_target: str = ""
        self.persistent: bool = False

        form = _form()
        p = (preset_path or "").strip()
        looks_smb = p.startswith("\\\\") or p.lower().startswith("smb://") or (mac and p.startswith("//"))
        self.path_edit = QLineEdit(p if looks_smb else "")
        self.path_edit.setPlaceholderText(ui.SMB_HINT)
        form.addRow("Network path:", self.path_edit)

        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText(
            "user_name  (DOMAIN;user also works)" if mac else r"user_name  (DOMAIN\user also works)")
        form.addRow("User name:", self.user_edit)

        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        show_cb = QCheckBox("Show")
        show_cb.toggled.connect(
            lambda on: self.pass_edit.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)
        )
        pass_row = QHBoxLayout()
        pass_row.setContentsMargins(0, 0, 0, 0)
        pass_row.addWidget(self.pass_edit, 1)
        pass_row.addWidget(show_cb)
        pass_wrap = QWidget()
        pass_wrap.setLayout(pass_row)
        form.addRow("Password:", pass_wrap)

        self.drive_combo = QComboBox()
        self.drive_combo.addItem("(no drive letter)")
        self.drive_combo.addItems(netshare.free_drive_letters())
        if netshare.supports_drive_letters():
            form.addRow("Map to drive:", self.drive_combo)
        else:
            self.drive_combo.setVisible(False)

        self.persistent_cb = QCheckBox(
            "Keep connected after quitting the app" if mac else
            "Remember the connection (across Windows restarts)")
        form.addRow("", self.persistent_cb)

        if mac:
            note = QLabel("The app never saves the password. Leave it empty and macOS "
                          "will ask for it and offer to save it in the Keychain. "
                          "The share is mounted under /Volumes, like Finder’s Connect to Server (⌘K).")
            note.setWordWrap(True)
            note.setForegroundRole(QPalette.PlaceholderText)
            form.addRow("", note)

        self.hint = QLabel("")
        self.hint.setWordWrap(True)
        self.hint.setStyleSheet("color:#c0392b;")
        form.addRow("", self.hint)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.button(QDialogButtonBox.Ok).setText("Connect")
        self.buttons.button(QDialogButtonBox.Cancel).setText("Cancel")
        self.buttons.accepted.connect(self._try_connect)
        self.buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.buttons)

    def _try_connect(self) -> None:
        import threading

        remote = self.path_edit.text().strip().strip('"')
        if netshare.parse_smb(remote) is None if sys.platform == "darwin" else \
                not remote.replace("/", "\\").startswith("\\\\"):
            self.hint.setText("Enter a path in the format " + ui.SMB_HINT.split("  ")[0])
            return

        drive = None
        if self.drive_combo.currentIndex() > 0:
            drive = self.drive_combo.currentText()

        # подключение — в фоне, чтобы окно не «зависало» на медленной сети
        self.hint.setStyleSheet("")
        self.hint.setText("Connecting…")
        self.buttons.setEnabled(False)
        self.setCursor(Qt.BusyCursor)
        res: dict = {}
        args = dict(remote=remote, username=self.user_edit.text().strip(),
                    password=self.pass_edit.text(), drive_letter=drive,
                    persistent=self.persistent_cb.isChecked())
        t = threading.Thread(target=lambda: res.update(r=netshare.connect(**args)), daemon=True)
        t.start()
        loop = QEventLoop()
        timer = QTimer()
        timer.timeout.connect(lambda: None if t.is_alive() else loop.quit())
        timer.start(100)
        loop.exec()
        timer.stop()
        self.unsetCursor()
        self.buttons.setEnabled(True)
        self.hint.setStyleSheet("color:#c0392b;")
        ok, message, scan_path = res.get("r", (False, "No response.", None))

        if not ok:
            self.hint.setText(message)
            return

        self.scan_path = scan_path
        self.persistent = self.persistent_cb.isChecked()
        self.connected_target = netshare.connection_target(remote, drive, scan_path)
        self.accept()


class TelegramDialog(QDialog):
    """Настройка бота и чата Telegram для уведомлений."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Telegram Notifications")
        self.setMinimumWidth(480)
        token, chat = app_settings.get_telegram()

        form = _form()
        self.token_edit = QLineEdit(token)
        self.token_edit.setEchoMode(QLineEdit.Password)
        show = QCheckBox("Show")
        show.toggled.connect(
            lambda on: self.token_edit.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)
        )
        trow = QHBoxLayout()
        trow.addWidget(self.token_edit, 1)
        trow.addWidget(show)
        tw = QWidget()
        tw.setLayout(trow)
        form.addRow("Bot token:", tw)

        self.chat_edit = QLineEdit(chat)
        self.chat_edit.setPlaceholderText("e.g. 123456789 or @username")
        form.addRow("Chat ID:", self.chat_edit)

        hint = QLabel(
            "Create a bot with @BotFather and paste its token. You can get your chat ID from "
            "@userinfobot (or open https://api.telegram.org/bot<token>/getUpdates "
            "after sending the bot a message)."
        )
        hint.setWordWrap(True)
        hint.setOpenExternalLinks(True)
        form.addRow("", hint)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        form.addRow("", self.status)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        row = QHBoxLayout()
        test_btn = QPushButton("Send Test")
        test_btn.clicked.connect(self._test)
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self._save)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        row.addWidget(test_btn)
        row.addStretch(1)
        row.addWidget(save_btn)
        row.addWidget(close_btn)
        layout.addLayout(row)

    def _test(self) -> None:
        self.setCursor(Qt.WaitCursor)
        ok, msg = notify.send_telegram(
            self.token_edit.text().strip(), self.chat_edit.text().strip(),
            "✅ Test notification — Storage Analyzer",
        )
        self.unsetCursor()
        self.status.setText(("Success: " if ok else "Error: ") + msg)
        self.status.setStyleSheet("color:#27ae60;" if ok else "color:#c0392b;")

    def _save(self) -> None:
        app_settings.set_telegram(self.token_edit.text().strip(), self.chat_edit.text().strip())
        self.status.setText("Saved.")
        self.status.setStyleSheet("color:#27ae60;")


class SettingsDialog(QDialog):
    """Настройки: папка базы данных + доступ к настройкам Telegram."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(580)

        layout = QVBoxLayout(self)
        form = _form()
        layout.addLayout(form)

        current = app_settings.get_db_path() or default_db_path()
        db_row = QHBoxLayout()
        self.db_edit = QLineEdit(os.path.dirname(current))
        db_row.addWidget(self.db_edit, 1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse_db)
        db_row.addWidget(browse)
        db_wrap = QWidget()
        db_wrap.setLayout(db_row)
        form.addRow("Database folder:", db_wrap)

        info = QLabel(f"The database file is analyzer.db in the chosen folder.\nCurrent: {current}")
        info.setWordWrap(True)
        form.addRow("", info)

        tg_btn = QPushButton("Configure Telegram…")
        tg_btn.clicked.connect(lambda: TelegramDialog(self).exec())
        form.addRow("Notifications:", tg_btn)

        # --- управление базой данных
        self._cur_db = current
        self.db_size_lbl = QLabel("")
        form.addRow("Database size:", self.db_size_lbl)

        self.scans_tree = QTreeWidget()
        self.scans_tree.setColumnCount(2)
        self.scans_tree.setHeaderLabels(["Snapshot (folder/bucket)", "Items"])
        self.scans_tree.setRootIsDecorated(False)
        self.scans_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        form.addRow("Snapshots:", self.scans_tree)

        db_btns = QHBoxLayout()
        vacuum_btn = QPushButton("Compact Database (VACUUM)")
        vacuum_btn.clicked.connect(self._vacuum)
        del_snap_btn = QPushButton("Delete Selected Snapshot")
        del_snap_btn.clicked.connect(self._delete_snapshot)
        db_btns.addWidget(vacuum_btn)
        db_btns.addWidget(del_snap_btn)
        db_btns.addStretch(1)
        form.addRow("", self._wrap(db_btns))

        self.status = QLabel("")
        self.status.setWordWrap(True)
        form.addRow("", self.status)

        self._refresh_db_info()

        row = QHBoxLayout()
        save = QPushButton("Save")
        save.setDefault(True)
        save.clicked.connect(self._save)
        close = QPushButton("Close")
        close.clicked.connect(self.reject)
        row.addStretch(1)
        row.addWidget(save)
        row.addWidget(close)
        layout.addLayout(row)

    def _browse_db(self) -> None:
        start = self.db_edit.text().strip() or os.path.expanduser("~")
        d = QFileDialog.getExistingDirectory(self, "Database Folder", start)
        if d:
            self.db_edit.setText(os.path.normpath(d))

    @staticmethod
    def _wrap(layout) -> QWidget:
        w = QWidget()
        w.setLayout(layout)
        return w

    def _refresh_db_info(self) -> None:
        size = db_size_bytes(self._cur_db)
        self.db_size_lbl.setText(human_size(size) if size else "—")
        self.scans_tree.clear()
        try:
            db = FileDatabase(self._cur_db)
            for root_orig, _last, count in db.list_scans():
                QTreeWidgetItem(self.scans_tree, [root_orig, f"{count:,}"])
            db.close()
        except Exception:  # noqa: BLE001
            pass

    def _vacuum(self) -> None:
        self.setCursor(Qt.WaitCursor)
        try:
            db = FileDatabase(self._cur_db)
            before = db.size_bytes()
            db.vacuum()
            after = db.size_bytes()
            db.close()
            self.status.setText(f"Database compacted: {human_size(before)} → {human_size(after)}")
            self.status.setStyleSheet("color:#27ae60;")
        except Exception as exc:  # noqa: BLE001
            self.status.setText(f"Could not compact: {exc}")
            self.status.setStyleSheet("color:#c0392b;")
        self.unsetCursor()
        self._refresh_db_info()

    def _delete_snapshot(self) -> None:
        item = self.scans_tree.currentItem()
        if item is None:
            self.status.setText("Select a snapshot in the list.")
            return
        root = item.text(0)
        if QMessageBox.question(
            self, "Delete Snapshot",
            f"Delete this snapshot from the database:\n{root}?\n(files on disk/in storage are not touched)",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        try:
            db = FileDatabase(self._cur_db)
            db.delete_scan(root)
            db.close()
            self.status.setText("Snapshot deleted. Click “Compact Database” to free the space.")
            self.status.setStyleSheet("color:#27ae60;")
        except Exception as exc:  # noqa: BLE001
            self.status.setText(f"Error: {exc}")
            self.status.setStyleSheet("color:#c0392b;")
        self._refresh_db_info()

    def _save(self) -> None:
        folder = self.db_edit.text().strip().strip('"')
        if not folder:
            self.status.setText("Specify a folder.")
            return
        try:
            os.makedirs(folder, exist_ok=True)
        except OSError as exc:
            self.status.setText(f"Folder not available: {exc}")
            return
        app_settings.set_db_path(os.path.join(folder, "analyzer.db"))
        self.status.setText("Saved. The database path is updated (applies to the next analysis).")
        self.status.setStyleSheet("color:#27ae60;")


class ConditionRow(QWidget):
    """Одна строка условия в диалоге правил (виджеты меняются под тип условия)."""

    def __init__(self, categories, on_remove) -> None:
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)

        self.type_combo = QComboBox()
        for label, key in rules.CONDITION_TYPES:
            self.type_combo.addItem(label, key)

        self.op_combo = QComboBox()
        self.number = QDoubleSpinBox()
        self.number.setRange(0, 1_000_000_000)
        self.number.setDecimals(2)
        self.number.setValue(6)
        self.unit_combo = QComboBox()
        self.date_combo = QComboBox()
        for label, key in rules.AGE_DATE_FIELDS:
            self.date_combo.addItem(label, key)
        self.text_edit = QLineEdit()
        self.cat_combo = QComboBox()
        self.cat_combo.addItems(categories)

        self.remove_btn = QPushButton("✕")
        self.remove_btn.setMaximumWidth(28)
        self.remove_btn.clicked.connect(lambda: on_remove(self))

        for w in (self.type_combo, self.op_combo, self.number, self.unit_combo,
                  self.date_combo, self.text_edit, self.cat_combo):
            lay.addWidget(w)
        lay.addWidget(self.remove_btn)

        self.type_combo.currentIndexChanged.connect(self._update)
        self._update()

    @staticmethod
    def _set(combo, pairs) -> None:
        combo.clear()
        for label, key in pairs:
            combo.addItem(label, key)

    def _update(self) -> None:
        kind = self.type_combo.currentData()
        op = num = unit = date = text = cat = False
        if kind == "age":
            self._set(self.op_combo, [("older than", "older"), ("newer than", "newer")])
            self._set(self.unit_combo, [(u, u) for u in rules.AGE_UNITS])
            op = num = unit = date = True
        elif kind == "size":
            self._set(self.op_combo, [("larger than", "gt"), ("smaller than", "lt")])
            self._set(self.unit_combo, [(u, u) for u in rules.SIZE_UNITS])
            op = num = unit = True
        elif kind == "ext":
            self.text_edit.setPlaceholderText("tmp, log, bak")
            text = True
        elif kind == "category":
            cat = True
        elif kind == "name":
            self._set(self.op_combo, [("contains", "contains"),
                                      ("wildcard", "wildcard"), ("regex", "regex")])
            self.text_edit.setPlaceholderText("text, ~$* or regex")
            op = text = True
        elif kind == "author":
            self.text_edit.setPlaceholderText(ui.AUTHOR_HINT)
            text = True
        # junk / empty — без параметров
        self.op_combo.setVisible(op)
        self.number.setVisible(num)
        self.unit_combo.setVisible(unit)
        self.date_combo.setVisible(date)
        self.text_edit.setVisible(text)
        self.cat_combo.setVisible(cat)

    def condition(self) -> rules.Condition:
        kind = self.type_combo.currentData()
        c = rules.Condition(kind=kind)
        if kind == "age":
            c.op = self.op_combo.currentData()
            c.number = self.number.value()
            c.unit = self.unit_combo.currentData()
            c.date_field = self.date_combo.currentData()
        elif kind == "size":
            c.op = self.op_combo.currentData()
            c.number = self.number.value()
            c.unit = self.unit_combo.currentData()
        elif kind == "ext":
            c.text = self.text_edit.text().strip()
        elif kind == "category":
            c.text = self.cat_combo.currentText()
        elif kind == "name":
            c.op = self.op_combo.currentData()
            c.text = self.text_edit.text().strip()
        elif kind == "author":
            c.text = self.text_edit.text().strip()
        return c


class RulesDialog(QDialog):
    """Условия отбора файлов → действие «Переместить в папку», с предпросмотром."""

    def __init__(self, parent=None, entries=None, root="", categories=None,
                 recursive=True, include_dirs=False, read_authors=False) -> None:
        super().__init__(parent)
        self.setWindowTitle("Rules: condition → action")
        self.resize(860, 680)
        self.entries = entries or []
        self.root = root or ""
        self.categories = categories or []
        self.opt_recursive = recursive
        self.opt_include_dirs = include_dirs
        self.opt_read_authors = read_authors
        self.matched: list = []
        self._rows: list[ConditionRow] = []

        layout = QVBoxLayout(self)

        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Rule name:"))
        self.name_edit = QLineEdit(_safe_task_name(self.root).replace("scan_", "rule_"))
        name_row.addWidget(self.name_edit, 1)
        layout.addLayout(name_row)

        layout.addWidget(QLabel("Conditions (combined with AND):"))

        self._cond_area = QVBoxLayout()
        wrap = QWidget()
        wrap.setLayout(self._cond_area)
        layout.addWidget(wrap)

        add_btn = QPushButton("+ Add Condition")
        add_btn.setAutoDefault(False)
        add_btn.clicked.connect(self._add_row)
        layout.addWidget(add_btn, alignment=Qt.AlignLeft)

        act_box = QGroupBox("Action: move matching files to a folder")
        act_lay = QHBoxLayout(act_box)
        act_lay.addWidget(QLabel("Destination folder:"))
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText(ui.TARGET_HINT)
        act_lay.addWidget(self.target_edit, 1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse_target)
        act_lay.addWidget(browse)
        layout.addWidget(act_box)

        btns = QHBoxLayout()
        find_btn = QPushButton("Find Matches")
        find_btn.setDefault(True)
        find_btn.clicked.connect(self._find)
        self.export_btn = QPushButton("Export List (CSV)")
        self.export_btn.clicked.connect(self._export)
        self.export_btn.setEnabled(False)
        self.move_btn = QPushButton("Move Files")
        self.move_btn.clicked.connect(self._move)
        self.move_btn.setEnabled(False)
        btns.addWidget(find_btn)
        btns.addWidget(self.export_btn)
        btns.addStretch(1)
        btns.addWidget(self.move_btn)
        layout.addLayout(btns)

        self.summary = QLabel("—")
        layout.addWidget(self.summary)

        self.preview = QTableWidget(0, 5)
        self.preview.setHorizontalHeaderLabels(["Name", "Size", "Category", "Modified", "Path"])
        self.preview.horizontalHeader().setStretchLastSection(True)
        self.preview.setEditTriggers(QTableWidget.NoEditTriggers)
        self.preview.verticalHeader().setVisible(False)
        layout.addWidget(self.preview, 1)

        # --- автоархивация по расписанию
        sched_box = QGroupBox("Scheduled auto-archiving (no confirmation)")
        sched_lay = QHBoxLayout(sched_box)
        sched_lay.addWidget(QLabel("Frequency:"))
        self.sched_freq = QComboBox()
        self.sched_freq.addItems(["Daily", "Every N hours", "Every N minutes"])
        self.sched_freq.currentIndexChanged.connect(self._update_sched_widgets)
        sched_lay.addWidget(self.sched_freq)
        sched_lay.addWidget(QLabel("N:"))
        self.sched_interval = QSpinBox()
        self.sched_interval.setRange(1, 999)
        self.sched_interval.setValue(6)
        sched_lay.addWidget(self.sched_interval)
        sched_lay.addWidget(QLabel("Time:"))
        self.sched_time = QTimeEdit(QTime(3, 0))
        self.sched_time.setDisplayFormat("HH:mm")
        sched_lay.addWidget(self.sched_time)
        self.sched_system_cb = QCheckBox("as a service (SYSTEM)")
        self.sched_system_cb.setToolTip(
            "Run in the background as SYSTEM without a logged-in user "
            "(administrator rights are needed to create it)."
        )
        self.sched_system_cb.setVisible(sys.platform == "win32")
        sched_lay.addWidget(self.sched_system_cb)
        sched_lay.addStretch(1)
        self.sched_btn = QPushButton("Create Auto-Archiving Task")
        self.sched_btn.clicked.connect(self._schedule)
        sched_lay.addWidget(self.sched_btn)
        layout.addWidget(sched_box)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)

        self._add_row()
        self._update_sched_widgets()

    def _add_row(self) -> None:
        row = ConditionRow(self.categories, self._remove_row)
        self._rows.append(row)
        self._cond_area.addWidget(row)

    def _remove_row(self, row) -> None:
        if len(self._rows) <= 1:
            return
        self._rows.remove(row)
        row.setParent(None)
        row.deleteLater()

    def _browse_target(self) -> None:
        start = self.target_edit.text().strip() or os.path.expanduser("~")
        d = QFileDialog.getExistingDirectory(self, "Destination Folder", start)
        if d:
            self.target_edit.setText(os.path.normpath(d))

    def _conditions(self):
        conds = []
        for r in self._rows:
            c = r.condition()
            if c.kind in ("ext", "category", "name", "author") and not c.text:
                continue  # пустое текстовое условие пропускаем
            conds.append(c)
        return conds

    def _find(self) -> None:
        import time
        conds = self._conditions()
        if not conds:
            self.summary.setText("Add at least one condition.")
            return
        self.matched = rules.evaluate(self.entries, conds, time.time(), include_dirs=False)
        total = sum(e.size for e in self.matched)
        self.summary.setText(
            f"Matched files: {len(self.matched)} · total: {human_size(total)}"
        )
        self._fill_preview()
        has = bool(self.matched)
        self.export_btn.setEnabled(has)
        self.move_btn.setEnabled(has)

    def _fill_preview(self) -> None:
        from model import fmt_dt
        self.preview.setRowCount(len(self.matched))
        for i, e in enumerate(self.matched):
            self.preview.setItem(i, 0, QTableWidgetItem(e.name))
            size_it = QTableWidgetItem(human_size(e.size))
            size_it.setTextAlignment(int(Qt.AlignRight | Qt.AlignVCenter))
            self.preview.setItem(i, 1, size_it)
            self.preview.setItem(i, 2, QTableWidgetItem(e.category))
            self.preview.setItem(i, 3, QTableWidgetItem(fmt_dt(e.modified)))
            self.preview.setItem(i, 4, QTableWidgetItem(e.path))
        self.preview.resizeColumnsToContents()

    def _export(self) -> None:
        if not self.matched:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save List", "matched.csv", "CSV (*.csv)")
        if not path:
            return
        try:
            rules.export_csv(self.matched, path)
            QMessageBox.information(self, "Done", f"Rows saved: {len(self.matched)}")
        except OSError as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _move(self) -> None:
        if not self.matched:
            return
        target = os.path.expanduser(self.target_edit.text().strip().strip('"'))
        if not target:
            QMessageBox.warning(self, "No folder", "Specify the destination folder.")
            return
        if self.root and _is_inside(target, self.root):
            QMessageBox.warning(
                self, "Not allowed",
                "The destination folder must not be inside the analyzed folder.",
            )
            return
        total = sum(e.size for e in self.matched)
        ans = QMessageBox.question(
            self, "Confirm",
            f"Move {len(self.matched)} files ({human_size(total)}) to:\n{target}\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if ans != QMessageBox.Yes:
            return
        self.setCursor(Qt.WaitCursor)
        moved, freed, errors = rules.execute_move(self.matched, self.root or "", target)
        self.unsetCursor()
        msg = f"Moved: {moved} files, freed {human_size(freed)}."
        if errors:
            msg += f"\n\nErrors: {len(errors)}\n" + "\n".join(errors[:5])
            if len(errors) > 5:
                msg += f"\n…and {len(errors) - 5} more."
        QMessageBox.information(self, "Done", msg)
        self.matched = [e for e in self.matched if os.path.exists(e.path)]
        self._fill_preview()
        self.summary.setText(f"Left in the list: {len(self.matched)}")
        self.move_btn.setEnabled(bool(self.matched))
        self.export_btn.setEnabled(bool(self.matched))

    def _update_sched_widgets(self) -> None:
        idx = self.sched_freq.currentIndex()
        self.sched_interval.setEnabled(idx in (1, 2))
        self.sched_time.setEnabled(idx in (0, 1))

    def _schedule(self) -> None:
        name = self.name_edit.text().strip()
        conds = self._conditions()
        target = os.path.expanduser(self.target_edit.text().strip().strip('"'))
        if not name:
            QMessageBox.warning(self, "Name", "Specify the rule name.")
            return
        if not conds:
            QMessageBox.warning(self, "Conditions", "Add at least one condition.")
            return
        if not target:
            QMessageBox.warning(self, "Folder", "Specify the destination folder for moving files.")
            return
        if not self.root or not os.path.isdir(self.root):
            QMessageBox.warning(
                self, "Analyzed folder",
                "The analyzed folder is not available — its path is needed for the scheduled run.",
            )
            return
        if _is_inside(target, self.root):
            QMessageBox.warning(
                self, "Not allowed",
                "The destination folder must not be inside the analyzed folder.",
            )
            return

        ans = QMessageBox.question(
            self, "Scheduled Auto-Archiving",
            "The task will move files that match the conditions ON A SCHEDULE, "
            "with no window and no confirmation:\n\n"
            f"from:  {self.root}\nto:    {target}\n\nCreate the task?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if ans != QMessageBox.Yes:
            return

        # если есть условие по автору — для планового скана нужно читать автора
        read_authors = self.opt_read_authors or any(c.kind == "author" for c in conds)
        rule = rules.Rule(
            name=name, root=self.root, conditions=conds, target=target, action="move",
            recursive=self.opt_recursive, include_dirs=self.opt_include_dirs,
            read_authors=read_authors,
        )
        rules.save_rule(rule)

        kind = {0: "DAILY", 1: "HOURLY", 2: "MINUTE"}[self.sched_freq.currentIndex()]
        ok, msg = schedule_task.create_rule_task(
            task_name=name, rule_name=name, kind=kind,
            time_str=self.sched_time.time().toString("HH:mm"),
            interval=self.sched_interval.value(),
            run_as_system=self.sched_system_cb.isChecked(),
        )
        if ok:
            QMessageBox.information(
                self, "Done",
                f"Auto-archiving task “{name}” created.\n"
                "You can run it now or delete it with the “Schedule…” button.",
            )
        else:
            QMessageBox.critical(self, "Error", f"Could not create the task:\n{msg}")


def _safe_task_name(path: str) -> str:
    base = os.path.basename(path.rstrip("\\/")) or path
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in base)
    return f"scan_{safe}" if safe else "scan"


class ScheduleDialog(QDialog):
    """Создание/управление заданиями Планировщика для инкрементного анализа."""

    def __init__(self, parent=None, path="", db_path=None,
                 recursive=True, include_dirs=True, read_authors=False, mode="file") -> None:
        super().__init__(parent)
        self.setWindowTitle("Scheduled Analysis")
        self.setMinimumWidth(560)
        self.db_path = db_path
        self.mode = mode

        layout = QVBoxLayout(self)
        form = _form()
        layout.addLayout(form)

        self.path_edit = QLineEdit(path)
        if mode == "s3":
            self.path_edit.setReadOnly(True)
            form.addRow("S3 bucket:", self.path_edit)
        else:
            self.path_edit.setPlaceholderText(ui.PATH_HINT)
            form.addRow("Folder:", self.path_edit)

        default_name = _safe_task_name(("s3_" + path) if mode == "s3" else path)
        self.name_edit = QLineEdit(default_name)
        form.addRow("Task name:", self.name_edit)

        # периодичность
        self.freq_combo = QComboBox()
        self.freq_combo.addItems(["Daily", "Every N hours", "Every N minutes"])
        self.freq_combo.currentIndexChanged.connect(self._update_freq_widgets)
        form.addRow("Frequency:", self.freq_combo)

        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(1, 999)
        self.interval_spin.setValue(6)
        form.addRow("Interval N:", self.interval_spin)

        self.time_edit = QTimeEdit(QTime(3, 0))
        self.time_edit.setDisplayFormat("HH:mm")
        form.addRow("Start time:", self.time_edit)

        self.authors_cb = QCheckBox("Detect author (slower)")
        self.authors_cb.setChecked(read_authors)
        self.authors_cb.setVisible(mode != "s3")
        form.addRow("", self.authors_cb)
        self.recursive_cb = QCheckBox("Include subfolders")
        self.recursive_cb.setChecked(recursive)
        self.recursive_cb.setVisible(mode != "s3")
        form.addRow("", self.recursive_cb)
        self._include_dirs = include_dirs

        # уведомление в Telegram при превышении размера папки/бакета
        notify_row = QHBoxLayout()
        label = "Notify in Telegram when the bucket size is ≥" if mode == "s3" else \
                "Notify in Telegram when the folder size is ≥"
        self.notify_cb = QCheckBox(label)
        notify_row.addWidget(self.notify_cb)
        self.notify_size = QDoubleSpinBox()
        self.notify_size.setRange(0.1, 1_000_000)
        self.notify_size.setDecimals(1)
        self.notify_size.setValue(100)
        self.notify_size.setEnabled(False)
        notify_row.addWidget(self.notify_size)
        self.notify_unit = QComboBox()
        self.notify_unit.addItems(["MB", "GB", "TB"])
        self.notify_unit.setCurrentText("GB")
        self.notify_unit.setEnabled(False)
        notify_row.addWidget(self.notify_unit)
        notify_row.addStretch(1)
        self.notify_cb.toggled.connect(self.notify_size.setEnabled)
        self.notify_cb.toggled.connect(self.notify_unit.setEnabled)
        notify_wrap = QWidget()
        notify_wrap.setLayout(notify_row)
        form.addRow("", notify_wrap)

        self.system_cb = QCheckBox(
            "Run in the background as a service (as SYSTEM, without a logged-in user)"
        )
        self.system_cb.setToolTip(
            "The task runs as SYSTEM in the background even when no user is logged in. "
            "Creating it requires administrator rights."
        )
        self.system_cb.setVisible(sys.platform == "win32")  # на Unix — от пользователя
        form.addRow("", self.system_cb)
        if sys.platform != "win32":
            backend = QLabel(
                "Tasks are run by launchd as your user (while the Mac is on "
                "and you are logged in). Logs are in the app data folder, logs/."
                if sys.platform == "darwin" else
                "Tasks are run by cron as your user."
            )
            backend.setWordWrap(True)
            backend.setForegroundRole(QPalette.PlaceholderText)
            form.addRow("", backend)

        self.hint = QLabel("")
        self.hint.setWordWrap(True)
        form.addRow("", self.hint)

        create_btn = QPushButton("Create / Update Task")
        create_btn.clicked.connect(self._create)
        layout.addWidget(create_btn)

        layout.addWidget(QLabel("Existing tasks:"))
        self.tasks = QTreeWidget()
        self.tasks.setColumnCount(3)
        self.tasks.setHeaderLabels(["Task", "Next run", "Status"])
        self.tasks.setRootIsDecorated(False)
        layout.addWidget(self.tasks, 1)

        row = QHBoxLayout()
        run_btn = QPushButton("Run Now")
        run_btn.clicked.connect(self._run_now)
        del_btn = QPushButton("Delete Task")
        del_btn.clicked.connect(self._delete)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        row.addWidget(run_btn)
        row.addWidget(del_btn)
        row.addStretch(1)
        row.addWidget(close_btn)
        layout.addLayout(row)

        self._update_freq_widgets()
        self._refresh_tasks()

    def _update_freq_widgets(self) -> None:
        idx = self.freq_combo.currentIndex()
        self.interval_spin.setEnabled(idx in (1, 2))   # часы/минуты
        self.time_edit.setEnabled(idx in (0, 1))       # день/часы (стартовое время)

    def _refresh_tasks(self) -> None:
        self.tasks.clear()
        for t in schedule_task.list_tasks():
            QTreeWidgetItem(self.tasks, [t["name"], t.get("next_run", ""), t.get("status", "")])

    def _selected_task(self):
        item = self.tasks.currentItem()
        return item.text(0) if item else None

    def _create(self) -> None:
        path = os.path.expanduser(self.path_edit.text().strip().strip('"'))
        name = self.name_edit.text().strip()
        if self.mode != "s3" and not os.path.isdir(path):
            self.hint.setText("The folder is not available or does not exist.")
            return
        if not name:
            self.hint.setText("Specify the task name.")
            return
        notify_bytes = 0
        if self.notify_cb.isChecked():
            notify_bytes = int(self.notify_size.value() * SIZE_UNITS[self.notify_unit.currentText()])
            token, chat = app_settings.get_telegram()
            if not token or not chat:
                ans = QMessageBox.question(
                    self, "Telegram is not set up",
                    "Notifications are enabled, but the Telegram bot/chat is not configured yet.\n"
                    "Open the Telegram settings now?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes,
                )
                if ans == QMessageBox.Yes:
                    TelegramDialog(self).exec()

        kind = {0: "DAILY", 1: "HOURLY", 2: "MINUTE"}[self.freq_combo.currentIndex()]
        if self.mode == "s3":
            ok, msg = schedule_task.create_s3_task(
                name=name, kind=kind,
                time_str=self.time_edit.time().toString("HH:mm"),
                interval=self.interval_spin.value(),
                db_path=self.db_path, notify_size=notify_bytes,
                run_as_system=self.system_cb.isChecked(),
            )
        else:
            ok, msg = schedule_task.create_task(
                name=name, path=path, kind=kind,
                time_str=self.time_edit.time().toString("HH:mm"),
                interval=self.interval_spin.value(),
                recursive=self.recursive_cb.isChecked(),
                include_dirs=self._include_dirs,
                read_authors=self.authors_cb.isChecked(),
                db_path=self.db_path,
                notify_size=notify_bytes,
                run_as_system=self.system_cb.isChecked(),
            )
        self.hint.setText("Task created." if ok else f"Failed: {msg}")
        self._refresh_tasks()

    def _delete(self) -> None:
        name = self._selected_task()
        if not name:
            self.hint.setText("Select a task in the list.")
            return
        ok, msg = schedule_task.delete_task(name)
        self.hint.setText("Task deleted." if ok else f"Failed: {msg}")
        self._refresh_tasks()

    def _run_now(self) -> None:
        name = self._selected_task()
        if not name:
            self.hint.setText("Select a task in the list.")
            return
        ok, msg = schedule_task.run_task_now(name)
        self.hint.setText("Task started." if ok else f"Failed: {msg}")


def run_cli(argv) -> int:
    """Безоконный режим для запуска по расписанию: анализ + сохранение в базу."""
    import argparse
    import time

    from scanner import run_scan

    parser = argparse.ArgumentParser(description="Incremental folder analysis into the database")
    parser.add_argument("--scan", required=True, help="folder path")
    parser.add_argument("--no-recursive", action="store_true")
    parser.add_argument("--no-dirs", action="store_true")
    parser.add_argument("--authors", action="store_true")
    parser.add_argument("--db", default=None)
    parser.add_argument("--full", action="store_true", help="full (non-incremental) analysis")
    parser.add_argument("--notify-size", type=int, default=0, dest="notify_size",
                        help="folder size threshold (bytes): send a Telegram notification when exceeded")
    parser.add_argument("--settings-file", default=None, dest="settings_file",
                        help="path to settings.json (for runs as SYSTEM)")
    args = parser.parse_args(argv)

    db_path = args.db or default_db_path()
    try:
        results, info = run_scan(
            args.scan,
            recursive=not args.no_recursive,
            include_dirs=not args.no_dirs,
            read_authors=args.authors,
            db_path=db_path,
            incremental=not args.full,
            scan_time=time.time(),
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Done: total {info['total']}, files {info['files']}, "
          f"new/changed {info['changed']}, deleted {info['deleted']}")

    if args.notify_size:
        import datetime
        import notify
        total_size = sum(e.size for e in results if not e.is_dir)
        if total_size >= args.notify_size:
            stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            text = (
                "⚠️ Folder size threshold exceeded\n"
                f"Folder: {args.scan}\n"
                f"Size: {human_size(total_size)} (threshold {human_size(args.notify_size)})\n"
                f"Files: {info['files']}\n"
                f"Time: {stamp}"
            )
            ok, msg = notify.notify(text, args.settings_file)
            print(f"Notification: {'sent' if ok else msg}")
    return 0


def run_apply_cli(argv) -> int:
    """Headless-применение сохранённого правила (для запуска по расписанию)."""
    import argparse
    import datetime
    import time

    parser = argparse.ArgumentParser(description="Auto-archiving by rule")
    parser.add_argument("--apply-rule", required=True, dest="rule")
    parser.add_argument("--rules-file", default=None)
    args = parser.parse_args(argv)

    rule = rules.get_rule(args.rule, args.rules_file)
    if rule is None:
        print(f"Rule not found: {args.rule}", file=sys.stderr)
        return 2

    log_dir = os.path.join(app_settings.app_data_dir(), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"{rule.name}.log")

    lines: list[str] = []

    def log(msg: str) -> None:
        lines.append(msg)
        print(msg)

    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log(f"[{stamp}] Rule '{rule.name}': {rule.root} -> {rule.target}")
    code = 0
    try:
        rules.apply_rule(rule, time.time(), on_log=log)
    except Exception as exc:  # noqa: BLE001
        log(f"Error: {exc}")
        code = 1
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError:
        pass
    return code


def run_s3_cli(argv) -> int:
    """Безоконный анализ бакета S3 по расписанию (профиль берётся из settings.json)."""
    import argparse
    import datetime
    import time as _t

    parser = argparse.ArgumentParser(description="Scheduled S3 bucket analysis")
    parser.add_argument("--s3-scan", action="store_true")
    parser.add_argument("--db", default=None)
    parser.add_argument("--notify-size", type=int, default=0, dest="notify_size")
    parser.add_argument("--settings-file", default=None, dest="settings_file")
    args = parser.parse_args(argv)

    cfg_d = app_settings.get_s3(args.settings_file)
    if not cfg_d or not cfg_d.get("bucket"):
        print("S3 profile is not configured.", file=sys.stderr)
        return 2
    cfg = s3client.S3Config(**cfg_d)
    db_path = args.db or default_db_path()

    from db import FileDatabase
    from scanner import incremental_stats
    prior = {}
    db = None
    try:
        db = FileDatabase(db_path)
        prior = db.load_entries(cfg.bucket)
    except Exception:  # noqa: BLE001
        db = None
    try:
        entries = s3client.list_entries(cfg)
    except Exception as exc:  # noqa: BLE001
        print(f"S3 error: {exc}", file=sys.stderr)
        return 1
    info = incremental_stats(entries, prior)
    if db is not None:
        try:
            db.save_scan(cfg.bucket, entries, _t.time())
        except Exception:  # noqa: BLE001
            pass
        db.close()
    print(f"S3 done: total {info['total']}, objects {info['files']}, changed {info['changed']}")

    if args.notify_size:
        total_size = sum(e.size for e in entries if not e.is_dir)
        if total_size >= args.notify_size:
            stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            text = (
                "⚠️ S3 bucket size threshold exceeded\n"
                f"Bucket: {cfg.bucket}\n"
                f"Size: {human_size(total_size)} (threshold {human_size(args.notify_size)})\n"
                f"Objects: {info['files']}\n"
                f"Time: {stamp}"
            )
            ok, msg = notify.notify(text, args.settings_file)
            print(f"Notification: {'sent' if ok else msg}")
    return 0


def main() -> None:
    argv = sys.argv[1:]
    if "--apply-rule" in argv:
        sys.exit(run_apply_cli(argv))
    if "--s3-scan" in argv:
        sys.exit(run_s3_cli(argv))
    if "--scan" in argv:
        sys.exit(run_cli(argv))
    # отдельный AppUserModelID — чтобы Windows показывал нашу иконку на панели задач
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("FolderAnalyzer.App")
        except Exception:  # noqa: BLE001
            pass

    app = QApplication(sys.argv)
    app.setApplicationName("FolderAnalyzer")
    app.setOrganizationName("FolderAnalyzer")
    app.setApplicationDisplayName(APP_TITLE)
    app.setApplicationVersion(APP_VERSION)
    # английский формат чисел и дат в полях ввода (точка в дробях), независимо от региона ОС
    from PySide6.QtCore import QLocale
    QLocale.setDefault(QLocale(QLocale.English, QLocale.UnitedStates))
    ip = _icon_path()
    if ip and not getattr(sys, "frozen", False) or (ip and sys.platform != "darwin"):
        app.setWindowIcon(QIcon(ip))  # из собранного .app иконку берёт macOS
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
