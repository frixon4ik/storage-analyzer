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

from PySide6.QtCore import QDate, QObject, Qt, QThread, QTime, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QIcon


def _icon_path() -> str:
    """Путь к иконке приложения (работает из исходников и из сборки; .ico/.png)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    for name in ("app_icon.ico", "app_icon.png"):
        p = os.path.join(base, name)
        if os.path.exists(p):
            return p
    return ""
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
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
    QRadioButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QTimeEdit,
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

from db import FileDatabase, db_size_bytes, default_db_path
from model import (
    COL_NAME,
    COL_PATH,
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

SIZE_UNITS = {"Б": 1, "КБ": 1024, "МБ": 1024**2, "ГБ": 1024**3, "ТБ": 1024**4}


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Анализатор хранилищ — локальные диски, SMB и S3")
        self.resize(1180, 720)
        _ip = _icon_path()
        if _ip:
            self.setWindowIcon(QIcon(_ip))

        self.controller = ScanController()
        self.s3_controller = S3ListController()
        self.mode = "file"  # "file" | "s3"
        self.s3cfg = s3client.S3Config(**app_settings.get_s3()) if app_settings.get_s3() else s3client.S3Config()
        self.db_path = app_settings.get_db_path() or default_db_path()
        self._last_info: dict = {}
        # ресурсы, подключённые за время сессии (для отключения при выходе)
        self._smb_connections: list[tuple[str, bool]] = []  # (адрес, persistent)
        self.model = FileListModel()  # быстрый фильтр+сортировка над списком

        # древовидное представление (по папкам) — ленивая модель
        self.tree_model = LazyFileTreeModel("", [])
        self._last_root = ""
        self._tree_built = False   # дерево строится по запросу при переключении вида
        self._tree_root = None     # для какого корня построено дерево (для переиспользования)
        self._building_tree = False
        self._tree_builder = None
        self._tree_total = 0

        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        root.addWidget(self._build_source_row())
        self.filter_box = self._build_filter_box()
        self.filter_box.setVisible(False)  # поля фильтра скрыты, пока не нажата кнопка «Фильтры»
        root.addWidget(self.filter_box)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_views())
        splitter.addWidget(self._build_summary())
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([860, 300])
        root.addWidget(splitter, 1)

        # Статусбар + прогресс
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # пока неизвестно общее число — «бегущая» полоса
        self.progress.setVisible(False)
        self.progress.setMinimumWidth(240)
        self.progress.setTextVisible(True)
        self.count_label = QLabel("Папка не выбрана")
        self.statusBar().addWidget(self.count_label, 1)
        self.statusBar().addPermanentWidget(self.progress)

    def _build_source_row(self) -> QWidget:
        box = QFrame()
        outer = QVBoxLayout(box)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)

        # --- строка 1: источник + путь (крупно) + основные кнопки
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Источник:"))
        self.source_combo = QComboBox()
        self.source_combo.addItems(["Файлы", "S3"])
        self.source_combo.currentIndexChanged.connect(self._on_source_changed)
        row1.addWidget(self.source_combo)

        self.path_label = QLabel("Папка:")
        row1.addWidget(self.path_label)
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(r"C:\Папка  или  \\synology\share\folder")
        self.path_edit.setMinimumHeight(28)
        self.path_edit.setClearButtonEnabled(True)
        self.path_edit.returnPressed.connect(self.start_scan)
        row1.addWidget(self.path_edit, 1)

        self.browse_btn = QPushButton("Обзор…")
        self.browse_btn.clicked.connect(self.browse_folder)
        row1.addWidget(self.browse_btn)

        self.s3_btn = QPushButton("Подключение S3…")
        self.s3_btn.clicked.connect(self.open_connect_s3)
        self.s3_btn.setVisible(False)
        row1.addWidget(self.s3_btn)

        self.scan_btn = QPushButton("Анализировать")
        self.scan_btn.setDefault(True)
        self.scan_btn.clicked.connect(self.start_scan)
        row1.addWidget(self.scan_btn)

        self.cancel_btn = QPushButton("Стоп")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel_scan)
        row1.addWidget(self.cancel_btn)
        outer.addLayout(row1)

        # --- строка 2: параметры и второстепенные кнопки (сдвинуты вниз)
        row2 = QHBoxLayout()
        self.smb_btn = QPushButton("Подключить SMB…")
        self.smb_btn.setToolTip("Подключиться к сетевому хранилищу с логином и паролем")
        self.smb_btn.clicked.connect(self.connect_smb)
        self.smb_btn.setVisible(netshare.is_available())  # только Windows
        row2.addWidget(self.smb_btn)

        self.recursive_cb = QCheckBox("С подпапками")
        self.recursive_cb.setChecked(True)
        row2.addWidget(self.recursive_cb)

        self.dirs_cb = QCheckBox("Показывать папки")
        self.dirs_cb.setChecked(True)
        row2.addWidget(self.dirs_cb)

        self.authors_cb = QCheckBox("Определять автора")
        self.authors_cb.setToolTip(
            "Читать «Автора» файла (как в Проводнике). Если автор не задан —\n"
            "подставляется владелец файла (учётная запись, создавшая файл).\n"
            "Замедляет сканирование, особенно на сетевых хранилищах."
        )
        row2.addWidget(self.authors_cb)

        self.incremental_cb = QCheckBox("Инкрементно (БД)")
        self.incremental_cb.setChecked(True)
        self.incremental_cb.setToolTip(
            "Сохранять результат в базу и при повторном анализе обновлять только\n"
            "изменённые файлы (неизменённые берутся из базы — быстрее)."
        )
        row2.addWidget(self.incremental_cb)

        self.filter_btn = QPushButton("Фильтры ▾")
        self.filter_btn.setCheckable(True)
        self.filter_btn.setToolTip("Показать/скрыть поля фильтра")
        self.filter_btn.toggled.connect(self._toggle_filters)
        row2.addWidget(self.filter_btn)

        row2.addStretch(1)

        self.schedule_btn = QPushButton("Расписание…")
        self.schedule_btn.setToolTip("Запускать инкрементный анализ этой папки по расписанию")
        self.schedule_btn.clicked.connect(self.open_schedule)
        row2.addWidget(self.schedule_btn)

        self.rules_btn = QPushButton("Правила…")
        self.rules_btn.setToolTip("Отобрать файлы по условиям и выполнить действие (перенос)")
        self.rules_btn.clicked.connect(self.open_rules)
        row2.addWidget(self.rules_btn)

        self.dup_btn = QPushButton("Дубликаты…")
        self.dup_btn.setToolTip("Найти дубликаты по выбранным полям и перенести их")
        self.dup_btn.clicked.connect(self.open_duplicates)
        row2.addWidget(self.dup_btn)

        self.settings_btn = QPushButton("Настройки…")
        self.settings_btn.setToolTip("Папка базы данных и уведомления Telegram")
        self.settings_btn.clicked.connect(self.open_settings)
        row2.addWidget(self.settings_btn)
        outer.addLayout(row2)

        return box

    def _toggle_filters(self, on: bool) -> None:
        self.filter_box.setVisible(on)
        self.filter_btn.setText("Фильтры ▴" if on else "Фильтры ▾")

    def _on_source_changed(self) -> None:
        self.mode = "s3" if self.source_combo.currentIndex() == 1 else "file"
        s3 = self.mode == "s3"
        self.path_label.setText("S3:" if s3 else "Папка:")
        self.path_edit.setReadOnly(s3)
        self.path_edit.setClearButtonEnabled(not s3)
        self.browse_btn.setVisible(not s3)
        self.s3_btn.setVisible(s3)
        self.smb_btn.setVisible((not s3) and netshare.is_available())
        self.recursive_cb.setVisible(not s3)
        self.authors_cb.setVisible(not s3)
        self.dirs_cb.setText("Показывать папки (префиксы)" if s3 else "Показывать папки")
        if s3:
            self._refresh_s3_target()
        else:
            self.path_edit.clear()
            self.path_edit.setPlaceholderText(r"C:\Папка  или  \\synology\share\folder")

    def _refresh_s3_target(self) -> None:
        if self.s3cfg.bucket:
            who = self.s3cfg.endpoint or "AWS"
            tgt = f"{who} / {self.s3cfg.bucket}" + (f" / {self.s3cfg.prefix}" if self.s3cfg.prefix else "")
            self.path_edit.setText(tgt)
        else:
            self.path_edit.setText("")
            self.path_edit.setPlaceholderText("нажмите «Подключение S3…»")

    def open_connect_s3(self) -> None:
        if not s3client.is_available():
            QMessageBox.warning(self, "Нет boto3", "Установите boto3: pip install boto3")
            return
        dlg = S3ConnectDialog(self, self.s3cfg)
        if dlg.exec() == QDialog.Accepted:
            self.s3cfg = dlg.cfg
            self._refresh_s3_target()

    def _build_filter_box(self) -> QWidget:
        group = QGroupBox("Фильтры")
        outer = QVBoxLayout(group)
        row1 = QHBoxLayout()
        row2 = QHBoxLayout()
        outer.addLayout(row1)
        outer.addLayout(row2)

        # --- строка 1: имя, формат, категория, тип
        row1.addWidget(QLabel("Имя содержит:"))
        self.f_name = QLineEdit()
        self.f_name.setMaximumWidth(180)
        row1.addWidget(self.f_name)

        row1.addWidget(QLabel("Формат:"))
        self.f_ext = QLineEdit()
        self.f_ext.setPlaceholderText("jpg, png, pdf")
        self.f_ext.setMaximumWidth(160)
        row1.addWidget(self.f_ext)

        row1.addWidget(QLabel("Категория:"))
        self.f_category = QComboBox()
        self.f_category.addItem("Все")
        row1.addWidget(self.f_category)

        row1.addWidget(QLabel("Тип:"))
        self.f_kind = QComboBox()
        self.f_kind.addItems(["Все", "Файл", "Папка"])
        row1.addWidget(self.f_kind)

        row1.addWidget(QLabel("Автор:"))
        self.f_author = QLineEdit()
        self.f_author.setPlaceholderText("содержит…")
        self.f_author.setMaximumWidth(160)
        row1.addWidget(self.f_author)
        row1.addStretch(1)

        # --- строка 2: размер, даты, кнопки
        row2.addWidget(QLabel("Размер от:"))
        self.f_min_size = QLineEdit()
        self.f_min_size.setMaximumWidth(70)
        self.f_min_size.setPlaceholderText("0")
        row2.addWidget(self.f_min_size)
        row2.addWidget(QLabel("до:"))
        self.f_max_size = QLineEdit()
        self.f_max_size.setMaximumWidth(70)
        self.f_max_size.setPlaceholderText("∞")
        row2.addWidget(self.f_max_size)
        self.f_size_unit = QComboBox()
        self.f_size_unit.addItems(list(SIZE_UNITS.keys()))
        self.f_size_unit.setCurrentText("МБ")
        row2.addWidget(self.f_size_unit)

        row2.addSpacing(16)
        self.f_date_on = QCheckBox("Изменён с:")
        row2.addWidget(self.f_date_on)
        self.f_date_from = QDateEdit()
        self.f_date_from.setCalendarPopup(True)
        self.f_date_from.setDisplayFormat("yyyy-MM-dd")
        self.f_date_from.setDate(QDate.currentDate().addMonths(-1))
        self.f_date_from.setEnabled(False)
        row2.addWidget(self.f_date_from)
        row2.addWidget(QLabel("по:"))
        self.f_date_to = QDateEdit()
        self.f_date_to.setCalendarPopup(True)
        self.f_date_to.setDisplayFormat("yyyy-MM-dd")
        self.f_date_to.setDate(QDate.currentDate())
        self.f_date_to.setEnabled(False)
        row2.addWidget(self.f_date_to)
        self.f_date_on.toggled.connect(self.f_date_from.setEnabled)
        self.f_date_on.toggled.connect(self.f_date_to.setEnabled)

        row2.addStretch(1)
        apply_btn = QPushButton("Применить")
        apply_btn.clicked.connect(self.apply_filters)
        row2.addWidget(apply_btn)
        reset_btn = QPushButton("Сбросить")
        reset_btn.clicked.connect(self.reset_filters)
        row2.addWidget(reset_btn)

        # Применять фильтр по Enter в текстовых полях
        for w in (self.f_name, self.f_ext, self.f_author, self.f_min_size, self.f_max_size):
            w.returnPressed.connect(self.apply_filters)

        return group

    def _build_views(self) -> QWidget:
        wrap = QWidget()
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)

        # переключатель вида
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Вид:"))
        self.view_list_rb = QRadioButton("Список")
        self.view_tree_rb = QRadioButton("Папки (дерево)")
        self.view_list_rb.setChecked(True)
        self.view_list_rb.toggled.connect(self._switch_view)
        bar.addWidget(self.view_list_rb)
        bar.addWidget(self.view_tree_rb)
        bar.addStretch(1)
        self.expand_btn = QPushButton("Развернуть всё")
        self.expand_btn.clicked.connect(lambda: self.tree.expandAll())
        self.expand_btn.setVisible(False)
        self.collapse_btn = QPushButton("Свернуть всё")
        self.collapse_btn.clicked.connect(lambda: self.tree.collapseAll())
        self.collapse_btn.setVisible(False)
        bar.addWidget(self.expand_btn)
        bar.addWidget(self.collapse_btn)
        lay.addLayout(bar)

        self.stack = QStackedWidget()
        lay.addWidget(self.stack, 1)

        # --- вид «Список» (плоская таблица)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_menu)
        self.table.doubleClicked.connect(self._open_selected)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        self.table.setColumnWidth(COL_NAME, 240)
        self.table.setColumnWidth(COL_PATH, 260)
        self.stack.addWidget(self.table)

        # --- вид «Папки» (дерево, как в Проводнике)
        self.tree = QTreeView()
        self.tree.setModel(self.tree_model)
        self.tree.setSortingEnabled(True)
        self.tree.setSelectionMode(QTreeView.ExtendedSelection)
        self.tree.setAlternatingRowColors(True)
        self.tree.setEditTriggers(QTreeView.NoEditTriggers)
        self.tree.setUniformRowHeights(True)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._show_menu)
        self.tree.doubleClicked.connect(self._tree_double_clicked)
        self.tree.header().setSectionResizeMode(QHeaderView.Interactive)
        self.tree.header().setStretchLastSection(True)
        self.tree.setColumnWidth(COL_NAME, 320)
        self.stack.addWidget(self.tree)

        return wrap

    def _switch_view(self) -> None:
        tree_mode = self.view_tree_rb.isChecked()
        if tree_mode and not self._tree_built and self.model.all_count() > 0:
            # ленивое дерево: индексация мгновенная, узлы строятся при раскрытии
            self.tree_model = LazyFileTreeModel(self._last_root, self.model.all_entries())
            self.tree_model.set_criteria(self.model.criteria)
            self.tree.setModel(self.tree_model)
            self.tree.expandToDepth(0)
            self._tree_built = True
            self._tree_root = self._last_root
        self.stack.setCurrentIndex(1 if tree_mode else 0)
        self.expand_btn.setVisible(tree_mode)
        self.collapse_btn.setVisible(tree_mode)
        self._update_summary()

    def _build_summary(self) -> QWidget:
        box = QGroupBox("Сводка")
        lay = QVBoxLayout(box)

        self.summary_total = QLabel("—")
        self.summary_total.setWordWrap(True)
        self.summary_total.setTextFormat(Qt.RichText)
        lay.addWidget(self.summary_total)

        lay.addWidget(QLabel("По категориям (клик — фильтр):"))
        self.cat_table = QTableWidget(0, 3)
        self.cat_table.setHorizontalHeaderLabels(["Категория", "Кол-во", "Размер"])
        self.cat_table.verticalHeader().setVisible(False)
        self.cat_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.cat_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.cat_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.cat_table.setCursor(Qt.PointingHandCursor)
        self.cat_table.cellClicked.connect(self._on_category_clicked)
        lay.addWidget(self.cat_table, 1)
        return box

    # -------------------------------------------------------------- actions
    def browse_folder(self) -> None:
        start = self.path_edit.text().strip() or os.path.expanduser("~")
        folder = QFileDialog.getExistingDirectory(self, "Выберите папку", start)
        if folder:
            self.path_edit.setText(os.path.normpath(folder))
            self.start_scan()

    def connect_smb(self) -> None:
        if not netshare.is_available():
            QMessageBox.warning(
                self, "Недоступно",
                "Подключение по SMB с учётными данными доступно только на Windows.",
            )
            return
        dlg = SmbConnectDialog(self, preset_path=self.path_edit.text().strip())
        if dlg.exec() != QDialog.Accepted:
            return
        scan_path = dlg.scan_path
        self._smb_connections.append((dlg.connected_target, dlg.persistent))
        self.path_edit.setText(scan_path)
        # сразу запускаем анализ подключённого ресурса
        self.start_scan()

    def open_schedule(self) -> None:
        if self.mode == "s3":
            if not self.s3cfg.bucket:
                QMessageBox.warning(self, "Не подключено", "Сначала задайте подключение к S3.")
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
                self, "Нет данных",
                "Сначала проанализируйте папку — правила применяются к её содержимому.",
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
            QMessageBox.information(self, "Нет данных", "Сначала проанализируйте папку/бакет.")
            return
        DuplicatesDialog(self, entries=entries, mode=self.mode,
                         root=self._last_root, s3cfg=self.s3cfg).exec()

    def open_settings(self) -> None:
        SettingsDialog(self).exec()
        # путь к базе мог измениться
        self.db_path = app_settings.get_db_path() or default_db_path()

    def start_scan(self) -> None:
        if self._building_tree:
            return  # идёт построение дерева — не перебиваем
        import time

        if self.mode == "s3":
            if not self.s3cfg.bucket:
                QMessageBox.warning(self, "Не подключено", "Сначала задайте подключение к S3.")
                return
            self._last_root = self.s3cfg.bucket
        else:
            path = self.path_edit.text().strip().strip('"')
            if not path:
                QMessageBox.warning(self, "Нет пути", "Укажите папку для анализа.")
                return
            if not os.path.isdir(path):
                QMessageBox.warning(
                    self, "Папка не найдена",
                    f"Путь недоступен или не является папкой:\n{path}\n\n"
                    "Для сетевых хранилищ используйте формат \\\\server\\share\\... "
                    "и убедитесь, что share подключён.",
                )
                return
            self._last_root = path

        self.scan_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.count_label.setText("Перечисление объектов…" if self.mode == "s3" else "Сканирование…")
        self.model.set_entries([])
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

    def cancel_scan(self) -> None:
        self.controller.stop()
        self.s3_controller.stop()
        self._finish_state()
        self.count_label.setText("Остановлено.")

    def _on_phase(self, text: str) -> None:
        self.count_label.setText(text)
        if text.startswith("Подсчёт"):
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
                f"Обработано: {done:,} из {total:,} ({pct}%)".replace(",", " ")
            )
        else:
            self.count_label.setText(f"Обработано: {done:,}".replace(",", " "))

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
            self.view_list_rb.blockSignals(True)
            self.view_tree_rb.blockSignals(True)
            self.view_list_rb.setChecked(True)
            self.view_list_rb.blockSignals(False)
            self.view_tree_rb.blockSignals(False)
            self.stack.setCurrentIndex(0)
            self.expand_btn.setVisible(False)
            self.collapse_btn.setVisible(False)
        self._populate_categories(entries)
        self.apply_filters()
        self._finish_state()
        self._update_summary()

        info = self._last_info
        if info and info.get("had_prior"):
            self.count_label.setText(
                f"Готово: {info['total']:,} объектов · ".replace(",", " ")
                + f"новых/изменённых: {info['changed']:,}".replace(",", " ")
                + f" · удалено: {info['deleted']:,} (инкрементно из базы)".replace(",", " ")
            )
        elif info:
            self.count_label.setText(
                f"Готово: {info['total']:,} объектов (сохранено в базу)".replace(",", " ")
            )

    def _on_error(self, message: str) -> None:
        self._finish_state()
        self.count_label.setText("Ошибка.")
        QMessageBox.critical(self, "Ошибка сканирования", message)

    def _finish_state(self) -> None:
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress.setVisible(False)

    # -------------------------------------------------------------- filters
    def _populate_categories(self, entries) -> None:
        cats = sorted({e.category for e in entries})
        current = self.f_category.currentText()
        self.f_category.blockSignals(True)
        self.f_category.clear()
        self.f_category.addItem("Все")
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

    def apply_filters(self) -> None:
        exts = {
            e.strip().lstrip(".").lower()
            for e in self.f_ext.text().replace(";", ",").split(",")
            if e.strip()
        }
        crit = FilterCriteria(
            name_text=self.f_name.text().strip(),
            extensions=exts,
            category=self.f_category.currentText(),
            kind=self.f_kind.currentText(),
            author_text=self.f_author.text().strip(),
            min_size=self._parse_size(self.f_min_size.text()),
            max_size=self._parse_size(self.f_max_size.text()),
        )
        if self.f_date_on.isChecked():
            # с начала дня «от» по конец дня «по»
            crit.modified_from = self.f_date_from.dateTime().toSecsSinceEpoch()
            crit.modified_to = self.f_date_to.dateTime().toSecsSinceEpoch() + 86399

        self.model.set_criteria(crit)
        if self._tree_built:
            self.tree_model.set_criteria(crit)
        self._update_summary()

    def reset_filters(self) -> None:
        self.f_name.clear()
        self.f_ext.clear()
        self.f_category.setCurrentIndex(0)
        self.f_kind.setCurrentIndex(0)
        self.f_author.clear()
        self.f_min_size.clear()
        self.f_max_size.clear()
        self.f_date_on.setChecked(False)
        self.model.set_criteria(FilterCriteria())
        if self._tree_built:
            self.tree_model.set_criteria(FilterCriteria())
        self._update_summary()

    # -------------------------------------------------------------- summary
    def _update_summary(self) -> None:
        # разбивка и итоги — по всему набору (чтобы список категорий был стабилен
        # и кликабелен); строка «Показано» отражает текущий фильтр
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
        self.summary_total.setText(
            f"<b>Показано:</b> {shown:,}".replace(",", " ")
            + f" из {all_rows:,}".replace(",", " ")
            + f"<br><b>Файлов:</b> {files:,}".replace(",", " ")
            + f" &nbsp; <b>Папок:</b> {dirs:,}".replace(",", " ")
            + f"<br><b>Общий размер:</b> {human_size(total_size)}"
        )

        active_cat = self.f_category.currentText()
        rows = sorted(by_cat_count.items(), key=lambda kv: by_cat_size[kv[0]], reverse=True)
        self.cat_table.setRowCount(len(rows))
        for i, (cat, cnt) in enumerate(rows):
            name_item = QTableWidgetItem(cat)
            if cat == active_cat:  # подсветим активную категорию
                font = name_item.font()
                font.setBold(True)
                name_item.setFont(font)
            self.cat_table.setItem(i, 0, name_item)
            self.cat_table.setItem(i, 1, QTableWidgetItem(f"{cnt}"))
            size_item = QTableWidgetItem(human_size(by_cat_size[cat]) if by_cat_size[cat] else "—")
            size_item.setTextAlignment(int(Qt.AlignRight | Qt.AlignVCenter))
            self.cat_table.setItem(i, 2, size_item)
        self.cat_table.resizeColumnToContents(1)
        self.cat_table.resizeColumnToContents(2)

    def _on_category_clicked(self, row: int, _col: int) -> None:
        item = self.cat_table.item(row, 0)
        if item is None:
            return
        cat = item.text()
        # показываем список, чтобы были видны файлы
        if self.view_tree_rb.isChecked():
            self.view_list_rb.setChecked(True)
        # тоггл: повторный клик по активной категории — сброс фильтра
        if self.f_category.currentText() == cat:
            self.f_category.setCurrentIndex(0)  # «Все»
        else:
            idx = self.f_category.findText(cat)
            if idx >= 0:
                self.f_category.setCurrentIndex(idx)
        if not self.filter_btn.isChecked():
            self.filter_btn.setChecked(True)  # показать активный фильтр
        self.apply_filters()

    # ------------------------------------------------- открытие / контекст-меню
    def _entry_at(self, view, index):
        """FileEntry по индексу в заданном представлении (с учётом прокси)."""
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
                QMessageBox.critical(self, "Ошибка S3", s3client.err_text(exc))
            return
        if not os.path.exists(entry.path):
            QMessageBox.warning(self, "Недоступно", f"Объект не найден:\n{entry.path}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(entry.path))

    def _open_location(self, entry) -> None:
        if entry is None or self.mode == "s3":
            return
        target = entry.path if entry.is_dir else entry.parent
        QDesktopServices.openUrl(QUrl.fromLocalFile(target))

    def _open_selected(self, index) -> None:
        self._open_entry(self._entry_at(self.table, index))

    def _tree_double_clicked(self, index) -> None:
        entry = self._entry_at(self.tree, index)
        if entry is not None and not entry.is_dir:
            self._open_entry(entry)

    def _selected_entries(self):
        view = self.tree if self.view_tree_rb.isChecked() else self.table
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
                menu.addAction("Открыть по ссылке", lambda: self._open_entry(entry))
            if n:
                menu.addAction(f"Скачать… ({n})", self._s3_download)
                menu.addAction(f"Переместить под префикс… ({n})", self._s3_move)
                menu.addAction(f"Удалить… ({n})", self._s3_delete)
            menu.addAction("Копировать ключ",
                           lambda: QApplication.clipboard().setText(
                               s3client.key_from_path(entry.path, self.s3cfg.bucket)))
        else:
            menu.addAction("Открыть папку" if entry.is_dir else "Открыть файл",
                           lambda: self._open_entry(entry))
            menu.addAction("Открыть расположение", lambda: self._open_location(entry))
            menu.addAction("Копировать полный путь",
                           lambda: QApplication.clipboard().setText(entry.path))
        if not menu.isEmpty():
            menu.exec(view.viewport().mapToGlobal(pos))

    # ---- действия S3
    def _s3_keys_or_warn(self):
        keys = self._selected_s3_keys()
        if not keys:
            QMessageBox.information(self, "Нет выбора", "Выделите объекты (файлы) в списке.")
        return keys

    def _s3_download(self) -> None:
        keys = self._s3_keys_or_warn()
        if not keys:
            return
        dest = QFileDialog.getExistingDirectory(self, "Папка для скачивания")
        if not dest:
            return
        self.setCursor(Qt.WaitCursor)
        ok, errors = s3client.download_keys(self.s3cfg, keys, dest)
        self.unsetCursor()
        msg = f"Скачано: {ok} из {len(keys)}."
        if errors:
            msg += "\nОшибки:\n" + "\n".join(errors[:5])
        QMessageBox.information(self, "Скачивание", msg)

    def _s3_move(self) -> None:
        keys = self._s3_keys_or_warn()
        if not keys:
            return
        prefix, ok = QInputDialog.getText(self, "Переместить под префикс",
                                          "Целевой префикс (например archive/2025):")
        if not ok or not prefix.strip():
            return
        if QMessageBox.question(self, "Подтверждение",
                                f"Переместить {len(keys)} объектов под «{prefix.strip()}»?",
                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        self.setCursor(Qt.WaitCursor)
        moved, _f, errors = s3client.move_to_prefix(self.s3cfg, keys, prefix.strip())
        self.unsetCursor()
        msg = f"Перемещено: {moved} из {len(keys)}."
        if errors:
            msg += "\nОшибки:\n" + "\n".join(errors[:5])
        QMessageBox.information(self, "Перемещение", msg)
        self.start_scan()

    def _s3_delete(self) -> None:
        keys = self._s3_keys_or_warn()
        if not keys:
            return
        if QMessageBox.warning(self, "Удаление",
                               f"Удалить безвозвратно {len(keys)} объектов из «{self.s3cfg.bucket}»?",
                               QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        self.setCursor(Qt.WaitCursor)
        deleted, errors = s3client.delete_keys(self.s3cfg, keys)
        self.unsetCursor()
        msg = f"Удалено: {deleted} из {len(keys)}."
        if errors:
            msg += "\nОшибки:\n" + "\n".join(errors[:5])
        QMessageBox.information(self, "Удаление", msg)
        self.start_scan()

    def closeEvent(self, event):  # noqa: N802
        self.controller.stop()
        self.s3_controller.stop()
        # отключаем временные (не «запомненные») SMB-подключения этой сессии
        for target, persistent in self._smb_connections:
            if not persistent:
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
        self.setWindowTitle("Поиск дубликатов")
        self.resize(840, 640)
        self.entries = entries or []
        self.mode = mode
        self.root = root or ""
        self.s3cfg = s3cfg
        self.controller = _DedupController()
        self.groups = []

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Поля сравнения (дубль — где совпадают все отмеченные):"))
        frow = QHBoxLayout()
        self.field_cbs = {}
        for key, label in dedup.FIELDS:
            cb = QCheckBox(label)
            if key == "size":
                cb.setChecked(True)
            if key == "hash" and mode == "s3":
                cb.setEnabled(False)
                cb.setToolTip("Для S3 сравнение по хэшу недоступно (нужно скачивание)")
            self.field_cbs[key] = cb
            frow.addWidget(cb)
        frow.addStretch(1)
        layout.addLayout(frow)

        brow = QHBoxLayout()
        self.find_btn = QPushButton("Найти дубликаты")
        self.find_btn.clicked.connect(self._find)
        self.cancel_btn = QPushButton("Стоп")
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
        self.tree.setHeaderLabels(["Файл / группа", "Размер"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        layout.addWidget(self.tree, 1)

        act = QGroupBox("Действие: переместить дубли (в каждой группе остаётся 1 — самый старый)")
        al = QHBoxLayout(act)
        al.addWidget(QLabel("Куда:"))
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("префикс, напр. duplicates/" if mode == "s3"
                                            else r"папка, напр. D:\Дубли")
        al.addWidget(self.target_edit, 1)
        if mode != "s3":
            b = QPushButton("Обзор…")
            b.clicked.connect(self._browse)
            al.addWidget(b)
        self.move_btn = QPushButton("Переместить дубли")
        self.move_btn.setEnabled(False)
        self.move_btn.clicked.connect(self._move)
        al.addWidget(self.move_btn)
        layout.addWidget(act)

        close = QPushButton("Закрыть")
        close.clicked.connect(self.accept)
        layout.addWidget(close, alignment=Qt.AlignRight)

    def _selected_fields(self):
        return {k for k, cb in self.field_cbs.items() if cb.isChecked() and cb.isEnabled()}

    def _find(self):
        fields = self._selected_fields()
        if not fields:
            QMessageBox.warning(self, "Поля", "Отметьте хотя бы одно поле сравнения.")
            return
        self.find_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.move_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.summary.setText("Поиск…")
        self.tree.clear()
        self.controller.start(self.entries, fields, self._on_progress,
                              self._on_found, self._on_error)

    def _stop(self):
        self.controller.stop()
        self._reset_state()
        self.summary.setText("Остановлено.")

    def _on_progress(self, done, total):
        if total > 0:
            self.progress.setRange(0, total)
            self.progress.setValue(done)
            self.summary.setText(f"Хэширование: {done:,} из {total:,}…".replace(",", " "))

    def _on_found(self, groups):
        self.groups = groups
        self._reset_state()
        self._fill(groups)

    def _on_error(self, msg):
        self._reset_state()
        QMessageBox.critical(self, "Ошибка", msg)

    def _reset_state(self):
        self.find_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress.setVisible(False)

    def _fill(self, groups):
        self.tree.clear()
        wasted = dedup.wasted_bytes(groups)
        dup_files = sum(len(g) - 1 for g in groups)
        self.summary.setText(
            f"Групп: {len(groups):,} · лишних файлов: {dup_files:,} · "
            f"можно освободить: {human_size(wasted)}".replace(",", " ")
        )
        for g in groups:
            keep = dedup._kept_first(g)
            top = QTreeWidgetItem(
                self.tree, [f"Группа из {len(g)} · {g[0].name}",
                            human_size(sum(e.size for e in g))]
            )
            for e in g:
                mark = "   ← оставить" if e is keep else ""
                QTreeWidgetItem(top, [e.path + mark, human_size(e.size)])
        self.move_btn.setEnabled(bool(groups))

    def _browse(self):
        start = self.target_edit.text().strip() or os.path.expanduser("~")
        d = QFileDialog.getExistingDirectory(self, "Папка для дублей", start)
        if d:
            self.target_edit.setText(os.path.normpath(d))

    def _move(self):
        if not self.groups:
            return
        target = self.target_edit.text().strip().strip('"')
        if not target:
            QMessageBox.warning(self, "Куда", "Укажите папку/префикс назначения.")
            return
        dups = dedup.duplicates_to_move(self.groups)
        if not dups:
            QMessageBox.information(self, "Нет дублей", "Перемещать нечего.")
            return
        if self.mode != "s3" and os.path.normpath(target).lower().startswith(
                os.path.normpath(self.root).lower()):
            QMessageBox.warning(self, "Недопустимо",
                                "Папка назначения не должна быть внутри анализируемой.")
            return
        total = sum(e.size for e in dups)
        if QMessageBox.question(
            self, "Подтверждение",
            f"Переместить {len(dups)} файлов-дублей ({human_size(total)}) в:\n{target}\n"
            "(в каждой группе остаётся один — самый старый)\n\nПродолжить?",
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
        msg = f"Перемещено: {moved} из {len(dups)}."
        if errors:
            msg += "\nОшибки:\n" + "\n".join(errors[:5])
        QMessageBox.information(self, "Готово", msg)
        self.groups = []
        self.tree.clear()
        self.move_btn.setEnabled(False)
        self.summary.setText("Готово. Запустите анализ заново для актуализации списка.")

    def closeEvent(self, event):  # noqa: N802
        self.controller.stop()
        super().closeEvent(event)


class S3ConnectDialog(QDialog):
    """Подключение к S3 (AWS или S3-совместимое)."""

    def __init__(self, parent=None, cfg=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Подключение к S3")
        self.setMinimumWidth(520)
        cfg = cfg or s3client.S3Config()
        self.cfg = cfg
        form = QFormLayout()
        self.endpoint = QLineEdit(cfg.endpoint)
        self.endpoint.setPlaceholderText("для AWS оставьте пустым; иначе https://minio:9000")
        form.addRow("Endpoint:", self.endpoint)
        self.region = QLineEdit(cfg.region)
        self.region.setPlaceholderText("например us-east-1")
        form.addRow("Регион:", self.region)
        self.access = QLineEdit(cfg.access_key)
        form.addRow("Access Key:", self.access)
        self.secret = QLineEdit(cfg.secret_key)
        self.secret.setEchoMode(QLineEdit.Password)
        show = QCheckBox("Показать")
        show.toggled.connect(lambda on: self.secret.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password))
        srow = QHBoxLayout()
        srow.addWidget(self.secret, 1)
        srow.addWidget(show)
        sw = QWidget()
        sw.setLayout(srow)
        form.addRow("Secret Key:", sw)
        self.bucket = QLineEdit(cfg.bucket)
        form.addRow("Бакет:", self.bucket)
        self.prefix = QLineEdit(cfg.prefix)
        self.prefix.setPlaceholderText("необязательно: анализировать только этот префикс")
        form.addRow("Префикс:", self.prefix)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        form.addRow("", self.status)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        row = QHBoxLayout()
        test_btn = QPushButton("Проверить")
        test_btn.clicked.connect(self._test)
        save_btn = QPushButton("Сохранить и закрыть")
        save_btn.clicked.connect(self._save)
        cancel = QPushButton("Отмена")
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
        self.status.setText(("Успех: " if ok else "Ошибка: ") + msg)
        self.status.setStyleSheet("color:#27ae60;" if ok else "color:#c0392b;")

    def _save(self) -> None:
        cfg = self._collect()
        if not cfg.bucket:
            self.status.setText("Укажите бакет.")
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
        self.setWindowTitle("Правила S3: условия → действие")
        self.resize(840, 620)
        self.entries = entries or []
        self.cats = cats or []
        self.cfg = cfg
        self.matched = []
        self._rows = []

        layout = QVBoxLayout(self)
        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Имя правила:"))
        self.name_edit = QLineEdit(_safe_task_name("rule_" + (cfg.bucket if cfg else "s3")))
        name_row.addWidget(self.name_edit, 1)
        layout.addLayout(name_row)

        layout.addWidget(QLabel("Условия (объединяются по «И»):"))
        self._cond_area = QVBoxLayout()
        wrap = QWidget()
        wrap.setLayout(self._cond_area)
        layout.addWidget(wrap)
        add_btn = QPushButton("+ Добавить условие")
        add_btn.clicked.connect(self._add_row)
        layout.addWidget(add_btn, alignment=Qt.AlignLeft)

        act = QGroupBox("Действие")
        act_lay = QHBoxLayout(act)
        act_lay.addWidget(QLabel("Что делать:"))
        self.action_combo = QComboBox()
        self.action_combo.addItems(["Удалить", "Переместить под префикс"])
        self.action_combo.currentIndexChanged.connect(self._upd_action)
        act_lay.addWidget(self.action_combo)
        self.prefix_edit = QLineEdit()
        self.prefix_edit.setPlaceholderText("целевой префикс, напр. archive/2025")
        act_lay.addWidget(self.prefix_edit, 1)
        layout.addWidget(act)

        btns = QHBoxLayout()
        find_btn = QPushButton("Найти совпадения")
        find_btn.clicked.connect(self._find)
        self.run_btn = QPushButton("Выполнить")
        self.run_btn.clicked.connect(self._run)
        self.run_btn.setEnabled(False)
        btns.addWidget(find_btn)
        btns.addStretch(1)
        btns.addWidget(self.run_btn)
        layout.addLayout(btns)

        self.summary = QLabel("—")
        layout.addWidget(self.summary)
        self.preview = QTableWidget(0, 4)
        self.preview.setHorizontalHeaderLabels(["Имя", "Размер", "Категория", "Ключ"])
        self.preview.horizontalHeader().setStretchLastSection(True)
        self.preview.setEditTriggers(QTableWidget.NoEditTriggers)
        self.preview.verticalHeader().setVisible(False)
        layout.addWidget(self.preview, 1)

        # --- автоархивация по расписанию
        sched = QGroupBox("Автоархивация по расписанию (без подтверждения)")
        sl = QHBoxLayout(sched)
        sl.addWidget(QLabel("Периодичность:"))
        self.sched_freq = QComboBox()
        self.sched_freq.addItems(["Каждый день", "Каждые N часов", "Каждые N минут"])
        self.sched_freq.currentIndexChanged.connect(self._upd_sched)
        sl.addWidget(self.sched_freq)
        sl.addWidget(QLabel("N:"))
        self.sched_interval = QSpinBox()
        self.sched_interval.setRange(1, 999)
        self.sched_interval.setValue(6)
        sl.addWidget(self.sched_interval)
        sl.addWidget(QLabel("Время:"))
        self.sched_time = QTimeEdit(QTime(3, 0))
        self.sched_time.setDisplayFormat("HH:mm")
        sl.addWidget(self.sched_time)
        self.sched_system_cb = QCheckBox("как служба (SYSTEM)")
        self.sched_system_cb.setVisible(sys.platform == "win32")
        sl.addWidget(self.sched_system_cb)
        sl.addStretch(1)
        self.sched_btn = QPushButton("Создать задание автоархивации")
        self.sched_btn.clicked.connect(self._schedule)
        sl.addWidget(self.sched_btn)
        layout.addWidget(sched)

        close_btn = QPushButton("Закрыть")
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
            self.summary.setText("Задайте хотя бы одно условие.")
            return
        self.matched = rules.evaluate(self.entries, conds, time.time(), include_dirs=False)
        total = sum(e.size for e in self.matched)
        self.summary.setText(f"Совпало объектов: {len(self.matched)} · объём: {human_size(total)}")
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
                QMessageBox.warning(self, "Префикс", "Укажите целевой префикс.")
                return
            q = f"Переместить {len(keys)} объектов под «{target}»?"
        else:
            q = f"Удалить безвозвратно {len(keys)} объектов?"
        if QMessageBox.warning(self, "Подтверждение", q,
                               QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        self.setCursor(Qt.WaitCursor)
        if move:
            done, _f, errors = s3client.move_to_prefix(self.cfg, keys, target)
            word = "Перемещено"
        else:
            done, errors = s3client.delete_keys(self.cfg, keys)
            word = "Удалено"
        self.unsetCursor()
        msg = f"{word}: {done} из {len(keys)}."
        if errors:
            msg += "\nОшибки:\n" + "\n".join(errors[:5])
        QMessageBox.information(self, "Готово", msg)

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
            QMessageBox.warning(self, "Имя", "Укажите имя правила.")
            return
        if not conds:
            QMessageBox.warning(self, "Условия", "Задайте хотя бы одно условие.")
            return
        if move and not target:
            QMessageBox.warning(self, "Префикс", "Укажите целевой префикс.")
            return
        act_word = f"перемещать под «{target}»" if move else "УДАЛЯТЬ"
        if QMessageBox.warning(
            self, "Автоархивация S3",
            f"Задание будет ПО РАСПИСАНИЮ без подтверждения {act_word} объекты "
            f"бакета «{self.cfg.bucket}», подходящие под условия.\n\nСоздать задание?",
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
                self, "Готово",
                f"Задание автоархивации S3 «{name}» создано.\n"
                "Управление — кнопка «Расписание…».",
            )
        else:
            QMessageBox.critical(self, "Ошибка", f"Не удалось создать задание:\n{msg}")


class SmbConnectDialog(QDialog):
    """Диалог ввода учётных данных для подключения к сетевому хранилищу."""

    def __init__(self, parent=None, preset_path: str = "") -> None:
        super().__init__(parent)
        self.setWindowTitle("Подключение к сетевому хранилищу (SMB)")
        self.setMinimumWidth(440)

        self.scan_path: str = ""
        self.connected_target: str = ""
        self.persistent: bool = False

        form = QFormLayout()

        self.path_edit = QLineEdit(preset_path if preset_path.startswith("\\\\") else "")
        self.path_edit.setPlaceholderText(r"\\synology\share  или  \\192.168.1.10\share\папка")
        form.addRow("Сетевой путь:", self.path_edit)

        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText(r"имя_пользователя  (можно DOMAIN\user)")
        form.addRow("Логин:", self.user_edit)

        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        show_cb = QCheckBox("Показать")
        show_cb.toggled.connect(
            lambda on: self.pass_edit.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)
        )
        pass_row = QHBoxLayout()
        pass_row.addWidget(self.pass_edit, 1)
        pass_row.addWidget(show_cb)
        pass_wrap = QWidget()
        pass_wrap.setLayout(pass_row)
        form.addRow("Пароль:", pass_wrap)

        self.drive_combo = QComboBox()
        self.drive_combo.addItem("(без буквы диска)")
        self.drive_combo.addItems(netshare.free_drive_letters())
        form.addRow("Подключить как диск:", self.drive_combo)

        self.persistent_cb = QCheckBox("Запомнить подключение (между перезагрузками Windows)")
        form.addRow("", self.persistent_cb)

        self.hint = QLabel("")
        self.hint.setWordWrap(True)
        self.hint.setStyleSheet("color:#c0392b;")
        form.addRow("", self.hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Подключить")
        buttons.button(QDialogButtonBox.Cancel).setText("Отмена")
        buttons.accepted.connect(self._try_connect)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _try_connect(self) -> None:
        remote = self.path_edit.text().strip().strip('"')
        if not remote.replace("/", "\\").startswith("\\\\"):
            self.hint.setText("Укажите путь в формате \\\\server\\share")
            return

        drive = None
        if self.drive_combo.currentIndex() > 0:
            drive = self.drive_combo.currentText()

        self.setCursor(Qt.WaitCursor)
        ok, message, scan_path = netshare.connect(
            remote=remote,
            username=self.user_edit.text().strip(),
            password=self.pass_edit.text(),
            drive_letter=drive,
            persistent=self.persistent_cb.isChecked(),
        )
        self.unsetCursor()

        if not ok:
            self.hint.setText(message)
            return

        self.scan_path = scan_path
        self.persistent = self.persistent_cb.isChecked()
        self.connected_target = drive if drive else (netshare.share_root(remote) or remote)
        self.accept()


class TelegramDialog(QDialog):
    """Настройка бота и чата Telegram для уведомлений."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Уведомления Telegram")
        self.setMinimumWidth(480)
        token, chat = app_settings.get_telegram()

        form = QFormLayout()
        self.token_edit = QLineEdit(token)
        self.token_edit.setEchoMode(QLineEdit.Password)
        show = QCheckBox("Показать")
        show.toggled.connect(
            lambda on: self.token_edit.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)
        )
        trow = QHBoxLayout()
        trow.addWidget(self.token_edit, 1)
        trow.addWidget(show)
        tw = QWidget()
        tw.setLayout(trow)
        form.addRow("Токен бота:", tw)

        self.chat_edit = QLineEdit(chat)
        self.chat_edit.setPlaceholderText("например 123456789 или @username")
        form.addRow("Chat ID:", self.chat_edit)

        hint = QLabel(
            "Создайте бота у @BotFather и вставьте токен. Chat ID можно узнать у "
            "@userinfobot (или открыть https://api.telegram.org/bot<токен>/getUpdates "
            "после сообщения боту)."
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
        test_btn = QPushButton("Проверить (тест)")
        test_btn.clicked.connect(self._test)
        save_btn = QPushButton("Сохранить")
        save_btn.clicked.connect(self._save)
        close_btn = QPushButton("Закрыть")
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
            "✅ Тест уведомления — Анализатор папок",
        )
        self.unsetCursor()
        self.status.setText(("Успех: " if ok else "Ошибка: ") + msg)
        self.status.setStyleSheet("color:#27ae60;" if ok else "color:#c0392b;")

    def _save(self) -> None:
        app_settings.set_telegram(self.token_edit.text().strip(), self.chat_edit.text().strip())
        self.status.setText("Сохранено.")
        self.status.setStyleSheet("color:#27ae60;")


class SettingsDialog(QDialog):
    """Настройки: папка базы данных + доступ к настройкам Telegram."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Настройки")
        self.setMinimumWidth(580)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        layout.addLayout(form)

        current = app_settings.get_db_path() or default_db_path()
        db_row = QHBoxLayout()
        self.db_edit = QLineEdit(os.path.dirname(current))
        db_row.addWidget(self.db_edit, 1)
        browse = QPushButton("Обзор…")
        browse.clicked.connect(self._browse_db)
        db_row.addWidget(browse)
        db_wrap = QWidget()
        db_wrap.setLayout(db_row)
        form.addRow("Папка базы данных:", db_wrap)

        info = QLabel(f"Файл базы — analyzer.db в выбранной папке.\nТекущий: {current}")
        info.setWordWrap(True)
        form.addRow("", info)

        tg_btn = QPushButton("Настроить Telegram…")
        tg_btn.clicked.connect(lambda: TelegramDialog(self).exec())
        form.addRow("Уведомления:", tg_btn)

        # --- управление базой данных
        self._cur_db = current
        self.db_size_lbl = QLabel("")
        form.addRow("Размер базы:", self.db_size_lbl)

        self.scans_tree = QTreeWidget()
        self.scans_tree.setColumnCount(2)
        self.scans_tree.setHeaderLabels(["Снимок (папка/бакет)", "Объектов"])
        self.scans_tree.setRootIsDecorated(False)
        self.scans_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        form.addRow("Снимки:", self.scans_tree)

        db_btns = QHBoxLayout()
        vacuum_btn = QPushButton("Сжать базу (VACUUM)")
        vacuum_btn.clicked.connect(self._vacuum)
        del_snap_btn = QPushButton("Удалить выбранный снимок")
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
        save = QPushButton("Сохранить")
        save.clicked.connect(self._save)
        close = QPushButton("Закрыть")
        close.clicked.connect(self.reject)
        row.addStretch(1)
        row.addWidget(save)
        row.addWidget(close)
        layout.addLayout(row)

    def _browse_db(self) -> None:
        start = self.db_edit.text().strip() or os.path.expanduser("~")
        d = QFileDialog.getExistingDirectory(self, "Папка для базы данных", start)
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
                QTreeWidgetItem(self.scans_tree, [root_orig, f"{count:,}".replace(",", " ")])
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
            self.status.setText(f"База сжата: {human_size(before)} → {human_size(after)}")
            self.status.setStyleSheet("color:#27ae60;")
        except Exception as exc:  # noqa: BLE001
            self.status.setText(f"Не удалось сжать: {exc}")
            self.status.setStyleSheet("color:#c0392b;")
        self.unsetCursor()
        self._refresh_db_info()

    def _delete_snapshot(self) -> None:
        item = self.scans_tree.currentItem()
        if item is None:
            self.status.setText("Выберите снимок в списке.")
            return
        root = item.text(0)
        if QMessageBox.question(
            self, "Удалить снимок",
            f"Удалить из базы снимок:\n{root}?\n(данные на диске/в хранилище не трогаются)",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        try:
            db = FileDatabase(self._cur_db)
            db.delete_scan(root)
            db.close()
            self.status.setText("Снимок удалён. Для освобождения места нажмите «Сжать базу».")
            self.status.setStyleSheet("color:#27ae60;")
        except Exception as exc:  # noqa: BLE001
            self.status.setText(f"Ошибка: {exc}")
            self.status.setStyleSheet("color:#c0392b;")
        self._refresh_db_info()

    def _save(self) -> None:
        folder = self.db_edit.text().strip().strip('"')
        if not folder:
            self.status.setText("Укажите папку.")
            return
        try:
            os.makedirs(folder, exist_ok=True)
        except OSError as exc:
            self.status.setText(f"Папка недоступна: {exc}")
            return
        app_settings.set_db_path(os.path.join(folder, "analyzer.db"))
        self.status.setText("Сохранено. Путь к базе обновлён (применится к следующему анализу).")
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
            self._set(self.op_combo, [("старше", "older"), ("младше", "newer")])
            self._set(self.unit_combo, [(u, u) for u in rules.AGE_UNITS])
            op = num = unit = date = True
        elif kind == "size":
            self._set(self.op_combo, [("больше", "gt"), ("меньше", "lt")])
            self._set(self.unit_combo, [(u, u) for u in rules.SIZE_UNITS])
            op = num = unit = True
        elif kind == "ext":
            self.text_edit.setPlaceholderText("tmp, log, bak")
            text = True
        elif kind == "category":
            cat = True
        elif kind == "name":
            self._set(self.op_combo, [("содержит", "contains"),
                                      ("маска", "wildcard"), ("регэксп", "regex")])
            self.text_edit.setPlaceholderText("текст, ~$* или регэксп")
            op = text = True
        elif kind == "author":
            self.text_edit.setPlaceholderText("домен\\пользователь")
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
        self.setWindowTitle("Правила: условия → действие")
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
        name_row.addWidget(QLabel("Имя правила:"))
        self.name_edit = QLineEdit(_safe_task_name(self.root).replace("scan_", "rule_"))
        name_row.addWidget(self.name_edit, 1)
        layout.addLayout(name_row)

        layout.addWidget(QLabel("Условия (объединяются по «И»):"))

        self._cond_area = QVBoxLayout()
        wrap = QWidget()
        wrap.setLayout(self._cond_area)
        layout.addWidget(wrap)

        add_btn = QPushButton("+ Добавить условие")
        add_btn.clicked.connect(self._add_row)
        layout.addWidget(add_btn, alignment=Qt.AlignLeft)

        act_box = QGroupBox("Действие: переместить совпавшие файлы в папку")
        act_lay = QHBoxLayout(act_box)
        act_lay.addWidget(QLabel("Папка назначения:"))
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText(r"например  D:\Карантин")
        act_lay.addWidget(self.target_edit, 1)
        browse = QPushButton("Обзор…")
        browse.clicked.connect(self._browse_target)
        act_lay.addWidget(browse)
        layout.addWidget(act_box)

        btns = QHBoxLayout()
        find_btn = QPushButton("Найти совпадения")
        find_btn.clicked.connect(self._find)
        self.export_btn = QPushButton("Экспорт списка (CSV)")
        self.export_btn.clicked.connect(self._export)
        self.export_btn.setEnabled(False)
        self.move_btn = QPushButton("Выполнить перемещение")
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
        self.preview.setHorizontalHeaderLabels(["Имя", "Размер", "Категория", "Изменён", "Путь"])
        self.preview.horizontalHeader().setStretchLastSection(True)
        self.preview.setEditTriggers(QTableWidget.NoEditTriggers)
        self.preview.verticalHeader().setVisible(False)
        layout.addWidget(self.preview, 1)

        # --- автоархивация по расписанию
        sched_box = QGroupBox("Автоархивация по расписанию (без подтверждения)")
        sched_lay = QHBoxLayout(sched_box)
        sched_lay.addWidget(QLabel("Периодичность:"))
        self.sched_freq = QComboBox()
        self.sched_freq.addItems(["Каждый день", "Каждые N часов", "Каждые N минут"])
        self.sched_freq.currentIndexChanged.connect(self._update_sched_widgets)
        sched_lay.addWidget(self.sched_freq)
        sched_lay.addWidget(QLabel("N:"))
        self.sched_interval = QSpinBox()
        self.sched_interval.setRange(1, 999)
        self.sched_interval.setValue(6)
        sched_lay.addWidget(self.sched_interval)
        sched_lay.addWidget(QLabel("Время:"))
        self.sched_time = QTimeEdit(QTime(3, 0))
        self.sched_time.setDisplayFormat("HH:mm")
        sched_lay.addWidget(self.sched_time)
        self.sched_system_cb = QCheckBox("как служба (SYSTEM)")
        self.sched_system_cb.setToolTip(
            "Выполнять в фоне от имени SYSTEM без входа в систему "
            "(нужны права администратора при создании)."
        )
        self.sched_system_cb.setVisible(sys.platform == "win32")
        sched_lay.addWidget(self.sched_system_cb)
        sched_lay.addStretch(1)
        self.sched_btn = QPushButton("Создать задание автоархивации")
        self.sched_btn.clicked.connect(self._schedule)
        sched_lay.addWidget(self.sched_btn)
        layout.addWidget(sched_box)

        close_btn = QPushButton("Закрыть")
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
        d = QFileDialog.getExistingDirectory(self, "Папка назначения", start)
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
            self.summary.setText("Задайте хотя бы одно условие.")
            return
        self.matched = rules.evaluate(self.entries, conds, time.time(), include_dirs=False)
        total = sum(e.size for e in self.matched)
        self.summary.setText(
            f"Совпало файлов: {len(self.matched)} · объём: {human_size(total)}"
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
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить список", "matched.csv", "CSV (*.csv)")
        if not path:
            return
        try:
            rules.export_csv(self.matched, path)
            QMessageBox.information(self, "Готово", f"Сохранено строк: {len(self.matched)}")
        except OSError as exc:
            QMessageBox.critical(self, "Ошибка", str(exc))

    def _move(self) -> None:
        if not self.matched:
            return
        target = self.target_edit.text().strip().strip('"')
        if not target:
            QMessageBox.warning(self, "Нет папки", "Укажите папку назначения.")
            return
        if self.root and os.path.normpath(target).lower().startswith(
                os.path.normpath(self.root).lower()):
            QMessageBox.warning(
                self, "Недопустимо",
                "Папка назначения не должна находиться внутри анализируемой папки.",
            )
            return
        total = sum(e.size for e in self.matched)
        ans = QMessageBox.question(
            self, "Подтверждение",
            f"Переместить {len(self.matched)} файлов ({human_size(total)}) в:\n{target}\n\nПродолжить?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if ans != QMessageBox.Yes:
            return
        self.setCursor(Qt.WaitCursor)
        moved, freed, errors = rules.execute_move(self.matched, self.root or "", target)
        self.unsetCursor()
        msg = f"Перемещено: {moved} файлов, освобождено {human_size(freed)}."
        if errors:
            msg += f"\n\nОшибок: {len(errors)}\n" + "\n".join(errors[:5])
            if len(errors) > 5:
                msg += f"\n…и ещё {len(errors) - 5}."
        QMessageBox.information(self, "Готово", msg)
        self.matched = [e for e in self.matched if os.path.exists(e.path)]
        self._fill_preview()
        self.summary.setText(f"Осталось в списке: {len(self.matched)}")
        self.move_btn.setEnabled(bool(self.matched))
        self.export_btn.setEnabled(bool(self.matched))

    def _update_sched_widgets(self) -> None:
        idx = self.sched_freq.currentIndex()
        self.sched_interval.setEnabled(idx in (1, 2))
        self.sched_time.setEnabled(idx in (0, 1))

    def _schedule(self) -> None:
        name = self.name_edit.text().strip()
        conds = self._conditions()
        target = self.target_edit.text().strip().strip('"')
        if not name:
            QMessageBox.warning(self, "Имя", "Укажите имя правила.")
            return
        if not conds:
            QMessageBox.warning(self, "Условия", "Задайте хотя бы одно условие.")
            return
        if not target:
            QMessageBox.warning(self, "Папка", "Укажите папку назначения для переноса.")
            return
        if not self.root or not os.path.isdir(self.root):
            QMessageBox.warning(
                self, "Папка анализа",
                "Анализируемая папка недоступна — её путь нужен для запланированного запуска.",
            )
            return
        if os.path.normpath(target).lower().startswith(os.path.normpath(self.root).lower()):
            QMessageBox.warning(
                self, "Недопустимо",
                "Папка назначения не должна находиться внутри анализируемой папки.",
            )
            return

        ans = QMessageBox.question(
            self, "Автоархивация по расписанию",
            "Задание будет ПО РАСПИСАНИЮ, без окна и без подтверждения, "
            "перемещать подходящие под условия файлы:\n\n"
            f"из:  {self.root}\nв:   {target}\n\nСоздать задание?",
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
                self, "Готово",
                f"Задание автоархивации «{name}» создано.\n"
                "Управлять (запустить сейчас / удалить) можно кнопкой «Расписание…».",
            )
        else:
            QMessageBox.critical(self, "Ошибка", f"Не удалось создать задание:\n{msg}")


def _safe_task_name(path: str) -> str:
    base = os.path.basename(path.rstrip("\\/")) or path
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in base)
    return f"scan_{safe}" if safe else "scan"


class ScheduleDialog(QDialog):
    """Создание/управление заданиями Планировщика для инкрементного анализа."""

    def __init__(self, parent=None, path="", db_path=None,
                 recursive=True, include_dirs=True, read_authors=False, mode="file") -> None:
        super().__init__(parent)
        self.setWindowTitle("Запуск анализа по расписанию")
        self.setMinimumWidth(560)
        self.db_path = db_path
        self.mode = mode

        layout = QVBoxLayout(self)
        form = QFormLayout()
        layout.addLayout(form)

        self.path_edit = QLineEdit(path)
        if mode == "s3":
            self.path_edit.setReadOnly(True)
            form.addRow("Бакет S3:", self.path_edit)
        else:
            self.path_edit.setPlaceholderText(r"C:\Папка  или  \\server\share\folder")
            form.addRow("Папка:", self.path_edit)

        default_name = ("s3_" + path) if mode == "s3" else _safe_task_name(path)
        self.name_edit = QLineEdit(_safe_task_name(default_name))
        form.addRow("Имя задания:", self.name_edit)

        # периодичность
        self.freq_combo = QComboBox()
        self.freq_combo.addItems(["Каждый день", "Каждые N часов", "Каждые N минут"])
        self.freq_combo.currentIndexChanged.connect(self._update_freq_widgets)
        form.addRow("Периодичность:", self.freq_combo)

        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(1, 999)
        self.interval_spin.setValue(6)
        form.addRow("Интервал N:", self.interval_spin)

        self.time_edit = QTimeEdit(QTime(3, 0))
        self.time_edit.setDisplayFormat("HH:mm")
        form.addRow("Время запуска:", self.time_edit)

        self.authors_cb = QCheckBox("Определять автора (медленнее)")
        self.authors_cb.setChecked(read_authors)
        self.authors_cb.setVisible(mode != "s3")
        form.addRow("", self.authors_cb)
        self.recursive_cb = QCheckBox("С подпапками")
        self.recursive_cb.setChecked(recursive)
        self.recursive_cb.setVisible(mode != "s3")
        form.addRow("", self.recursive_cb)
        self._include_dirs = include_dirs

        # уведомление в Telegram при превышении размера папки/бакета
        notify_row = QHBoxLayout()
        label = "Уведомлять в Telegram, если размер бакета ≥" if mode == "s3" else \
                "Уведомлять в Telegram, если размер папки ≥"
        self.notify_cb = QCheckBox(label)
        notify_row.addWidget(self.notify_cb)
        self.notify_size = QDoubleSpinBox()
        self.notify_size.setRange(0.1, 1_000_000)
        self.notify_size.setDecimals(1)
        self.notify_size.setValue(100)
        self.notify_size.setEnabled(False)
        notify_row.addWidget(self.notify_size)
        self.notify_unit = QComboBox()
        self.notify_unit.addItems(["МБ", "ГБ", "ТБ"])
        self.notify_unit.setCurrentText("ГБ")
        self.notify_unit.setEnabled(False)
        notify_row.addWidget(self.notify_unit)
        notify_row.addStretch(1)
        self.notify_cb.toggled.connect(self.notify_size.setEnabled)
        self.notify_cb.toggled.connect(self.notify_unit.setEnabled)
        notify_wrap = QWidget()
        notify_wrap.setLayout(notify_row)
        form.addRow("", notify_wrap)

        self.system_cb = QCheckBox(
            "Запускать в фоне как службу (от SYSTEM, без входа в систему)"
        )
        self.system_cb.setToolTip(
            "Задание будет выполняться от имени SYSTEM в фоне даже без входа "
            "пользователя. Для создания нужны права администратора."
        )
        self.system_cb.setVisible(sys.platform == "win32")  # на Unix — cron от пользователя
        form.addRow("", self.system_cb)

        self.hint = QLabel("")
        self.hint.setWordWrap(True)
        form.addRow("", self.hint)

        create_btn = QPushButton("Создать / обновить задание")
        create_btn.clicked.connect(self._create)
        layout.addWidget(create_btn)

        layout.addWidget(QLabel("Существующие задания:"))
        self.tasks = QTreeWidget()
        self.tasks.setColumnCount(3)
        self.tasks.setHeaderLabels(["Задание", "Следующий запуск", "Статус"])
        self.tasks.setRootIsDecorated(False)
        layout.addWidget(self.tasks, 1)

        row = QHBoxLayout()
        run_btn = QPushButton("Запустить сейчас")
        run_btn.clicked.connect(self._run_now)
        del_btn = QPushButton("Удалить задание")
        del_btn.clicked.connect(self._delete)
        close_btn = QPushButton("Закрыть")
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
        path = self.path_edit.text().strip().strip('"')
        name = self.name_edit.text().strip()
        if self.mode != "s3" and not os.path.isdir(path):
            self.hint.setText("Папка недоступна или не существует.")
            return
        if not name:
            self.hint.setText("Укажите имя задания.")
            return
        notify_bytes = 0
        if self.notify_cb.isChecked():
            notify_bytes = int(self.notify_size.value() * SIZE_UNITS[self.notify_unit.currentText()])
            token, chat = app_settings.get_telegram()
            if not token or not chat:
                ans = QMessageBox.question(
                    self, "Telegram не настроен",
                    "Уведомления включены, но бот/чат Telegram ещё не заданы.\n"
                    "Открыть настройки Telegram сейчас?",
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
        self.hint.setText("Задание создано." if ok else f"Не удалось: {msg}")
        self._refresh_tasks()

    def _delete(self) -> None:
        name = self._selected_task()
        if not name:
            self.hint.setText("Выберите задание в списке.")
            return
        ok, msg = schedule_task.delete_task(name)
        self.hint.setText("Задание удалено." if ok else f"Не удалось: {msg}")
        self._refresh_tasks()

    def _run_now(self) -> None:
        name = self._selected_task()
        if not name:
            self.hint.setText("Выберите задание в списке.")
            return
        ok, msg = schedule_task.run_task_now(name)
        self.hint.setText("Задание запущено." if ok else f"Не удалось: {msg}")


def run_cli(argv) -> int:
    """Безоконный режим для запуска по расписанию: анализ + сохранение в базу."""
    import argparse
    import time

    from scanner import run_scan

    parser = argparse.ArgumentParser(description="Инкрементный анализ папки в базу")
    parser.add_argument("--scan", required=True, help="путь к папке")
    parser.add_argument("--no-recursive", action="store_true")
    parser.add_argument("--no-dirs", action="store_true")
    parser.add_argument("--authors", action="store_true")
    parser.add_argument("--db", default=None)
    parser.add_argument("--full", action="store_true", help="полный (не инкрементный) анализ")
    parser.add_argument("--notify-size", type=int, default=0, dest="notify_size",
                        help="порог размера папки (байт): при превышении — уведомление в Telegram")
    parser.add_argument("--settings-file", default=None, dest="settings_file",
                        help="путь к settings.json (для запуска от SYSTEM)")
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
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    print(f"Готово: всего {info['total']}, файлов {info['files']}, "
          f"новых/изменённых {info['changed']}, удалено {info['deleted']}")

    if args.notify_size:
        import datetime
        import notify
        total_size = sum(e.size for e in results if not e.is_dir)
        if total_size >= args.notify_size:
            stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            text = (
                "⚠️ Превышен порог размера папки\n"
                f"Папка: {args.scan}\n"
                f"Размер: {human_size(total_size)} (порог {human_size(args.notify_size)})\n"
                f"Файлов: {info['files']}\n"
                f"Время: {stamp}"
            )
            ok, msg = notify.notify(text, args.settings_file)
            print(f"Уведомление: {'отправлено' if ok else msg}")
    return 0


def run_apply_cli(argv) -> int:
    """Headless-применение сохранённого правила (для запуска по расписанию)."""
    import argparse
    import datetime
    import time

    parser = argparse.ArgumentParser(description="Автоархивация по правилу")
    parser.add_argument("--apply-rule", required=True, dest="rule")
    parser.add_argument("--rules-file", default=None)
    args = parser.parse_args(argv)

    rule = rules.get_rule(args.rule, args.rules_file)
    if rule is None:
        print(f"Правило не найдено: {args.rule}", file=sys.stderr)
        return 2

    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    log_dir = os.path.join(base, "FolderAnalyzer", "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"{rule.name}.log")

    lines: list[str] = []

    def log(msg: str) -> None:
        lines.append(msg)
        print(msg)

    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log(f"[{stamp}] Правило '{rule.name}': {rule.root} -> {rule.target}")
    code = 0
    try:
        rules.apply_rule(rule, time.time(), on_log=log)
    except Exception as exc:  # noqa: BLE001
        log(f"Ошибка: {exc}")
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

    parser = argparse.ArgumentParser(description="Плановый анализ бакета S3")
    parser.add_argument("--s3-scan", action="store_true")
    parser.add_argument("--db", default=None)
    parser.add_argument("--notify-size", type=int, default=0, dest="notify_size")
    parser.add_argument("--settings-file", default=None, dest="settings_file")
    args = parser.parse_args(argv)

    cfg_d = app_settings.get_s3(args.settings_file)
    if not cfg_d or not cfg_d.get("bucket"):
        print("Профиль S3 не настроен.", file=sys.stderr)
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
        print(f"Ошибка S3: {exc}", file=sys.stderr)
        return 1
    info = incremental_stats(entries, prior)
    if db is not None:
        try:
            db.save_scan(cfg.bucket, entries, _t.time())
        except Exception:  # noqa: BLE001
            pass
        db.close()
    print(f"S3 готово: всего {info['total']}, объектов {info['files']}, изменённых {info['changed']}")

    if args.notify_size:
        total_size = sum(e.size for e in entries if not e.is_dir)
        if total_size >= args.notify_size:
            stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            text = (
                "⚠️ Превышен порог размера бакета S3\n"
                f"Бакет: {cfg.bucket}\n"
                f"Размер: {human_size(total_size)} (порог {human_size(args.notify_size)})\n"
                f"Объектов: {info['files']}\n"
                f"Время: {stamp}"
            )
            ok, msg = notify.notify(text, args.settings_file)
            print(f"Уведомление: {'отправлено' if ok else msg}")
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
    app.setApplicationName("Анализатор папок")
    ip = _icon_path()
    if ip:
        app.setWindowIcon(QIcon(ip))
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
