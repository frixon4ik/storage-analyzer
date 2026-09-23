"""Сканирование папок: сбор метаданных файлов в фоновом потоке.

Работает с локальными дисками и сетевыми хранилищами (Synology, QNAP и др.),
подключёнными по SMB как UNC-пути (\\\\server\\share) или подключённые диски (Z:\\).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime

from PySide6.QtCore import QObject, QThread, Signal

import authors


# Сопоставление расширений с человеко-понятными категориями.
CATEGORY_MAP: dict[str, str] = {}


def _register(category: str, extensions: str) -> None:
    for ext in extensions.split():
        CATEGORY_MAP[ext] = category


_register("Images", "jpg jpeg png gif bmp tiff tif webp heic heif svg ico raw cr2 nef arw dng psd")
_register("Video", "mp4 mkv avi mov wmv flv webm m4v mpg mpeg 3gp ts m2ts vob mxf")
_register("Audio", "mp3 wav flac aac ogg wma m4a aiff alac opus mid")
_register("Documents", "pdf doc docx xls xlsx ppt pptx odt ods odp rtf txt md csv epub pages numbers key")
_register("Archives", "zip rar 7z tar gz bz2 xz iso dmg cab z lz lzma tgz")
_register("Code", "py js ts jsx tsx java c cpp h hpp cs go rs rb php swift kt sql sh bat ps1 html css json xml yaml yml toml ini")
_register("Executables", "exe msi dll bat cmd com app deb rpm apk")
_register("Fonts", "ttf otf woff woff2 eot")
_register("3D / CAD", "obj stl fbx step stp dwg dxf blend 3ds")


def category_for(extension: str) -> str:
    """Возвращает категорию по расширению (без точки, в нижнем регистре)."""
    if not extension:
        return "No extension"
    return CATEGORY_MAP.get(extension.lower(), "Other")


@dataclass(slots=True)
class FileEntry:
    """Метаданные одного элемента (файла или папки)."""

    name: str
    path: str
    parent: str
    is_dir: bool
    extension: str          # без точки, нижний регистр; "" для папок/без расширения
    category: str
    size: int               # в байтах (0 для папок)
    created: float          # unix-время
    modified: float
    accessed: float
    author: str = ""        # свойство System.Author (как в Проводнике)

    @property
    def created_dt(self) -> datetime:
        return datetime.fromtimestamp(self.created)

    @property
    def modified_dt(self) -> datetime:
        return datetime.fromtimestamp(self.modified)

    @property
    def accessed_dt(self) -> datetime:
        return datetime.fromtimestamp(self.accessed)

    @property
    def kind(self) -> str:
        return "Folder" if self.is_dir else "File"


def _ext_of(name: str) -> str:
    base, dot, tail = name.rpartition(".")
    return tail.lower() if dot and base else ""


def _make_entry(entry: os.DirEntry, parent: str, reader=None, prior=None) -> FileEntry | None:
    try:
        st = entry.stat(follow_symlinks=False)
        is_dir = entry.is_dir(follow_symlinks=False)
    except OSError:
        return None

    name = entry.name
    ext = "" if is_dir else _ext_of(name)

    author = ""
    if not is_dir:
        old = prior.get(entry.path) if prior else None
        # инкрементно: файл не изменился -> берём автора из базы, не читая заново
        if old is not None and old.size == st.st_size and abs(old.modified - st.st_mtime) <= 1:
            author = old.author
        elif reader is not None:
            author = reader.author_of(parent, name)

    return FileEntry(
        name=name,
        path=entry.path,
        parent=parent,
        is_dir=is_dir,
        extension=ext,
        category="Folder" if is_dir else category_for(ext),
        size=0 if is_dir else st.st_size,
        # macOS/BSD: настоящая дата создания — st_birthtime (st_ctime там —
        # время изменения метаданных); на Windows st_ctime — дата создания
        created=getattr(st, "st_birthtime", st.st_ctime),
        modified=st.st_mtime,
        accessed=st.st_atime,
        author=author,
    )


def count_tree(root: str, recursive: bool, include_dirs: bool, cancel=None) -> int:
    """Быстрый подсчёт количества элементов (без stat) — для шкалы прогресса."""
    total = 0
    stack = [root]
    while stack:
        if cancel and cancel():
            return total
        directory = stack.pop()
        try:
            with os.scandir(directory) as it:
                for entry in it:
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        is_dir = False
                    if not is_dir or include_dirs:
                        total += 1
                    if is_dir and recursive:
                        stack.append(entry.path)
        except (PermissionError, OSError):
            continue
    return total


def scan_tree(root, recursive, include_dirs, reader=None, prior=None,
              cancel=None, on_progress=None, total=0) -> list[FileEntry]:
    """Обходит дерево (итеративно) и собирает метаданные. on_progress(done, total)."""
    results: list[FileEntry] = []
    stack = [root]
    done = 0
    while stack:
        if cancel and cancel():
            break
        directory = stack.pop()
        try:
            with os.scandir(directory) as it:
                entries = list(it)
        except (PermissionError, OSError):
            continue
        for entry in entries:
            if cancel and cancel():
                break
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                is_dir = False
            if not is_dir or include_dirs:
                fe = _make_entry(entry, directory, reader, prior)
                if fe is not None:
                    results.append(fe)
                    done += 1
                    if on_progress and done % 200 == 0:
                        on_progress(done, total)
            if is_dir and recursive:
                stack.append(entry.path)
    if on_progress:
        on_progress(done, total)
    return results


def incremental_stats(results: list[FileEntry], prior: dict) -> dict:
    """Сравнивает текущий результат с предыдущим снимком из базы."""
    files = [e for e in results if not e.is_dir]
    seen = {e.path for e in files}
    changed = 0
    for e in files:
        old = prior.get(e.path)
        if old is None or old.size != e.size or abs(old.modified - e.modified) > 1:
            changed += 1
    prior_file_paths = {p for p, o in prior.items() if not o.is_dir}
    deleted = len(prior_file_paths - seen)
    return {
        "total": len(results),
        "files": len(files),
        "changed": changed,
        "deleted": deleted,
        "had_prior": bool(prior),
    }


def _fill_authors_parallel(entries, cancel=None, on_phase=None, on_total=None,
                           on_progress=None, workers=8):
    """Читает автора/владельца для списка файлов в несколько потоков.

    win32security потокобезопасен; Shell.Application — STA, поэтому у каждого
    потока свой AuthorReader (со своим CoInitialize)."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    if on_phase:
        on_phase("Reading authors/owners…")
    total = len(entries)
    if on_total:
        on_total(total)

    n = min(workers, max(1, (os.cpu_count() or 2)))
    chunks = [entries[i::n] for i in range(n)]   # непересекающиеся подсписки
    done = [0]
    lock = threading.Lock()

    def work(chunk):
        with authors.AuthorReader() as reader:
            for e in chunk:
                if cancel and cancel():
                    return
                e.author = reader.author_of(e.parent, e.name)
                with lock:
                    done[0] += 1
                    if on_progress and done[0] % 200 == 0:
                        on_progress(done[0], total)

    with ThreadPoolExecutor(max_workers=n) as ex:
        list(ex.map(work, [c for c in chunks if c]))
    if on_progress:
        on_progress(total, total)


def run_scan(root, recursive=True, include_dirs=True, read_authors=False,
             db_path=None, incremental=True, cancel=None, on_phase=None,
             on_total=None, on_progress=None, scan_time=0.0):
    """Полный сценарий анализа одной папки (используется и GUI, и CLI/расписанием).

    Возвращает (results, info). Если задан db_path — результат сохраняется в базу,
    а при incremental из базы берётся предыдущий снимок для ускорения.
    """
    if not os.path.isdir(root):
        raise NotADirectoryError(f"The path is not a folder or is not available: {root}")

    db = None
    prior: dict = {}
    if db_path:
        try:
            from db import FileDatabase  # импорт здесь, чтобы избежать циклической зависимости
            db = FileDatabase(db_path)
            if incremental:
                prior = db.load_entries(root)
        except Exception:  # noqa: BLE001
            db = None
            prior = {}

    # оценка общего числа: из базы (быстро), иначе неизвестно (без второго обхода)
    total = len(prior) if prior else 0
    if on_total:
        on_total(total)
    if on_phase:
        on_phase("Analyzing…")

    # обход без чтения автора (быстро); у неизменённых автор берётся из базы
    results = scan_tree(root, recursive, include_dirs, None, prior,
                        cancel, on_progress, total)

    # чтение автора/владельца — параллельно и только для новых/изменённых файлов
    use_authors = read_authors and authors.is_available()
    if use_authors and not (cancel and cancel()):
        todo = [e for e in results if not e.is_dir and not e.author]
        if todo:
            _fill_authors_parallel(todo, cancel, on_phase, on_total, on_progress)

    info = incremental_stats(results, prior)

    if db is not None and not (cancel and cancel()):
        try:
            db.save_scan(root, results, scan_time)
        except Exception:  # noqa: BLE001
            pass
    if db is not None:
        db.close()
    return results, info


class ScanWorker(QObject):
    """Фоновый обходчик каталога. Запускается в отдельном QThread."""

    phase = Signal(str)              # текст фазы («Подсчёт…», «Анализ…»)
    total = Signal(int)              # общее число элементов (для прогресса)
    progress = Signal(int, int)      # обработано, всего
    info = Signal(dict)              # инкрементная статистика
    finished = Signal(list)          # list[FileEntry]
    error = Signal(str)

    def __init__(self, root: str, recursive: bool, include_dirs: bool,
                 read_authors: bool = False, db_path: str | None = None,
                 incremental: bool = True, scan_time: float = 0.0) -> None:
        super().__init__()
        self.root = root
        self.recursive = recursive
        self.include_dirs = include_dirs
        self.read_authors = read_authors
        self.db_path = db_path
        self.incremental = incremental
        self.scan_time = scan_time
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def _is_cancelled(self) -> bool:
        return self._cancelled

    def run(self) -> None:
        try:
            results, info = run_scan(
                self.root, self.recursive, self.include_dirs, self.read_authors,
                db_path=self.db_path, incremental=self.incremental,
                cancel=self._is_cancelled,
                on_phase=self.phase.emit,
                on_total=self.total.emit,
                on_progress=self.progress.emit,
                scan_time=self.scan_time,
            )
            if not self._cancelled:
                self.info.emit(info)
            self.finished.emit(results)
        except Exception as exc:  # noqa: BLE001 — отдаём любую ошибку в UI
            self.error.emit(f"Scan error:\n{exc}")


class ScanController:
    """Удобная обёртка: создаёт поток и воркер, прокидывает сигналы.

    Сигналы воркера подключаются напрямую к слотам окна (QObject в главном
    потоке) — Qt автоматически доставляет их в главный поток, поэтому всё
    обновление интерфейса происходит безопасно. Поток корректно завершается
    через quit()/deleteLater без ожидания самого себя.
    """

    def __init__(self) -> None:
        self.thread: QThread | None = None
        self.worker: ScanWorker | None = None

    def start(self, root, recursive, include_dirs, on_progress, on_finished, on_error,
              read_authors=False, db_path=None, incremental=True, scan_time=0.0,
              on_phase=None, on_total=None, on_info=None):
        self.stop()
        self.thread = QThread()
        self.worker = ScanWorker(root, recursive, include_dirs, read_authors,
                                 db_path, incremental, scan_time)
        self.worker.moveToThread(self.thread)

        # запуск работы при старте потока
        self.thread.started.connect(self.worker.run)

        # слоты окна — доставляются в главный поток (очередь)
        self.worker.progress.connect(on_progress)
        self.worker.error.connect(on_error)
        self.worker.finished.connect(on_finished)
        if on_phase is not None:
            self.worker.phase.connect(on_phase)
        if on_total is not None:
            self.worker.total.connect(on_total)
        if on_info is not None:
            self.worker.info.connect(on_info)

        # завершение потока и уборка
        self.worker.finished.connect(self.thread.quit)
        self.worker.error.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(self._on_finished)

        self.thread.start()

    def _on_finished(self) -> None:
        # вызывается по сигналу thread.finished; просто отпускаем ссылки
        self.thread = None
        self.worker = None

    def stop(self) -> None:
        """Безопасная остановка (вызывается из главного потока)."""
        if self.worker is not None:
            self.worker.cancel()
            # подавляем сигналы брошенного воркера: даже если он завершится
            # позже нового сканирования, его finished не затрёт свежий результат
            self.worker.blockSignals(True)
        thread = self.thread
        if thread is not None:
            thread.quit()
            # ждём только если вызвано НЕ из самого рабочего потока
            if QThread.currentThread() is not thread:
                thread.wait(3000)
        self.thread = None
        self.worker = None
