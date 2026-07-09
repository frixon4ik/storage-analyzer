"""Запуск анализа по расписанию через Планировщик заданий Windows (schtasks).

Создаёт задание, которое запускает безоконный инкрементный анализ папки
(`pythonw app.py --scan ...`). Результат сохраняется в базу — так копятся
инкрементные обновления без участия пользователя.
"""

from __future__ import annotations

import csv
import io
import os
import subprocess
import sys

TASK_FOLDER = "FolderAnalyzer"  # папка заданий в Планировщике

_NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW — не мигать консолью
_WINDOWS = sys.platform == "win32"
CRON_MARKER = "# FolderAnalyzerJob:"  # метка наших заданий в crontab (Unix)


def python_runner() -> str:
    """Путь к pythonw.exe (без консоли), иначе к текущему python.exe."""
    exe = sys.executable
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    return pyw if os.path.exists(pyw) else exe


def script_path() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "app.py"))


def _exe_prefix() -> list[str]:
    if getattr(sys, "frozen", False):
        return [f'"{sys.executable}"']
    return [f'"{python_runner()}"', f'"{script_path()}"']


def build_command(path, recursive=True, include_dirs=True,
                  read_authors=False, db_path=None, notify_size=None,
                  settings_file=None) -> str:
    parts = _exe_prefix() + ["--scan", f'"{path}"']
    if not recursive:
        parts.append("--no-recursive")
    if not include_dirs:
        parts.append("--no-dirs")
    if read_authors:
        parts.append("--authors")
    if db_path:
        parts += ["--db", f'"{db_path}"']
    if notify_size:
        parts += ["--notify-size", str(int(notify_size))]
        # абсолютный путь к настройкам — чтобы задание от SYSTEM нашло токен Telegram
        if settings_file:
            parts += ["--settings-file", f'"{settings_file}"']
    return " ".join(parts)


def _tasks_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "FolderAnalyzer", "tasks")
    os.makedirs(d, exist_ok=True)
    return d


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name) or "task"


def _launcher_path(name: str) -> str:
    return os.path.join(_tasks_dir(), f"{_safe(name)}.cmd")


def _oem_encoding() -> str:
    """Кодировка консоли (для .cmd с не-ASCII путями)."""
    try:
        import ctypes
        return "cp" + str(ctypes.windll.kernel32.GetOEMCP())
    except Exception:  # noqa: BLE001
        return "utf-8"


def build_s3_command(db_path=None, notify_size=None, settings_file=None) -> str:
    """Команда планового анализа бакета S3 (берёт профиль из settings.json)."""
    parts = _exe_prefix() + ["--s3-scan"]
    if db_path:
        parts += ["--db", f'"{db_path}"']
    if notify_size:
        parts += ["--notify-size", str(int(notify_size))]
    if settings_file:
        parts += ["--settings-file", f'"{settings_file}"']
    return " ".join(parts)


def create_s3_task(name, kind="DAILY", time_str="03:00", interval=1,
                   db_path=None, notify_size=None, run_as_system=False) -> tuple[bool, str]:
    sf = None
    try:
        import settings
        sf = settings.default_settings_path()
    except Exception:  # noqa: BLE001
        sf = None
    cmdline = build_s3_command(db_path, notify_size, sf)
    if not _WINDOWS:
        return _cron_create(name, cmdline, kind, time_str, interval)
    return _create_with_launcher(name, cmdline, kind, time_str, interval, run_as_system)


def build_rule_command(rule_name: str, rules_file=None) -> str:
    """Команда headless-применения сохранённого правила (автоархивация)."""
    parts = _exe_prefix() + ["--apply-rule", f'"{rule_name}"']
    # явный путь к файлу правил — чтобы задание от SYSTEM нашло правило
    if rules_file:
        parts += ["--rules-file", f'"{rules_file}"']
    return " ".join(parts)


def _write_launcher_cmd(name: str, cmdline: str) -> str:
    """Создаёт .cmd-обёртку с командой (обходит лимит 261 символ у /TR)."""
    launcher = _launcher_path(name)
    content = "@echo off\r\n" + cmdline + "\r\n"
    with open(launcher, "w", encoding=_oem_encoding(), errors="replace", newline="") as f:
        f.write(content)
    return launcher


def _create_with_launcher(task_name, cmdline, kind, time_str, interval,
                          run_as_system=False) -> tuple[bool, str]:
    tn = f"{TASK_FOLDER}\\{task_name}"
    launcher = _write_launcher_cmd(task_name, cmdline)
    cmd = ["schtasks", "/Create", "/F", "/TN", tn, "/TR", f'"{launcher}"', "/SC", kind]
    if kind in ("MINUTE", "HOURLY"):
        cmd += ["/MO", str(max(1, int(interval)))]
    if time_str and kind in ("MINUTE", "HOURLY", "DAILY"):
        cmd += ["/ST", time_str]
    if run_as_system:
        # фон как служба: от имени SYSTEM, с наивысшими правами, без входа в систему
        cmd += ["/RU", "SYSTEM", "/RL", "HIGHEST"]
    ok, msg = _run(cmd)
    if not ok and run_as_system and ("denied" in msg.lower() or "отказан" in msg.lower()):
        msg += ("\n\nДля задания от SYSTEM запустите программу от имени "
                "администратора (правый клик → «Запуск от имени администратора»).")
    return ok, msg


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _run(cmd: list[str]) -> tuple[bool, str]:
    kw = {"creationflags": _NO_WINDOW} if _WINDOWS else {}
    try:
        res = subprocess.run(cmd, capture_output=True, **kw)
    except FileNotFoundError:
        return False, f"Команда не найдена: {cmd[0]}"
    text = _decode(res.stdout) + _decode(res.stderr)
    return res.returncode == 0, text.strip()


# ------------------------------------------------------------- cron (Unix)
def _cron_expr(kind, time_str, interval) -> str:
    try:
        hh, mm = (time_str or "3:0").split(":")[:2]
        hh, mm = int(hh), int(mm)
    except Exception:  # noqa: BLE001
        hh, mm = 3, 0
    n = max(1, int(interval))
    if kind == "HOURLY":
        return f"{mm} */{n} * * *"
    if kind == "MINUTE":
        return f"*/{n} * * * *"
    return f"{mm} {hh} * * *"  # DAILY


def _read_crontab():
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    except FileNotFoundError:
        return None
    return r.stdout if r.returncode == 0 else ""


def _write_crontab(text: str) -> tuple[bool, str]:
    try:
        r = subprocess.run(["crontab", "-"], input=text, capture_output=True, text=True)
    except FileNotFoundError:
        return False, "crontab не найден"
    return r.returncode == 0, (r.stderr or "").strip()


def _cron_create(name, cmdline, kind, time_str, interval) -> tuple[bool, str]:
    cur = _read_crontab()
    if cur is None:
        return False, "Планировщик cron недоступен."
    marker = CRON_MARKER + name
    lines = [ln for ln in cur.splitlines() if marker not in ln]
    lines.append(f"{_cron_expr(kind, time_str, interval)} {cmdline} {marker}")
    ok, err = _write_crontab("\n".join(lines).strip() + "\n")
    return ok, ("Создано (cron)." if ok else err or "Ошибка crontab")


def create_task(name, path, kind="DAILY", time_str="03:00", interval=1,
                recursive=True, include_dirs=True, read_authors=False,
                db_path=None, notify_size=None, run_as_system=False) -> tuple[bool, str]:
    """Создаёт/перезаписывает задание анализа. kind: MINUTE|HOURLY|DAILY."""
    settings_file = None
    if notify_size:
        try:
            import settings
            settings_file = settings.default_settings_path()
        except Exception:  # noqa: BLE001
            settings_file = None
    cmdline = build_command(path, recursive, include_dirs, read_authors,
                            db_path, notify_size, settings_file)
    if not _WINDOWS:
        return _cron_create(name, cmdline, kind, time_str, interval)
    return _create_with_launcher(name, cmdline, kind, time_str, interval, run_as_system)


def create_rule_task(task_name, rule_name, kind="DAILY", time_str="03:00",
                     interval=1, run_as_system=False) -> tuple[bool, str]:
    """Создаёт задание автоархивации — применяет сохранённое правило по графику."""
    rules_file = None
    try:
        import rules
        rules_file = rules.default_rules_path()
    except Exception:  # noqa: BLE001
        rules_file = None
    cmdline = build_rule_command(rule_name, rules_file)
    if not _WINDOWS:
        return _cron_create(task_name, cmdline, kind, time_str, interval)
    return _create_with_launcher(task_name, cmdline, kind, time_str, interval, run_as_system)


def list_tasks() -> list[dict]:
    """Список заданий: [{name, next_run, status}]."""
    if not _WINDOWS:
        cur = _read_crontab() or ""
        tasks = []
        for ln in cur.splitlines():
            i = ln.find(CRON_MARKER)
            if i >= 0:
                name = ln[i + len(CRON_MARKER):].strip()
                cron = " ".join(ln.split()[:5])
                tasks.append({"name": name, "next_run": "cron", "status": cron})
        return tasks
    ok, out = _run(["schtasks", "/Query", "/FO", "CSV", "/NH"])
    if not ok:
        return []
    tasks: list[dict] = []
    reader = csv.reader(io.StringIO(out))
    prefix = f"\\{TASK_FOLDER}\\"
    seen = set()
    for row in reader:
        if not row:
            continue
        tn = row[0]  # без /V первый столбец — TaskName
        if not tn.startswith(prefix):
            continue
        name = tn[len(prefix):]
        if name in seen:
            continue
        seen.add(name)
        next_run = row[1] if len(row) > 1 else ""
        status = row[2] if len(row) > 2 else ""
        tasks.append({"name": name, "next_run": next_run, "status": status})
    return tasks


def delete_task(name: str) -> tuple[bool, str]:
    if not _WINDOWS:
        cur = _read_crontab()
        if cur is None:
            return False, "cron недоступен."
        marker = CRON_MARKER + name
        lines = [ln for ln in cur.splitlines() if marker not in ln]
        ok, err = _write_crontab("\n".join(lines).strip() + "\n")
        return ok, ("Удалено." if ok else err)
    ok, msg = _run(["schtasks", "/Delete", "/F", "/TN", f"{TASK_FOLDER}\\{name}"])
    try:
        launcher = _launcher_path(name)
        if os.path.exists(launcher):
            os.remove(launcher)
    except OSError:
        pass
    return ok, msg


def run_task_now(name: str) -> tuple[bool, str]:
    if not _WINDOWS:
        cur = _read_crontab() or ""
        marker = CRON_MARKER + name
        for ln in cur.splitlines():
            if marker in ln:
                parts = ln.split(None, 5)
                body = parts[5].split(CRON_MARKER)[0].strip() if len(parts) > 5 else ""
                if not body:
                    return False, "Пустая команда."
                try:
                    subprocess.Popen(body, shell=True)
                    return True, "Запущено."
                except Exception as exc:  # noqa: BLE001
                    return False, str(exc)
        return False, "Задание не найдено."
    return _run(["schtasks", "/Run", "/TN", f"{TASK_FOLDER}\\{name}"])
