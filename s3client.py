"""Работа с объектным хранилищем S3 (AWS и S3-совместимые) через boto3.

Перечисляет объекты бакета и отдаёт их в виде FileEntry (как файловый сканер),
чтобы переисповать готовые таблицу, дерево, фильтры и сводку. «Папки» —
это префиксы ключей. Действия: удаление, перемещение (copy+delete), скачивание.

Ключи S3 разделяются «/». Чтобы переиспользовать построитель дерева (ориентирован
на пути с общим корнем), путь FileEntry формируется как  <бакет>/<ключ>, а корнем
дерева выступает имя бакета. Реальный ключ восстанавливается key_from_path().
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime

from scanner import FileEntry, category_for

try:
    import boto3
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import BotoCoreError, ClientError

    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


def is_available() -> bool:
    return _AVAILABLE


@dataclass
class S3Config:
    endpoint: str = ""        # пусто для AWS; иначе https://minio.local:9000 и т.п.
    access_key: str = ""
    secret_key: str = ""
    region: str = ""
    bucket: str = ""
    prefix: str = ""          # ограничить анализ префиксом (необязательно)


def _ext_of(name: str) -> str:
    base, dot, tail = name.rpartition(".")
    return tail.lower() if dot and base else ""


def make_client(cfg: S3Config):
    kwargs: dict = {}
    if cfg.endpoint:
        kwargs["endpoint_url"] = cfg.endpoint
    if cfg.region:
        kwargs["region_name"] = cfg.region
    if cfg.access_key:
        kwargs["aws_access_key_id"] = cfg.access_key
    if cfg.secret_key:
        kwargs["aws_secret_access_key"] = cfg.secret_key
    # для своих endpoint (MinIO/Ceph/IP) обычно нужен path-style и v4-подпись
    style = {"addressing_style": "path"} if cfg.endpoint else {}
    boto_cfg = BotoConfig(s3=style, signature_version="s3v4",
                          retries={"max_attempts": 3})
    return boto3.client("s3", config=boto_cfg, **kwargs)


def err_text(exc) -> str:
    if _AVAILABLE and isinstance(exc, ClientError):
        e = exc.response.get("Error", {})
        return f"{e.get('Code', '')}: {e.get('Message', str(exc))}".strip(": ")
    return str(exc)


def test_connection(cfg: S3Config) -> tuple[bool, str]:
    if not _AVAILABLE:
        return False, "The boto3 library is not installed."
    if not cfg.bucket:
        return False, "No bucket specified."
    try:
        client = make_client(cfg)
        client.head_bucket(Bucket=cfg.bucket)
        return True, "Connection successful."
    except Exception as exc:  # noqa: BLE001
        return False, err_text(exc)


def key_from_path(path: str, bucket: str) -> str:
    """Восстанавливает реальный ключ объекта из пути FileEntry (<бакет>/<ключ>)."""
    p = path.replace("\\", "/")
    prefix = bucket + "/"
    return p[len(prefix):] if p.startswith(prefix) else p


def _object_to_entry(key: str, size: int, ts: float, owner: str,
                     storage_class: str, bucket: str) -> FileEntry:
    name = key.rstrip("/").split("/")[-1]
    rel_parent = "/".join(key.rstrip("/").split("/")[:-1])
    parent = bucket + ("/" + rel_parent if rel_parent else "")
    ext = _ext_of(name)
    return FileEntry(
        name=name, path=bucket + "/" + key, parent=parent, is_dir=False,
        extension=ext, category=category_for(ext), size=size,
        created=ts, modified=ts, accessed=ts,
        author=owner or storage_class or "",
    )


def _dir_entry(rel_prefix: str, bucket: str) -> FileEntry:
    name = rel_prefix.rstrip("/").split("/")[-1]
    rel_parent = "/".join(rel_prefix.rstrip("/").split("/")[:-1])
    parent = bucket + ("/" + rel_parent if rel_parent else "")
    return FileEntry(
        name=name, path=bucket + "/" + rel_prefix, parent=parent, is_dir=True,
        extension="", category="Folder", size=0, created=0.0, modified=0.0,
        accessed=0.0, author="",
    )


def list_entries(cfg: S3Config, on_progress=None, cancel=None,
                 include_dirs: bool = True) -> list[FileEntry]:
    """Перечисляет все объекты бакета (под префиксом) и возвращает list[FileEntry]."""
    client = make_client(cfg)
    paginator = client.get_paginator("list_objects_v2")
    params: dict = {"Bucket": cfg.bucket, "FetchOwner": True}
    prefix = cfg.prefix.strip().lstrip("/")
    if prefix:
        params["Prefix"] = prefix

    files: list[FileEntry] = []
    dirs_seen: set[str] = set()
    count = 0

    for page in paginator.paginate(**params):
        if cancel and cancel():
            break
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/") and obj.get("Size", 0) == 0:
                dirs_seen.add(key.rstrip("/"))
                continue
            owner = ""
            o = obj.get("Owner") or {}
            owner = o.get("DisplayName") or o.get("ID", "") or ""
            sc = obj.get("StorageClass", "STANDARD")
            lm = obj.get("LastModified")
            ts = lm.timestamp() if lm else 0.0
            files.append(_object_to_entry(key, obj.get("Size", 0), ts, owner, sc, cfg.bucket))
            # запоминаем все родительские префиксы
            rel = "/".join(key.split("/")[:-1])
            while rel and rel not in dirs_seen:
                dirs_seen.add(rel)
                rel = "/".join(rel.split("/")[:-1])
            count += 1
            if on_progress and count % 500 == 0:
                on_progress(count)

    if on_progress:
        on_progress(count)

    entries = files
    if include_dirs:
        for d in dirs_seen:
            if d:
                entries.append(_dir_entry(d, cfg.bucket))
    return entries


# --------------------------------------------------------------------- действия
def delete_keys(cfg: S3Config, keys: list[str]) -> tuple[int, list[str]]:
    """Удаляет объекты пачками по 1000. Возвращает (удалено, [ошибки])."""
    client = make_client(cfg)
    deleted = 0
    errors: list[str] = []
    for i in range(0, len(keys), 1000):
        batch = [{"Key": k} for k in keys[i:i + 1000]]
        try:
            resp = client.delete_objects(Bucket=cfg.bucket, Delete={"Objects": batch, "Quiet": True})
            deleted += len(batch) - len(resp.get("Errors", []))
            for e in resp.get("Errors", []):
                errors.append(f"{e.get('Key')}: {e.get('Message')}")
        except Exception as exc:  # noqa: BLE001
            errors.append(err_text(exc))
    return deleted, errors


def move_key(cfg: S3Config, key: str, new_key: str) -> None:
    """Перемещает объект внутри бакета (copy + delete)."""
    client = make_client(cfg)
    client.copy_object(Bucket=cfg.bucket, Key=new_key,
                       CopySource={"Bucket": cfg.bucket, "Key": key})
    client.delete_object(Bucket=cfg.bucket, Key=key)


def move_to_prefix(cfg: S3Config, keys: list[str], target_prefix: str) -> tuple[int, int, list[str]]:
    """Переносит объекты под целевой префикс (сохраняя структуру ключей)."""
    moved = 0
    freed = 0  # для S3 «освобождение» условно — считаем перенесённый объём отдельно
    errors: list[str] = []
    tp = target_prefix.strip().strip("/")
    for key in keys:
        new_key = (tp + "/" + key) if tp else key
        if new_key == key:
            continue
        try:
            move_key(cfg, key, new_key)
            moved += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{key}: {err_text(exc)}")
    return moved, freed, errors


def download_keys(cfg: S3Config, keys: list[str], dest_dir: str) -> tuple[int, list[str]]:
    """Скачивает объекты в локальную папку (с сохранением структуры ключей)."""
    client = make_client(cfg)
    ok = 0
    errors: list[str] = []
    for key in keys:
        local = os.path.join(dest_dir, *key.split("/"))
        try:
            os.makedirs(os.path.dirname(local), exist_ok=True)
            client.download_file(cfg.bucket, key, local)
            ok += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{key}: {err_text(exc)}")
    return ok, errors


def presigned_url(cfg: S3Config, key: str, expires: int = 3600) -> str:
    client = make_client(cfg)
    return client.generate_presigned_url(
        "get_object", Params={"Bucket": cfg.bucket, "Key": key}, ExpiresIn=expires
    )
