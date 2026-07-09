"""Отправка уведомлений в Telegram через Bot API (только стандартная библиотека)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

import settings


def send_telegram(token: str, chat_id: str, text: str, timeout: int = 15) -> tuple[bool, str]:
    if not token or not chat_id:
        return False, "Не указан токен бота или chat_id."
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode("utf-8")
    try:
        with urllib.request.urlopen(url, data=data, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
        obj = json.loads(body)
        if obj.get("ok"):
            return True, "Сообщение отправлено."
        return False, obj.get("description", "Ошибка Telegram API.")
    except urllib.error.HTTPError as exc:
        try:
            desc = json.loads(exc.read().decode("utf-8", "replace")).get("description", "")
        except Exception:  # noqa: BLE001
            desc = ""
        return False, f"HTTP {exc.code}: {desc or exc.reason}"
    except urllib.error.URLError as exc:
        return False, f"Нет связи: {exc.reason}"
    except Exception as exc:  # noqa: BLE001
        return False, f"Ошибка: {exc}"


def notify(text: str, path: str | None = None) -> tuple[bool, str]:
    """Отправляет уведомление, взяв токен и chat_id из настроек."""
    token, chat_id = settings.get_telegram(path)
    if not token or not chat_id:
        return False, "Telegram не настроен."
    return send_telegram(token, chat_id, text)
