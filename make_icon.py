# -*- coding: utf-8 -*-
"""Генерация иконки приложения: питон (змейка) с лупой. Создаёт app_icon.ico и .png.

    python make_icon.py            # app_icon.png + app_icon.ico (+ простой .icns)
    python make_icon.py --macos    # только app_icon.icns по сетке macOS (нужен iconutil)
"""
import math
import os
import shutil
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw

SS = 4          # суперсэмплинг для сглаживания
S = 256 * SS    # рабочий размер


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def rounded_mask(size, radius):
    m = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(m)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return m


def make(macos_only=False):
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # --- фон: вертикальный градиент (синий) со скруглением
    top, bot = (74, 163, 255), (20, 64, 140)
    grad = Image.new("RGBA", (S, S))
    gd = grad.load()
    for y in range(S):
        c = lerp(top, bot, y / S)
        for x in range(S):
            gd[x, y] = (c[0], c[1], c[2], 255)
    img.paste(grad, (0, 0), rounded_mask(S, int(56 * SS)))

    d = ImageDraw.Draw(img)

    # --- змейка: вертикальная S-кривая
    cx = S * 0.42
    amp = S * 0.16
    y0, y1 = S * 0.16, S * 0.84
    pts = []
    n = 80
    for i in range(n + 1):
        t = i / n
        y = y0 + (y1 - y0) * t
        x = cx + amp * math.sin(t * math.pi * 2.05)
        pts.append((x, y))
    body_w = int(58 * SS)
    # тёмно-зелёная обводка + ярко-зелёное тело
    d.line(pts, fill=(28, 110, 60, 255), width=body_w + int(10 * SS), joint="curve")
    d.line(pts, fill=(67, 196, 99, 255), width=body_w, joint="curve")

    # голова (верхний конец) + глаз + язык
    hx, hy = pts[0]
    hr = int(40 * SS)
    d.ellipse([hx - hr, hy - hr, hx + hr, hy + hr], fill=(67, 196, 99, 255),
              outline=(28, 110, 60, 255), width=int(6 * SS))
    er = int(9 * SS)
    d.ellipse([hx + int(6 * SS) - er, hy - int(12 * SS) - er,
               hx + int(6 * SS) + er, hy - int(12 * SS) + er], fill=(20, 30, 30, 255))
    # язык (раздвоенный)
    d.line([(hx, hy - hr), (hx, hy - hr - int(26 * SS))], fill=(220, 60, 60, 255), width=int(7 * SS))
    d.line([(hx, hy - hr - int(26 * SS)), (hx - int(12 * SS), hy - hr - int(40 * SS))],
           fill=(220, 60, 60, 255), width=int(7 * SS))
    d.line([(hx, hy - hr - int(26 * SS)), (hx + int(12 * SS), hy - hr - int(40 * SS))],
           fill=(220, 60, 60, 255), width=int(7 * SS))

    # --- лупа (низ-право), линза частично над змейкой
    lx, ly = S * 0.66, S * 0.64
    lr = int(86 * SS)
    # стекло (полупрозрачное)
    glass = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    gdd = ImageDraw.Draw(glass)
    gdd.ellipse([lx - lr, ly - lr, lx + lr, ly + lr], fill=(230, 245, 255, 90))
    img.alpha_composite(glass)
    d = ImageDraw.Draw(img)
    # блик
    d.arc([lx - lr + int(16 * SS), ly - lr + int(16 * SS), lx - int(8 * SS), ly - int(8 * SS)],
          200, 320, fill=(255, 255, 255, 160), width=int(10 * SS))
    # оправа
    ring_w = int(22 * SS)
    d.ellipse([lx - lr, ly - lr, lx + lr, ly + lr], outline=(245, 180, 0, 255), width=ring_w)
    d.ellipse([lx - lr, ly - lr, lx + lr, ly + lr], outline=(180, 130, 0, 255), width=int(4 * SS))
    # ручка
    a = math.radians(45)
    hx0 = lx + (lr + ring_w // 2) * math.cos(a)
    hy0 = ly + (lr + ring_w // 2) * math.sin(a)
    hx1 = lx + (lr + int(80 * SS)) * math.cos(a)
    hy1 = ly + (lr + int(80 * SS)) * math.sin(a)
    d.line([(hx0, hy0), (hx1, hy1)], fill=(245, 180, 0, 255), width=int(34 * SS))
    d.line([(hx0, hy0), (hx1, hy1)], fill=(180, 130, 0, 255), width=int(10 * SS))

    if macos_only:
        make_macos_icns(img)
        return

    out = img.resize((256, 256), Image.LANCZOS)
    out.save("app_icon.png")
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    out.save("app_icon.ico", sizes=sizes)
    saved = "app_icon.png, app_icon.ico"
    try:  # для macOS
        img.resize((512, 512), Image.LANCZOS).save("app_icon.icns")
        saved += ", app_icon.icns"
    except Exception as exc:  # noqa: BLE001
        print("icns не создан:", exc)
    print("Сохранено:", saved)


def make_macos_icns(art, path="app_icon.icns"):
    """.icns по сетке Apple: рисунок 824×824 по центру холста 1024 + мягкая тень."""
    from PIL import ImageFilter

    canvas = 1024
    body = art.resize((824, 824), Image.LANCZOS)
    off = (canvas - 824) // 2
    shadow = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    alpha = body.split()[3].point(lambda a: int(a * 0.35))
    shadow.paste((0, 0, 0, 255), (off, off + 12), alpha)
    shadow = shadow.filter(ImageFilter.GaussianBlur(14))
    icon = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    icon.alpha_composite(shadow)
    icon.alpha_composite(body, (off, off))

    tmp = tempfile.mkdtemp()
    iconset = os.path.join(tmp, "app.iconset")
    os.makedirs(iconset)
    for size in (16, 32, 128, 256, 512):
        icon.resize((size, size), Image.LANCZOS).save(os.path.join(iconset, f"icon_{size}x{size}.png"))
        icon.resize((size * 2, size * 2), Image.LANCZOS).save(
            os.path.join(iconset, f"icon_{size}x{size}@2x.png"))
    try:
        subprocess.run(["iconutil", "--convert", "icns", "--output", path, iconset], check=True)
        print("Сохранено:", path)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    make(macos_only="--macos" in sys.argv)
