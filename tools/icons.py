from PIL import Image, ImageDraw, ImageFilter
import os
S = 4
def art(size, bleed):
    """foreground artwork on transparent canvas of `size`; bleed=True draws full bg too"""
    n = size * S
    im = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    u = n / 108.0           # 108dp adaptive canvas
    if bleed:
        d.rounded_rectangle([0, 0, n - 1, n - 1], radius=22 * u, fill=(42, 31, 39, 255))
    # paper with domed top
    px0, px1, py0, py1 = 36 * u, 72 * u, 24 * u, 66 * u
    d.rounded_rectangle([px0, py0, px1, py1 + 20 * u], radius=11 * u, fill=(244, 238, 226, 255))
    # typed lines
    for i, w in enumerate((22, 26, 15)):
        y = (36 + i * 7) * u
        d.rounded_rectangle([42 * u, y, (42 + w) * u, y + 2.2 * u], radius=1.1 * u, fill=(60, 48, 52, 255))
    # platen rail
    d.rounded_rectangle([24 * u, 63 * u, 84 * u, 69 * u], radius=3 * u, fill=(24, 18, 22, 255))
    d.rounded_rectangle([24 * u, 63 * u, 84 * u, 65 * u], radius=1 * u, fill=(70, 58, 64, 255))
    # carriage pill
    d.rounded_rectangle([46 * u, 59.5 * u, 62 * u, 72.5 * u], radius=6.5 * u, fill=(255, 226, 222, 255))
    for k, col in enumerate(((120, 200, 120), (60, 44, 50), (60, 44, 50))):
        cx = (50 + k * 4) * u
        d.ellipse([cx - 1.2 * u, 66 * u - 1.2 * u, cx + 1.2 * u, 66 * u + 1.2 * u], fill=col + (255,))
    # paper below rail cut (keep tidy): mask region below rail
    d.rectangle([20 * u, 73 * u, 88 * u, 90 * u], fill=(0, 0, 0, 0) if not bleed else (42, 31, 39, 255))
    return im.resize((size, size), Image.LANCZOS)

dens = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
for k, px in dens.items():
    art(px, True).save(f"res/mipmap-{k}/ic_launcher.png")
art(432, False).save("res/mipmap-xxxhdpi/ic_fg.png")
art(512, True).save("build/icon_512.png")
