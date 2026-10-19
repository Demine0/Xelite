"""Generates the Xelite tile/splash PNGs (white 'X' mark) without external libraries."""
import os, struct, sys, zlib

def png(path, w, h, pixels):
    raw = b"".join(b"\0" + bytes(pixels[y * w * 4:(y + 1) * w * 4]) for y in range(h))
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    data = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
    data += chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    open(path, "wb").write(data)

def seg_dist(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0, min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return ((px - ax - t * dx) ** 2 + (py - ay - t * dy) ** 2) ** 0.5

def render(w, h, size, bg=None, ss=3):
    """Draws an 'X' of the given size centred in a w*h canvas, with a small accent dot."""
    cx, cy, r, th = w / 2, h / 2, size / 2, size * 0.13
    pix = bytearray(w * h * 4)
    for y in range(h):
        for x in range(w):
            cov = dot = 0
            for sy in range(ss):
                for sx in range(ss):
                    px, py = x + (sx + .5) / ss, y + (sy + .5) / ss
                    d = min(seg_dist(px, py, cx - r, cy - r, cx + r, cy + r),
                            seg_dist(px, py, cx - r, cy + r, cx + r, cy - r))
                    if d <= th / 2:
                        cov += 1
                    elif ((px - (cx + r * 1.32)) ** 2 + (py - (cy - r * 1.32)) ** 2) ** .5 <= th * .55:
                        dot += 1
            a, ad = cov / ss / ss, dot / ss / ss
            i = (y * w + x) * 4
            base = bg + (255,) if bg else (0, 0, 0, 0)
            col = (255, 255, 255)
            acc = (0x2D, 0x7F, 0xF9)
            r_ = base[0] * (1 - a - ad) + col[0] * a + acc[0] * ad
            g_ = base[1] * (1 - a - ad) + col[1] * a + acc[1] * ad
            b_ = base[2] * (1 - a - ad) + col[2] * a + acc[2] * ad
            al = base[3] if bg else 255 * min(1, a + ad)
            if not bg and al:
                r_, g_, b_ = [(c * a * 255 + ac * ad * 255) / al for c, ac in zip(col, acc)]
            pix[i:i + 4] = bytes((int(r_), int(g_), int(b_), int(al)))
    return pix

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
for name, w, h, size, bg in [
    ("Square44x44Logo.png", 44, 44, 26, None),
    ("Square44x44Logo.targetsize-24_altform-unplated.png", 24, 24, 15, None),
    ("Square150x150Logo.png", 150, 150, 60, None),
    ("Wide310x150Logo.png", 310, 150, 60, None),
    ("StoreLogo.png", 50, 50, 28, (0x0B, 0x14, 0x26)),
    ("SplashScreen.png", 620, 300, 110, None),
]:
    png(os.path.join(out, name), w, h, render(w, h, size, bg))
    print("wrote", name)
