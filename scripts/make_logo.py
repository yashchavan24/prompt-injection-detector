import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from PIL import Image
from collections import deque

src = r"C:\Users\smita\Downloads\prompt-injection-detector-logo.jpg"
img = Image.open(src).convert("RGBA")
w, h = img.size
print("source size:", w, h)

# Make the white corners transparent (flood fill from the 4 corners).
px = img.load()

def is_white(p):
    r, g, b, a = p
    return r > 235 and g > 235 and b > 235

visited = set()
q = deque()
for start in [(0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)]:
    if is_white(px[start[0], start[1]]):
        q.append(start)
        visited.add(start)
while q:
    x, y = q.popleft()
    px[x, y] = (255, 255, 255, 0)
    for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
        nx, ny = x + dx, y + dy
        if 0 <= nx < w and 0 <= ny < h and (nx, ny) not in visited \
                and is_white(px[nx, ny]):
            visited.add((nx, ny))
            q.append((nx, ny))

# Save 512px PNG for the topbar / README.
logo = img.resize((512, 512), Image.LANCZOS)
logo.save("static/logo.png", optimize=True)

# Favicon (multi-size ICO).
img.resize((32, 32), Image.LANCZOS).save(
    "static/favicon.ico",
    sizes=[(16, 16), (32, 32), (48, 48)])

import os
print("logo.png:", os.path.getsize("static/logo.png"), "bytes")
print("favicon.ico:", os.path.getsize("static/favicon.ico"), "bytes")

# Sanity: corners of the 512 PNG should now be transparent, center opaque.
chk = Image.open("static/logo.png").convert("RGBA")
print("corner alpha:", chk.getpixel((2, 2))[3], "center:", chk.getpixel((256, 256)))
