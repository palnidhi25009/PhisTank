"""
generate_icons.py
------------------
One-off script to generate the extension's toolbar icons as simple
geometric shapes (a shield outline) in the same ink/amber palette as
the web UI. Run once; the output PNGs are committed to icons/.

    python generate_icons.py
"""

from PIL import Image, ImageDraw

INK = (16, 19, 26, 255)        # #10131A
AMBER = (232, 163, 61, 255)    # #E8A33D
AMBER_DIM = (138, 101, 40, 255)  # #8A6528


def draw_shield(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = size * 0.12
    # Rounded background square
    draw.rounded_rectangle(
        [pad * 0.3, pad * 0.3, size - pad * 0.3, size - pad * 0.3],
        radius=size * 0.22,
        fill=INK,
    )

    # Shield shape: a simple polygon (pointed bottom, flat top) in amber
    cx = size / 2
    top = size * 0.28
    bottom = size * 0.82
    left = size * 0.32
    right = size * 0.68
    mid_y = size * 0.58

    shield_points = [
        (left, top),
        (right, top),
        (right, mid_y),
        (cx, bottom),
        (left, mid_y),
    ]
    draw.polygon(shield_points, fill=AMBER)

    # Small notch line inside the shield for a bit of detail/depth
    draw.line([(cx, top + size * 0.06), (cx, bottom - size * 0.14)], fill=AMBER_DIM, width=max(1, int(size * 0.03)))

    return img


if __name__ == "__main__":
    import os
    out_dir = os.path.join(os.path.dirname(__file__), "icons")
    os.makedirs(out_dir, exist_ok=True)
    for size in (16, 32, 48, 128):
        img = draw_shield(size)
        path = os.path.join(out_dir, f"icon{size}.png")
        img.save(path)
        print(f"Saved {path}")
