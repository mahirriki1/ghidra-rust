#!/usr/bin/env python3
"""Render docs/images/ghidra-rust-logo.svg into the multi-size Windows icon.

Each size is drawn from the SVG with rsvg-convert and stored as a PNG image
inside the .ico, which Windows Vista and later read at every size.
"""

from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs/images/ghidra-rust-logo.svg"
OUTPUT = ROOT / "docs/images/ghidra-rust-icon.ico"
SIZES = (16, 24, 32, 48, 64, 256)


def png_size(data):
    if data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise ValueError("rsvg-convert did not produce a PNG")
    return struct.unpack(">II", data[16:24])


def main():
    images = []
    with tempfile.TemporaryDirectory() as temporary:
        for size in SIZES:
            path = Path(temporary) / f"{size}.png"
            subprocess.run(["rsvg-convert", "--width", str(size), "--height", str(size),
                            str(SOURCE), "-o", str(path)], check=True)
            data = path.read_bytes()
            if png_size(data) != (size, size):
                raise ValueError(f"Unexpected rendered size for {size}x{size}")
            images.append((size, data))
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = len(header) + 16 * len(images)
    entries, payload = b"", b""
    for size, data in images:
        # Width and height 0 mean 256 in an ICONDIRENTRY.
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32,
                               len(data), offset + len(payload))
        payload += data
    OUTPUT.write_bytes(header + entries + payload)
    print(f"Wrote {OUTPUT.relative_to(ROOT)} ({len(images)} sizes)")


if __name__ == "__main__":
    main()
