"""Pure-Python PNG codec, smart auto-crop, Kitty TGP, and half-block renderer."""

from __future__ import annotations

import base64
import importlib
import io
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich import box
from rich.color import Color, ColorSystem
from rich.panel import Panel
from rich.style import Style
from rich.text import Text

from soclens.config import get_tui_image_protocol

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_BG_RGB = (24, 28, 36)
_HALF_BLOCK = "\u2580"
_MAX_DIM = 16384
_MAX_PIXELS = 25_000_000
_KITTY_PLACEHOLDER_CP = 0x10EEEE
_KITTY_ID_MIN = 0x524601
_KITTY_ID_MAX = 0x52FFFF
_KITTY_ID_LOCK = threading.Lock()
_KITTY_ID_COUNTER = _KITTY_ID_MIN - 1

_UNSET = object()
_TERMINAL_PROBE_LOCK = threading.Lock()
_TERMINAL_PROBE_DONE = False
_TERMINAL_PROBE_RESULT: str | None = None

VALID_IMAGE_PROTOCOLS: frozenset[str] = frozenset({"kitty", "iterm2", "sixel", "halfblock"})

_KITTY_QUERY_ACK_RE = re.compile(
    rb"\x1b_G(?:[^\x1b\x07;]*,)?i=31(?:,[^\x1b\x07;]*)?;OK(?:\x1b\\|\x07)"
)
_XTVERSION_RE = re.compile(rb"\x1bP>\|([^\x1b\x07]*)(?:\x1b\\|\x07)")
_DA1_RE = re.compile(rb"\x1b\[\?([0-9;]*)c")

_ITERM2_TERM_PROGRAMS: frozenset[str] = frozenset({"iterm.app", "wezterm", "mintty", "tabby"})
_NON_PIXEL_TERM_PROGRAMS: frozenset[str] = frozenset(
    {"apple_terminal", "vscode", "alacritty", "warpterminal", "hyper", "rio"}
)
_NON_PIXEL_ENV_VARS: tuple[str, ...] = (
    "VSCODE_PID",
    "VSCODE_INJECTION",
    "VSCODE_IPC_HOOK_CLI",
    "CURSOR_TRACE_ID",
    "ALACRITTY_SOCKET",
    "ALACRITTY_WINDOW_ID",
    "GNOME_TERMINAL_SCREEN",
    "VTE_VERSION",
    "WARP_IS_LOCAL_SHELL_SESSION",
    "ConEmuPID",
)
_NON_PIXEL_TERM_TOKENS: tuple[str, ...] = (
    "dumb",
    "alacritty",
    "rxvt",
    "vt100",
    "linux",
)

_SIXEL_C_LUT: tuple[int, ...] = tuple(min(5, (v * 5 + 127) // 255) for v in range(256))
_SIXEL_G_LUT: tuple[int, ...] = tuple(216 + min(31, (v * 31 + 127) // 255) for v in range(256))
_SIXEL_CHAR_TRANS: bytes = bytes(63 + i for i in range(64)) + bytes(192)
_SIXEL_RLE_RE = re.compile(r"(.)\1{3,}")

# Exact first 256 combining diacritic codepoints from Kitty's rowcolumn-diacritics.txt
_KITTY_DIACRITIC_CODEPOINTS: tuple[int, ...] = (
    0x0305, 0x030D, 0x030E, 0x0310, 0x0312, 0x033D, 0x033E, 0x033F,
    0x0346, 0x034A, 0x034B, 0x034C, 0x0350, 0x0351, 0x0352, 0x0357,
    0x035B, 0x0363, 0x0364, 0x0365, 0x0366, 0x0367, 0x0368, 0x0369,
    0x036A, 0x036B, 0x036C, 0x036D, 0x036E, 0x036F, 0x0483, 0x0484,
    0x0485, 0x0486, 0x0487, 0x0592, 0x0593, 0x0594, 0x0595, 0x0597,
    0x0598, 0x0599, 0x059C, 0x059D, 0x059E, 0x059F, 0x05A0, 0x05A1,
    0x05A8, 0x05A9, 0x05AB, 0x05AC, 0x05AF, 0x05C4, 0x0610, 0x0611,
    0x0612, 0x0613, 0x0614, 0x0615, 0x0616, 0x0617, 0x0657, 0x0658,
    0x0659, 0x065A, 0x065B, 0x065D, 0x065E, 0x06D6, 0x06D7, 0x06D8,
    0x06D9, 0x06DA, 0x06DB, 0x06DC, 0x06DF, 0x06E0, 0x06E1, 0x06E2,
    0x06E4, 0x06E7, 0x06E8, 0x06EB, 0x06EC, 0x0730, 0x0732, 0x0733,
    0x0735, 0x0736, 0x073A, 0x073D, 0x073F, 0x0740, 0x0741, 0x0743,
    0x0745, 0x0747, 0x0749, 0x074A, 0x07EB, 0x07EC, 0x07ED, 0x07EE,
    0x07EF, 0x07F0, 0x07F1, 0x07F3, 0x0816, 0x0817, 0x0818, 0x0819,
    0x081B, 0x081C, 0x081D, 0x081E, 0x081F, 0x0820, 0x0821, 0x0822,
    0x0823, 0x0825, 0x0826, 0x0827, 0x0829, 0x082A, 0x082B, 0x082C,
    0x082D, 0x0951, 0x0953, 0x0954, 0x0F82, 0x0F83, 0x0F86, 0x0F87,
    0x135D, 0x135E, 0x135F, 0x17DD, 0x193A, 0x1A17, 0x1A75, 0x1A76,
    0x1A77, 0x1A78, 0x1A79, 0x1A7A, 0x1A7B, 0x1A7C, 0x1B6B, 0x1B6D,
    0x1B6E, 0x1B6F, 0x1B70, 0x1B71, 0x1B72, 0x1B73, 0x1CD0, 0x1CD1,
    0x1CD2, 0x1CDA, 0x1CDB, 0x1CE0, 0x1DC0, 0x1DC1, 0x1DC3, 0x1DC4,
    0x1DC5, 0x1DC6, 0x1DC7, 0x1DC8, 0x1DC9, 0x1DCB, 0x1DCC, 0x1DD1,
    0x1DD2, 0x1DD3, 0x1DD4, 0x1DD5, 0x1DD6, 0x1DD7, 0x1DD8, 0x1DD9,
    0x1DDA, 0x1DDB, 0x1DDC, 0x1DDD, 0x1DDE, 0x1DDF, 0x1DE0, 0x1DE1,
    0x1DE2, 0x1DE3, 0x1DE4, 0x1DE5, 0x1DE6, 0x1DFE, 0x20D0, 0x20D1,
    0x20D4, 0x20D5, 0x20D6, 0x20D7, 0x20DB, 0x20DC, 0x20E1, 0x20E7,
    0x20E9, 0x20F0, 0x2CEF, 0x2CF0, 0x2CF1, 0x2DE0, 0x2DE1, 0x2DE2,
    0x2DE3, 0x2DE4, 0x2DE5, 0x2DE6, 0x2DE7, 0x2DE8, 0x2DE9, 0x2DEA,
    0x2DEB, 0x2DEC, 0x2DED, 0x2DEE, 0x2DEF, 0x2DF0, 0x2DF1, 0x2DF2,
    0x2DF3, 0x2DF4, 0x2DF5, 0x2DF6, 0x2DF7, 0x2DF8, 0x2DF9, 0x2DFA,
    0x2DFB, 0x2DFC, 0x2DFD, 0x2DFE, 0x2DFF, 0xA66F, 0xA67C, 0xA67D,
    0xA6F0, 0xA6F1, 0xA8E0, 0xA8E1, 0xA8E2, 0xA8E3, 0xA8E4, 0xA8E5,
)
_KITTY_DIACRITICS: tuple[str, ...] = tuple(chr(cp) for cp in _KITTY_DIACRITIC_CODEPOINTS)

_COLOR_CHANNELS: dict[int, int] = {
    0: 1,  # Grayscale
    2: 3,  # RGB
    3: 1,  # Indexed palette
    4: 2,  # Grayscale + Alpha
    6: 4,  # RGBA
}

_VALID_BIT_DEPTHS: dict[int, tuple[int, ...]] = {
    0: (1, 2, 4, 8, 16),
    2: (8, 16),
    3: (1, 2, 4, 8),
    4: (8, 16),
    6: (8, 16),
}

_ADAM7_PASSES: tuple[tuple[int, int, int, int], ...] = (
    (0, 0, 8, 8),
    (4, 0, 8, 8),
    (0, 4, 4, 8),
    (2, 0, 4, 4),
    (0, 2, 2, 4),
    (1, 0, 2, 2),
    (0, 1, 1, 2),
)


@dataclass(slots=True)
class DecodedImage:
    """Decoded 8-bit RGB image frame ready for terminal rendering."""

    width: int
    height: int
    color_type: int
    bit_depth: int
    raw_size: int
    rgb_rows: list[bytes]


def _blend_over_bg(r: int, g: int, b: int, a: int) -> tuple[int, int, int]:
    if a >= 255:
        return (r, g, b)
    if a <= 0:
        return _BG_RGB
    inv = 255 - a
    return (
        (r * a + _BG_RGB[0] * inv + 127) // 255,
        (g * a + _BG_RGB[1] * inv + 127) // 255,
        (b * a + _BG_RGB[2] * inv + 127) // 255,
    )


def _unfilter_pass(
    raw: bytes,
    offset: int,
    width: int,
    height: int,
    channels: int,
    bit_depth: int,
) -> tuple[int, list[bytes]]:
    if width <= 0 or height <= 0:
        return offset, []

    bpp = max(1, (channels * bit_depth + 7) // 8)
    stride = (width * channels * bit_depth + 7) // 8
    needed = offset + height * (1 + stride)
    if needed > len(raw):
        raise ValueError("Truncated PNG image scanline data")

    rows: list[bytes] = []
    prev = bytearray(stride)
    pos = offset

    for _ in range(height):
        ftype = raw[pos]
        pos += 1
        src = raw[pos : pos + stride]
        pos += stride

        if ftype == 0:
            row = bytearray(src)
        elif ftype == 1:
            row = bytearray(src)
            for i in range(bpp, stride):
                row[i] = (row[i] + row[i - bpp]) & 0xFF
        elif ftype == 2:
            row = bytearray(src)
            for i in range(stride):
                row[i] = (row[i] + prev[i]) & 0xFF
        elif ftype == 3:
            row = bytearray(src)
            for i in range(bpp):
                row[i] = (row[i] + (prev[i] >> 1)) & 0xFF
            for i in range(bpp, stride):
                row[i] = (row[i] + ((row[i - bpp] + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:
            row = bytearray(src)
            for i in range(bpp):
                row[i] = (row[i] + prev[i]) & 0xFF
            for i in range(bpp, stride):
                a = row[i - bpp]
                b = prev[i]
                c = prev[i - bpp]
                p = a + b - c
                pa = abs(p - a)
                pb = abs(p - b)
                pc = abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                row[i] = (row[i] + pr) & 0xFF
        else:
            raise ValueError(f"Unsupported PNG scanline filter type: {ftype}")

        rows.append(bytes(row))
        prev = row

    return pos, rows


def _unpack_samples(row: bytes, count: int, bit_depth: int) -> list[int]:
    if bit_depth == 8:
        return list(row[:count])
    if bit_depth == 16:
        return [row[2 * i] for i in range(count)]
    mask = (1 << bit_depth) - 1
    samples_per_byte = 8 // bit_depth
    out: list[int] = []
    for i in range(count):
        byte_val = row[i // samples_per_byte]
        shift = 8 - bit_depth * (1 + (i % samples_per_byte))
        out.append((byte_val >> shift) & mask)
    return out


def _build_palette_lut(plte: bytes, trns: bytes) -> list[tuple[int, int, int]]:
    n_colors = len(plte) // 3
    lut: list[tuple[int, int, int]] = []
    for idx in range(256):
        if idx < n_colors:
            r, g, b = plte[3 * idx], plte[3 * idx + 1], plte[3 * idx + 2]
            alpha = trns[idx] if idx < len(trns) else 255
            lut.append(_blend_over_bg(r, g, b, alpha))
        else:
            lut.append(_BG_RGB)
    return lut


def _scanline_to_rgb(
    row: bytes,
    width: int,
    color_type: int,
    bit_depth: int,
    palette_lut: list[tuple[int, int, int]],
    trns: bytes,
) -> bytes:
    # Fast paths for the dominant 8-bit PNG types
    if color_type == 2 and bit_depth == 8 and not trns:
        return row[: width * 3]

    if color_type == 3 and bit_depth == 8:
        out = bytearray(width * 3)
        for x in range(width):
            r, g, b = palette_lut[row[x]]
            p = x * 3
            out[p] = r
            out[p + 1] = g
            out[p + 2] = b
        return bytes(out)

    channels = _COLOR_CHANNELS[color_type]
    samples = _unpack_samples(row, width * channels, bit_depth)
    out = bytearray(width * 3)

    if color_type == 0:
        max_val = (1 << bit_depth) - 1
        trns_gray: int | None = None
        if len(trns) >= 2:
            raw_t = struct.unpack(">H", trns[:2])[0]
            trns_gray = raw_t >> 8 if bit_depth == 16 else raw_t
        for x in range(width):
            s = samples[x]
            if trns_gray is not None and s == trns_gray:
                r, g, b = _BG_RGB
            else:
                v = s if bit_depth in (8, 16) else (s * 255) // max_val
                r = g = b = v
            p = x * 3
            out[p] = r
            out[p + 1] = g
            out[p + 2] = b
        return bytes(out)

    if color_type == 2:
        trns_rgb: tuple[int, int, int] | None = None
        if len(trns) >= 6:
            tr, tg, tb = struct.unpack(">HHH", trns[:6])
            if bit_depth == 16:
                tr, tg, tb = tr >> 8, tg >> 8, tb >> 8
            trns_rgb = (tr, tg, tb)
        for x in range(width):
            i = x * 3
            r, g, b = samples[i], samples[i + 1], samples[i + 2]
            if trns_rgb is not None and (r, g, b) == trns_rgb:
                r, g, b = _BG_RGB
            out[i] = r
            out[i + 1] = g
            out[i + 2] = b
        return bytes(out)

    if color_type == 3:
        for x in range(width):
            r, g, b = palette_lut[samples[x]]
            p = x * 3
            out[p] = r
            out[p + 1] = g
            out[p + 2] = b
        return bytes(out)

    if color_type == 4:
        for x in range(width):
            i = x * 2
            v, a = samples[i], samples[i + 1]
            r, g, b = _blend_over_bg(v, v, v, a)
            p = x * 3
            out[p] = r
            out[p + 1] = g
            out[p + 2] = b
        return bytes(out)

    # color_type == 6 (RGBA)
    for x in range(width):
        i = x * 4
        r, g, b = _blend_over_bg(samples[i], samples[i + 1], samples[i + 2], samples[i + 3])
        p = x * 3
        out[p] = r
        out[p + 1] = g
        out[p + 2] = b
    return bytes(out)


def decode_png(data: bytes) -> DecodedImage:
    """Decode a PNG byte stream into RGB scanline rows without external dependencies."""
    if not data.startswith(_PNG_SIGNATURE):
        raise ValueError("Invalid PNG signature")

    pos = len(_PNG_SIGNATURE)
    width = height = bit_depth = color_type = interlace = 0
    saw_ihdr = False
    plte = b""
    trns = b""
    idat = bytearray()

    while pos + 8 <= len(data):
        length, chunk_type = struct.unpack(">I4s", data[pos : pos + 8])
        chunk_start = pos + 8
        chunk_end = chunk_start + length
        if chunk_end + 4 > len(data):
            raise ValueError("Truncated PNG chunk")
        chunk = data[chunk_start:chunk_end]
        pos = chunk_end + 4

        if chunk_type == b"IHDR":
            if len(chunk) != 13:
                raise ValueError("Invalid PNG IHDR chunk length")
            width, height, bit_depth, color_type, comp, flt, interlace = struct.unpack(
                ">IIBBBBB", chunk
            )
            saw_ihdr = True
            if comp != 0 or flt != 0 or interlace not in (0, 1):
                raise ValueError("Unsupported PNG compression, filter, or interlace method")
        elif chunk_type == b"PLTE":
            plte = chunk
        elif chunk_type == b"tRNS":
            trns = chunk
        elif chunk_type == b"IDAT":
            idat.extend(chunk)
        elif chunk_type == b"IEND":
            break

    if not saw_ihdr or not idat:
        raise ValueError("Missing PNG IHDR or IDAT data")
    if width <= 0 or height <= 0 or width > _MAX_DIM or height > _MAX_DIM:
        raise ValueError(f"Invalid PNG dimensions: {width}x{height}")
    if width * height > _MAX_PIXELS:
        raise ValueError(f"PNG pixel count exceeds safety limit: {width}x{height}")
    if color_type not in _VALID_BIT_DEPTHS or bit_depth not in _VALID_BIT_DEPTHS[color_type]:
        raise ValueError(f"Unsupported PNG color_type={color_type} bit_depth={bit_depth}")
    if color_type == 3 and not plte:
        raise ValueError("Indexed PNG missing PLTE palette chunk")

    try:
        raw = zlib.decompress(bytes(idat))
    except zlib.error as exc:
        raise ValueError(f"Corrupt PNG zlib stream: {exc}") from exc

    channels = _COLOR_CHANNELS[color_type]
    palette_lut = _build_palette_lut(plte, trns) if color_type == 3 else []

    if interlace == 0:
        _, scanlines = _unfilter_pass(raw, 0, width, height, channels, bit_depth)
        rgb_rows = [
            _scanline_to_rgb(row, width, color_type, bit_depth, palette_lut, trns)
            for row in scanlines
        ]
    else:
        frame = [bytearray(width * 3) for _ in range(height)]
        offset = 0
        for x0, y0, dx, dy in _ADAM7_PASSES:
            pw = (width - x0 + dx - 1) // dx if width > x0 else 0
            ph = (height - y0 + dy - 1) // dy if height > y0 else 0
            if pw <= 0 or ph <= 0:
                continue
            offset, pass_rows = _unfilter_pass(raw, offset, pw, ph, channels, bit_depth)
            for py, pass_row in enumerate(pass_rows):
                dest_row = frame[y0 + py * dy]
                rgb_pass = _scanline_to_rgb(
                    pass_row, pw, color_type, bit_depth, palette_lut, trns
                )
                for px in range(pw):
                    src_i = px * 3
                    dst_i = (x0 + px * dx) * 3
                    dest_row[dst_i : dst_i + 3] = rgb_pass[src_i : src_i + 3]
        rgb_rows = [bytes(r) for r in frame]

    return DecodedImage(
        width=width,
        height=height,
        color_type=color_type,
        bit_depth=bit_depth,
        raw_size=len(data),
        rgb_rows=rgb_rows,
    )


def decode_image(data: bytes) -> DecodedImage:
    """Decode PNG bytes natively, or fall back to Pillow if installed for other formats."""
    if not data:
        raise ValueError("Empty image payload")
    if data.startswith(_PNG_SIGNATURE):
        return decode_png(data)

    try:
        from PIL import Image  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ValueError("Unsupported image format (PNG expected)") from exc

    try:
        with Image.open(io.BytesIO(data)) as im:
            w, h = im.size
            if w <= 0 or h <= 0 or w > _MAX_DIM or h > _MAX_DIM or w * h > _MAX_PIXELS:
                raise ValueError(f"Invalid image dimensions: {w}x{h}")
            rgba = im.convert("RGBA")
            bg = Image.new("RGBA", (w, h), (*_BG_RGB, 255))
            composited = Image.alpha_composite(bg, rgba).convert("RGB")
            raw_rgb = composited.tobytes()
            stride = w * 3
            rows = [raw_rgb[y * stride : (y + 1) * stride] for y in range(h)]
            return DecodedImage(
                width=w,
                height=h,
                color_type=2,
                bit_depth=8,
                raw_size=len(data),
                rgb_rows=rows,
            )
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Unable to decode image: {exc}") from exc


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type)
    crc = zlib.crc32(data, crc) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def encode_png(img: DecodedImage, *, compress_level: int = 3) -> bytes:
    """Encode an 8-bit RGB ``DecodedImage`` into PNG bytes without external deps."""
    if img.width <= 0 or img.height <= 0 or len(img.rgb_rows) != img.height:
        raise ValueError(f"Invalid DecodedImage geometry: {img.width}x{img.height}")
    ihdr = struct.pack(">IIBBBBB", img.width, img.height, 8, 2, 0, 0, 0)
    raw_scanlines = b"".join(b"\x00" + row[: img.width * 3] for row in img.rgb_rows)
    idat = zlib.compress(raw_scanlines, level=max(0, min(9, compress_level)))
    return (
        _PNG_SIGNATURE
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND", b"")
    )


def crop_decoded_image(img: DecodedImage, box: tuple[int, int, int, int]) -> DecodedImage:
    """Slice a ``DecodedImage`` to the pixel bounding box ``(x0, y0, x1, y1)``."""
    x0, y0, x1, y1 = box
    cx0 = max(0, min(img.width - 1, x0))
    cy0 = max(0, min(img.height - 1, y0))
    cx1 = max(cx0 + 1, min(img.width, x1))
    cy1 = max(cy0 + 1, min(img.height, y1))
    start_b = cx0 * 3
    end_b = cx1 * 3
    cropped_rows = [row[start_b:end_b] for row in img.rgb_rows[cy0:cy1]]
    return DecodedImage(
        width=cx1 - cx0,
        height=cy1 - cy0,
        color_type=2,
        bit_depth=8,
        raw_size=img.raw_size,
        rgb_rows=cropped_rows,
    )


def _expand_span(start: int, end: int, min_span: int, limit: int) -> tuple[int, int]:
    span = end - start
    if span >= min_span or limit <= span:
        return start, end
    target = min(limit, min_span)
    need = target - span
    new_start = max(0, start - need // 2)
    new_end = min(limit, new_start + target)
    if new_end - new_start < target:
        new_start = max(0, new_end - target)
    return new_start, new_end


def auto_crop_margins(
    img: DecodedImage,
    *,
    tolerance: int = 10,
    padding_ratio: float = 0.03,
    min_padding: int = 12,
    min_trim_fraction: float = 0.12,
) -> tuple[DecodedImage, tuple[int, int, int, int] | None]:
    """Trim large uniform page margins around screenshot content while preserving small details."""
    w, h, rows = img.width, img.height, img.rgb_rows
    if w < 16 or h < 16 or len(rows) != h:
        return img, None

    def _px(x: int, y: int) -> tuple[int, int, int]:
        row = rows[y]
        off = x * 3
        return row[off], row[off + 1], row[off + 2]

    border_samples = (
        _px(0, 0),
        _px(w - 1, 0),
        _px(0, h - 1),
        _px(w - 1, h - 1),
        _px(w // 2, 0),
        _px(w // 2, h - 1),
        _px(0, h // 2),
        _px(w - 1, h // 2),
    )

    best_bg: tuple[int, int, int] | None = None
    best_cnt = 0
    for s in border_samples:
        cnt = sum(
            1
            for o in border_samples
            if abs(s[0] - o[0]) <= tolerance
            and abs(s[1] - o[1]) <= tolerance
            and abs(s[2] - o[2]) <= tolerance
        )
        if cnt > best_cnt:
            best_cnt = cnt
            best_bg = s

    if best_bg is None or best_cnt < 5:
        return img, None

    br, bg_g, bb = best_bg
    bg_row = bytes(best_bg) * w
    min_x, max_x = w, -1
    min_y, max_y = h, -1

    for y, row in enumerate(rows):
        if row == bg_row:
            continue
        row_has_content = False

        # Check left outside current [min_x, max_x]
        left_lim = min(min_x, w)
        for x in range(left_lim):
            off = x * 3
            if (
                abs(row[off] - br) > tolerance
                or abs(row[off + 1] - bg_g) > tolerance
                or abs(row[off + 2] - bb) > tolerance
            ):
                min_x = x
                row_has_content = True
                break

        # Check right outside current max_x (or entire row on first hit)
        right_stop = max(max_x, -1)
        for x in range(w - 1, right_stop, -1):
            off = x * 3
            if (
                abs(row[off] - br) > tolerance
                or abs(row[off + 1] - bg_g) > tolerance
                or abs(row[off + 2] - bb) > tolerance
            ):
                max_x = x
                row_has_content = True
                break

        # If row didn't extend X bounds, verify interior [min_x, max_x] when extending Y bounds
        if not row_has_content and min_x <= max_x and (y < min_y or y > max_y):
            for x in range(min_x, max_x + 1):
                off = x * 3
                if (
                    abs(row[off] - br) > tolerance
                    or abs(row[off + 1] - bg_g) > tolerance
                    or abs(row[off + 2] - bb) > tolerance
                ):
                    row_has_content = True
                    break

        if row_has_content:
            if y < min_y:
                min_y = y
            if y > max_y:
                max_y = y

    if max_x < min_x or max_y < min_y:
        return img, None

    cw = max_x - min_x + 1
    ch = max_y - min_y + 1
    pad = max(min_padding, int(round(max(cw, ch) * padding_ratio)))
    cx0 = max(0, min_x - pad)
    cy0 = max(0, min_y - pad)
    cx1 = min(w, max_x + 1 + pad)
    cy1 = min(h, max_y + 1 + pad)

    cx0, cx1 = _expand_span(cx0, cx1, min(w, 64), w)
    cy0, cy1 = _expand_span(cy0, cy1, min(h, 64), h)

    if (cx1 - cx0) * (cy1 - cy0) > w * h * (1.0 - min_trim_fraction):
        return img, None

    crop_box = (cx0, cy0, cx1, cy1)
    return crop_decoded_image(img, crop_box), crop_box


def _sample_positions(start: int, end: int, max_samples: int = 4) -> tuple[int, ...]:
    span = end - start
    if span <= 1:
        return (start,)
    if span <= max_samples:
        return tuple(range(start, end))
    return tuple(start + ((i * span + span // 2) // max_samples) for i in range(max_samples))


def _sharpen_pixel_grid(
    grid: list[list[tuple[int, int, int]]],
    amount: float = 0.35,
) -> list[list[tuple[int, int, int]]]:
    h = len(grid)
    w = len(grid[0]) if h else 0
    if w < 3 or h < 3:
        return grid
    out: list[list[tuple[int, int, int]]] = []
    for y in range(h):
        up = grid[y - 1 if y > 0 else 0]
        cur = grid[y]
        dn = grid[y + 1 if y + 1 < h else h - 1]
        row_out: list[tuple[int, int, int]] = []
        for x in range(w):
            lx = x - 1 if x > 0 else 0
            rx = x + 1 if x + 1 < w else w - 1
            cr, cg, cb = cur[x]
            ar = (up[x][0] + dn[x][0] + cur[lx][0] + cur[rx][0]) >> 2
            ag = (up[x][1] + dn[x][1] + cur[lx][1] + cur[rx][1]) >> 2
            ab = (up[x][2] + dn[x][2] + cur[lx][2] + cur[rx][2]) >> 2
            sr = max(0, min(255, int(round(cr + amount * (cr - ar)))))
            sg = max(0, min(255, int(round(cg + amount * (cg - ag)))))
            sb = max(0, min(255, int(round(cb + amount * (cb - ab)))))
            row_out.append((sr, sg, sb))
        out.append(row_out)
    return out


def _downsample_rgb_grid(
    img: DecodedImage,
    target_w: int,
    target_h: int,
) -> list[list[tuple[int, int, int]]]:
    x_offsets: list[tuple[int, ...]] = []
    for ox in range(target_w):
        x0 = (ox * img.width) // target_w
        x1 = max(x0 + 1, ((ox + 1) * img.width) // target_w)
        x_offsets.append(tuple(sx * 3 for sx in _sample_positions(x0, min(img.width, x1))))

    def _downsample_row(oy: int) -> list[tuple[int, int, int]]:
        y0 = (oy * img.height) // target_h
        y1 = max(y0 + 1, ((oy + 1) * img.height) // target_h)
        ys = _sample_positions(y0, min(img.height, y1))
        src_rows = [img.rgb_rows[sy] for sy in ys]
        n_y = len(src_rows)
        pixels: list[tuple[int, int, int]] = []
        for x_offs in x_offsets:
            r_sum = g_sum = b_sum = 0
            count = n_y * len(x_offs)
            for row_bytes in src_rows:
                for off in x_offs:
                    r_sum += row_bytes[off]
                    g_sum += row_bytes[off + 1]
                    b_sum += row_bytes[off + 2]
            pixels.append((r_sum // count, g_sum // count, b_sum // count))
        return pixels

    return [_downsample_row(oy) for oy in range(target_h)]


def resize_decoded_image(
    img: DecodedImage,
    *,
    max_width: int,
    max_height: int,
) -> DecodedImage:
    """Downscale a ``DecodedImage`` aspect-preservingly to fit ``max_width`` x ``max_height``."""
    bound_w = max(2, max_width)
    bound_h = max(2, max_height)
    if img.width <= bound_w and img.height <= bound_h:
        return img
    scale = min(bound_w / img.width, bound_h / img.height)
    target_w = max(2, min(bound_w, int(round(img.width * scale))))
    target_h = max(2, min(bound_h, int(round(img.height * scale))))
    grid = _downsample_rgb_grid(img, target_w, target_h)
    rows = [bytes(ch for rgb in row for ch in rgb) for row in grid]
    return DecodedImage(
        width=target_w,
        height=target_h,
        color_type=2,
        bit_depth=8,
        raw_size=img.raw_size,
        rgb_rows=rows,
    )


def blur_decoded_image(
    img: DecodedImage,
    *,
    strength: int = 16,
    max_output_dim: int = 360,
) -> DecodedImage:
    """Apply a fast pure-Python frosted-glass privacy blur to a ``DecodedImage``."""
    if img.width <= 0 or img.height <= 0 or not img.rgb_rows:
        return img

    div = max(4, strength)
    small_w = max(2, min(img.width, max(6, min(28, img.width // div))))
    small_h = max(2, min(img.height, max(6, min(28, img.height // div))))
    grid = _downsample_rgb_grid(img, small_w, small_h)

    # Smooth twice on the downsampled grid to eliminate sharp text/UI edges
    for _ in range(2):
        smoothed: list[list[tuple[int, int, int]]] = []
        for y in range(small_h):
            y0, y2 = max(0, y - 1), min(small_h - 1, y + 1)
            row_out: list[tuple[int, int, int]] = []
            for x in range(small_w):
                x0, x2 = max(0, x - 1), min(small_w - 1, x + 1)
                rs = gs = bs = 0
                for yy in (y0, y, y2):
                    src_r = grid[yy]
                    for xx in (x0, x, x2):
                        px = src_r[xx]
                        rs += px[0]
                        gs += px[1]
                        bs += px[2]
                row_out.append((rs // 9, gs // 9, bs // 9))
            smoothed.append(row_out)
        grid = smoothed

    max_edge = max(img.width, img.height)
    if max_edge > max_output_dim > 0:
        scale = max_output_dim / max_edge
        out_w = max(2, int(round(img.width * scale)))
        out_h = max(2, int(round(img.height * scale)))
    else:
        out_w, out_h = img.width, img.height

    x_map: list[tuple[int, int, int]] = []
    for x in range(out_w):
        fx = (x + 0.5) * small_w / out_w - 0.5
        x0 = max(0, min(small_w - 1, int(fx)))
        x1 = min(small_w - 1, x0 + 1)
        tx = int(max(0.0, min(1.0, fx - x0)) * 256)
        x_map.append((x0, x1, tx))

    out_rows: list[bytes] = []
    for y in range(out_h):
        fy = (y + 0.5) * small_h / out_h - 0.5
        y0 = max(0, min(small_h - 1, int(fy)))
        y1 = min(small_h - 1, y0 + 1)
        ty = int(max(0.0, min(1.0, fy - y0)) * 256)
        ity = 256 - ty
        r0, r1 = grid[y0], grid[y1]
        buf = bytearray(out_w * 3)
        pos = 0
        for x0, x1, tx in x_map:
            itx = 256 - tx
            p00, p10 = r0[x0], r0[x1]
            p01, p11 = r1[x0], r1[x1]
            r_top = (p00[0] * itx + p10[0] * tx) >> 8
            g_top = (p00[1] * itx + p10[1] * tx) >> 8
            b_top = (p00[2] * itx + p10[2] * tx) >> 8
            r_bot = (p01[0] * itx + p11[0] * tx) >> 8
            g_bot = (p01[1] * itx + p11[1] * tx) >> 8
            b_bot = (p01[2] * itx + p11[2] * tx) >> 8
            buf[pos] = (r_top * ity + r_bot * ty) >> 8
            buf[pos + 1] = (g_top * ity + g_bot * ty) >> 8
            buf[pos + 2] = (b_top * ity + b_bot * ty) >> 8
            pos += 3
        out_rows.append(bytes(buf))

    return DecodedImage(
        width=out_w,
        height=out_h,
        color_type=2,
        bit_depth=8,
        raw_size=img.raw_size,
        rgb_rows=out_rows,
    )


def blur_image_bytes(
    raw_bytes: bytes,
    *,
    decoded: DecodedImage | None = None,
    strength: int = 16,
    max_output_dim: int = 640,
) -> bytes:
    """Return PNG bytes containing a frosted-glass privacy-blurred version of the image."""
    img_obj = decoded if decoded is not None else decode_image(raw_bytes)
    blurred = blur_decoded_image(img_obj, strength=strength, max_output_dim=max_output_dim)
    return encode_png(blurred)


def prepare_image_cache_entry(raw_bytes: bytes) -> dict[str, Any]:
    """Decode, auto-crop, pre-blur, and PNG-encode a screenshot off the UI thread."""
    payload_bytes = bytes(raw_bytes)
    decoded = decode_image(payload_bytes)
    cropped_img, crop_box = auto_crop_margins(decoded)
    cropped_png = encode_png(cropped_img) if crop_box is not None else payload_bytes
    blurred_img = blur_decoded_image(cropped_img)
    blurred_png = encode_png(blurred_img)
    return {
        "bytes": payload_bytes,
        "decoded": decoded,
        "crop_checked": True,
        "crop_box": crop_box,
        "cropped_decoded": cropped_img,
        "cropped_png": cropped_png,
        "blurred_decoded": blurred_img,
        "blurred_png": blurred_png,
    }


def _sixel_rle_sub(match: re.Match[str]) -> str:
    run = match.group(0)
    return f"!{len(run)}{run[0]}"


def encode_sixel(
    img: DecodedImage,
    *,
    max_width: int = 640,
    max_height: int = 420,
) -> str:
    """Encode a ``DecodedImage`` as a pure-Python DEC Sixel graphics sequence."""
    scaled = resize_decoded_image(img, max_width=max_width, max_height=max_height)
    w, h = scaled.width, scaled.height
    c_lut = _SIXEL_C_LUT
    g_lut = _SIXEL_G_LUT

    q_rows: list[bytearray] = []
    used_colors: set[int] = set()
    for row_bytes in scaled.rgb_rows:
        qr = bytearray(w)
        for x in range(w):
            off = x * 3
            r, g, b = row_bytes[off], row_bytes[off + 1], row_bytes[off + 2]
            if abs(r - g) <= 10 and abs(g - b) <= 10 and abs(r - b) <= 10:
                idx = g_lut[(r + g + b) // 3]
            else:
                idx = c_lut[r] * 36 + c_lut[g] * 6 + c_lut[b]
            qr[x] = idx
        used_colors.update(qr)
        q_rows.append(qr)

    out: list[str] = [f'\x1bP0;1q"1;1;{w};{h}']
    for idx in sorted(used_colors):
        if idx < 216:
            rp = (idx // 36) * 20
            gp = ((idx // 6) % 6) * 20
            bp = (idx % 6) * 20
        else:
            vp = round(((idx - 216) / 31.0) * 100)
            rp = gp = bp = vp
        out.append(f"#{idx};2;{rp};{gp};{bp}")

    zero_row = bytes(w)
    for by in range(0, h, 6):
        band = q_rows[by : min(h, by + 6)]
        color_bits: dict[int, bytearray] = {}
        for bit_i, row_q in enumerate(band):
            bit_val = 1 << bit_i
            for x, color_idx in enumerate(row_q):
                arr = color_bits.get(color_idx)
                if arr is None:
                    arr = bytearray(zero_row)
                    color_bits[color_idx] = arr
                arr[x] |= bit_val
        first_c = True
        for color_idx, bits in color_bits.items():
            sixel_str = bits.rstrip(b"\x00").translate(_SIXEL_CHAR_TRANS).decode("ascii")
            if not sixel_str:
                continue
            if not first_c:
                out.append("$")
            first_c = False
            out.append(f"#{color_idx}" + _SIXEL_RLE_RE.sub(_sixel_rle_sub, sixel_str))
        if by + 6 < h:
            out.append("-")
    out.append("\x1b\\")
    return "".join(out)


def render_image_halfblock(
    img: DecodedImage,
    *,
    max_width: int,
    max_height: int,
    sharpen: bool = True,
) -> Text:
    """Render a ``DecodedImage`` using true-color Unicode half-block characters."""
    bound_w = max(2, max_width)
    bound_h_px = max(2, max_height * 2)
    scale = min(bound_w / img.width, bound_h_px / img.height)
    target_w = max(2, min(bound_w, int(round(img.width * scale))))
    target_h_px = max(2, min(bound_h_px, int(round(img.height * scale))))
    if target_h_px % 2 != 0:
        if target_h_px + 1 <= bound_h_px:
            target_h_px += 1
        elif target_h_px > 2:
            target_h_px -= 1

    grid = _downsample_rgb_grid(img, target_w, target_h_px)
    if sharpen and max(img.width / target_w, img.height / target_h_px) >= 1.8 and target_w >= 4 and target_h_px >= 4:
        grid = _sharpen_pixel_grid(grid, amount=0.35)

    canvas = Text()
    n_term_rows = target_h_px // 2
    for row_idx in range(n_term_rows):
        if row_idx > 0:
            canvas.append("\n")
        top_row = grid[row_idx * 2]
        bot_row = grid[row_idx * 2 + 1]

        run_start = 0
        prev_pair = (top_row[0], bot_row[0])
        for col_idx in range(1, target_w):
            pair = (top_row[col_idx], bot_row[col_idx])
            if pair != prev_pair:
                top_c, bot_c = prev_pair
                canvas.append(
                    _HALF_BLOCK * (col_idx - run_start),
                    style=Style(color=Color.from_rgb(*top_c), bgcolor=Color.from_rgb(*bot_c)),
                )
                run_start = col_idx
                prev_pair = pair
        top_c, bot_c = prev_pair
        canvas.append(
            _HALF_BLOCK * (target_w - run_start),
            style=Style(color=Color.from_rgb(*top_c), bgcolor=Color.from_rgb(*bot_c)),
        )

    return canvas


def next_kitty_image_id() -> int:
    """Allocate a monotonic 24-bit Kitty Graphics Protocol image ID."""
    global _KITTY_ID_COUNTER
    with _KITTY_ID_LOCK:
        _KITTY_ID_COUNTER += 1
        if _KITTY_ID_COUNTER > _KITTY_ID_MAX:
            _KITTY_ID_COUNTER = _KITTY_ID_MIN
        return _KITTY_ID_COUNTER


def is_tmux_session(env: Mapping[str, str] | None = None) -> bool:
    """Return True when running inside a tmux multiplexer session."""
    e = os.environ if env is None else env
    return bool(e.get("TMUX"))


def is_multiplexer_session(env: Mapping[str, str] | None = None) -> bool:
    """Return True when running inside tmux, GNU screen, or Zellij."""
    e = os.environ if env is None else env
    return bool(e.get("TMUX") or e.get("STY") or e.get("ZELLIJ"))


def is_no_color_environment(env: Mapping[str, str] | None = None) -> bool:
    """Return True when ``NO_COLOR`` is present in the environment."""
    e = os.environ if env is None else env
    return e.get("NO_COLOR") is not None


def is_windows_terminal_environment(
    env: Mapping[str, str] | None = None,
    *,
    platform_name: str | None = None,
) -> bool:
    """Return True when running on Windows or inside Windows Terminal / ConEmu."""
    e = os.environ if env is None else env
    plat = (sys.platform if platform_name is None else platform_name).strip().lower()
    if plat.startswith("win") or plat in {"cygwin", "msys"}:
        return True
    if platform_name is None and os.name == "nt":
        return True
    return bool(e.get("WT_SESSION") or e.get("WT_PROFILE_ID") or e.get("ConEmuPID"))


def _has_kitty_env_indicator(env: Mapping[str, str]) -> bool:
    term = (env.get("TERM") or "").strip().lower()
    term_prog = (env.get("TERM_PROGRAM") or "").strip().lower()
    return bool(
        env.get("KITTY_WINDOW_ID")
        or env.get("GHOSTTY_RESOURCES_DIR")
        or "kitty" in term
        or "ghostty" in term
        or term_prog in {"kitty", "ghostty"}
    )


def _has_explicit_non_pixel_terminal(env: Mapping[str, str]) -> bool:
    """Return True when env explicitly identifies a non-pixel terminal emulator."""
    term_prog = (env.get("TERM_PROGRAM") or "").strip().lower()
    if term_prog in _NON_PIXEL_TERM_PROGRAMS:
        return True
    if any(env.get(var) for var in _NON_PIXEL_ENV_VARS):
        return True
    term_emu = (env.get("TERMINAL_EMULATOR") or "").strip().lower()
    if "jetbrains" in term_emu or "jediterm" in term_emu:
        return True
    term = (env.get("TERM") or "").strip().lower()
    if term == "dumb" or term.startswith("st-") or term == "st":
        return True
    return any(tok in term for tok in _NON_PIXEL_TERM_TOKENS)


def _has_non_pixel_env_indicator(
    env: Mapping[str, str],
    *,
    platform_name: str | None = None,
) -> bool:
    if _has_explicit_non_pixel_terminal(env):
        return True
    plat = (sys.platform if platform_name is None else platform_name).strip().lower()
    if plat.startswith("win") or plat in {"cygwin", "msys"} or (
        platform_name is None and os.name == "nt"
    ):
        return True
    return False


def _resolve_protocol_override(env: Mapping[str, str], *, use_persisted: bool) -> str:
    override = (env.get("RF_TUI_IMAGE_PROTOCOL") or "").strip().lower()
    if not override and use_persisted:
        override = (get_tui_image_protocol() or "").strip().lower()
    return override


def is_truecolor_kitty_env(
    env: Mapping[str, str] | None = None,
    *,
    platform_name: str | None = None,
) -> bool:
    """Return True if the env identifies a Kitty/Ghostty terminal capable of 24-bit color."""
    e = os.environ if env is None else env
    if is_no_color_environment(e) or is_multiplexer_session(e):
        return False
    term_prog = (e.get("TERM_PROGRAM") or "").strip().lower()
    if term_prog in _ITERM2_TERM_PROGRAMS or e.get("ITERM_SESSION_ID") or e.get("WEZTERM_PANE") or e.get("WEZTERM_EXECUTABLE"):
        return False
    if e.get("WT_SESSION") or e.get("WT_PROFILE_ID") or e.get("KONSOLE_VERSION") or e.get("KONSOLE_DBUS_SESSION"):
        return False
    if _has_non_pixel_env_indicator(e, platform_name=platform_name):
        return False
    return _has_kitty_env_indicator(e)


def can_emit_kitty_truecolor(
    app: Any = None,
    env: Mapping[str, str] | None = None,
) -> bool:
    """Return True only when 24-bit RGB foreground colors (needed for Kitty image IDs) work."""
    if app is not None:
        if bool(getattr(app, "no_color", False)):
            return False
        console = getattr(app, "console", None)
        if console is not None:
            cs = getattr(console, "_color_system", None)
            if cs is None:
                cs = getattr(console, "color_system", None)
            if cs not in (ColorSystem.TRUECOLOR, "truecolor"):
                return False
    if env is not None and is_no_color_environment(env):
        return False
    if app is None and env is None and is_no_color_environment(os.environ):
        return False
    return True


def get_terminal_probe_result() -> str | None:
    """Return the cached live terminal graphics probe protocol (or ``None``)."""
    with _TERMINAL_PROBE_LOCK:
        return _TERMINAL_PROBE_RESULT


def set_terminal_probe_result(result: str | None) -> None:
    """Set the cached live terminal graphics probe protocol (primarily for tests/startup)."""
    global _TERMINAL_PROBE_DONE, _TERMINAL_PROBE_RESULT
    with _TERMINAL_PROBE_LOCK:
        _TERMINAL_PROBE_RESULT = result
        _TERMINAL_PROBE_DONE = result is not None


def reset_terminal_probe_cache() -> None:
    """Clear the cached live terminal graphics probe result."""
    global _TERMINAL_PROBE_DONE, _TERMINAL_PROBE_RESULT
    with _TERMINAL_PROBE_LOCK:
        _TERMINAL_PROBE_DONE = False
        _TERMINAL_PROBE_RESULT = None


def parse_terminal_graphics_probe(
    raw: bytes,
    *,
    env: Mapping[str, str] | None = None,
) -> str:
    """Classify terminal pixel capability from Kitty ``a=q`` + ``XTVERSION`` + ``DA1`` replies."""
    if not raw:
        return "halfblock"

    kitty_ack = bool(_KITTY_QUERY_ACK_RE.search(raw))
    xt_match = _XTVERSION_RE.search(raw)
    xt_payload = (
        xt_match.group(1).decode("utf-8", errors="ignore").strip().lower()
        if xt_match is not None
        else ""
    )
    da1_match = _DA1_RE.search(raw)
    da1_params = (
        [part for part in da1_match.group(1).decode("ascii", errors="ignore").split(";") if part]
        if da1_match is not None
        else []
    )
    has_sixel = "4" in da1_params

    e = os.environ if env is None else env
    if kitty_ack:
        if "kitty" in xt_payload or "ghostty" in xt_payload:
            return "kitty"
        if not xt_payload and _has_kitty_env_indicator(e) and not _has_non_pixel_env_indicator(e):
            return "kitty"

    if any(tok in xt_payload for tok in ("iterm", "wezterm", "mintty", "tabby")):
        return "iterm2"
    if "vscode" in xt_payload and has_sixel:
        return "iterm2"
    if has_sixel:
        return "sixel"
    return "halfblock"


def probe_terminal_graphics_support(
    *,
    timeout: float = 0.12,
    env: Mapping[str, str] | None = None,
    force: bool = False,
) -> str | None:
    """Probe the active POSIX TTY once for Kitty/iTerm2/Sixel graphics support."""
    e = os.environ if env is None else env

    if env is None and not force:
        with _TERMINAL_PROBE_LOCK:
            if _TERMINAL_PROBE_DONE:
                return _TERMINAL_PROBE_RESULT

    if sys.platform == "win32" or os.name == "nt" or is_windows_terminal_environment(e):
        return None
    if e.get("PYTEST_CURRENT_TEST") and not force:
        return None

    override = _resolve_protocol_override(e, use_persisted=env is None)
    if override in VALID_IMAGE_PROTOCOLS:
        return None

    term = (e.get("TERM") or "").strip().lower()
    if is_no_color_environment(e) or is_multiplexer_session(e) or term == "dumb":
        if env is None:
            set_terminal_probe_result("halfblock")
        return "halfblock"

    stdin_obj = sys.__stdin__
    if stdin_obj is None:
        return None
    try:
        if not stdin_obj.isatty():
            return None
        stdin_fd = stdin_obj.fileno()
    except (OSError, ValueError, AttributeError):
        return None

    stdout_fd: int | None = None
    for out_obj in (sys.__stdout__, sys.__stderr__):
        if out_obj is None:
            continue
        try:
            if out_obj.isatty():
                stdout_fd = out_obj.fileno()
                break
        except (OSError, ValueError, AttributeError):
            continue
    if stdout_fd is None:
        return None

    try:
        select = importlib.import_module("select")
        termios = importlib.import_module("termios")
    except ImportError:
        return None

    termios_err = getattr(termios, "error", OSError)
    old_attrs: list[Any] | None = None
    buf = bytearray()
    try:
        old_attrs = termios.tcgetattr(stdin_fd)
        new_attrs = list(old_attrs)
        new_attrs[3] = new_attrs[3] & ~(termios.ICANON | termios.ECHO)
        cc = list(new_attrs[6])
        cc[termios.VMIN] = 0
        cc[termios.VTIME] = 0
        new_attrs[6] = cc
        termios.tcsetattr(stdin_fd, termios.TCSANOW, new_attrs)

        probe_seq = b"\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\\x1b[>0q\x1b[c"
        os.write(stdout_fd, probe_seq)

        deadline = time.monotonic() + max(0.02, timeout)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select([stdin_fd], [], [], remaining)
            if not readable:
                break
            chunk = os.read(stdin_fd, 4096)
            if not chunk:
                break
            buf.extend(chunk)
            if _DA1_RE.search(buf):
                tail_ready, _, _ = select.select([stdin_fd], [], [], 0.005)
                if tail_ready:
                    extra = os.read(stdin_fd, 4096)
                    if extra:
                        buf.extend(extra)
                break
    except (OSError, ValueError, termios_err):
        return None
    finally:
        if old_attrs is not None:
            try:
                termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_attrs)
            except Exception:
                pass

    result = parse_terminal_graphics_probe(bytes(buf), env=e)
    if env is None:
        set_terminal_probe_result(result)
    return result


def get_terminal_cell_pixel_size(default: tuple[int, int] = (9, 18)) -> tuple[int, int]:
    """Return terminal cell ``(width_px, height_px)`` via ``TIOCGWINSZ`` when available."""
    if sys.platform == "win32" or os.name == "nt":
        return default
    try:
        fcntl = importlib.import_module("fcntl")
        termios = importlib.import_module("termios")
    except ImportError:
        return default

    for stream in (sys.__stderr__, sys.__stdout__, sys.__stdin__):
        if stream is None:
            continue
        try:
            if not stream.isatty():
                continue
            fd = stream.fileno()
            packed = fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\x00" * 8)
            rows, cols, xpixel, ypixel = struct.unpack("HHHH", packed)
        except (AttributeError, OSError, ValueError):
            continue
        if rows > 0 and cols > 0 and xpixel > 0 and ypixel > 0:
            cell_w = max(4, min(40, int(round(xpixel / cols))))
            cell_h = max(8, min(80, int(round(ypixel / rows))))
            return cell_w, cell_h
    return default


def get_terminal_cell_aspect(default: float = 0.5) -> float:
    """Return terminal cell width/height pixel aspect ratio via ``TIOCGWINSZ`` when available."""
    cell_w, cell_h = get_terminal_cell_pixel_size()
    if cell_h <= 0:
        return default
    return max(0.25, min(1.0, cell_w / cell_h))


def detect_terminal_graphics_protocol(
    env: Mapping[str, str] | None = None,
    *,
    is_headless: bool = False,
    platform_name: str | None = None,
    probe_result: Any = _UNSET,
    app: Any = None,
) -> str:
    """Detect the best supported terminal image protocol (``kitty``, ``iterm2``, ``sixel``, or ``halfblock``)."""
    e = os.environ if env is None else env
    override = _resolve_protocol_override(e, use_persisted=env is None)
    if override in VALID_IMAGE_PROTOCOLS:
        return override
    if is_headless:
        return "halfblock"
    term = (e.get("TERM") or "").strip().lower()
    if is_no_color_environment(e) or term == "dumb":
        return "halfblock"
    if is_multiplexer_session(e):
        return "halfblock"

    resolved_probe = (
        get_terminal_probe_result()
        if (probe_result is _UNSET and env is None)
        else (None if probe_result is _UNSET else probe_result)
    )
    if resolved_probe in VALID_IMAGE_PROTOCOLS:
        if resolved_probe == "kitty":
            return "kitty" if (app is None or can_emit_kitty_truecolor(app, e)) else "halfblock"
        return str(resolved_probe)

    if _has_explicit_non_pixel_terminal(e):
        return "halfblock"

    term_prog = (e.get("TERM_PROGRAM") or "").strip().lower()
    if (
        term_prog in _ITERM2_TERM_PROGRAMS
        or e.get("ITERM_SESSION_ID")
        or e.get("WEZTERM_PANE")
        or e.get("WEZTERM_EXECUTABLE")
        or "wezterm" in term
    ):
        return "iterm2"

    if (
        e.get("WT_SESSION")
        or e.get("WT_PROFILE_ID")
        or e.get("KONSOLE_VERSION")
        or e.get("KONSOLE_DBUS_SESSION")
        or term.startswith("foot")
        or "konsole" in term
        or "mlterm" in term
    ):
        return "sixel"

    if _has_non_pixel_env_indicator(e, platform_name=platform_name):
        return "halfblock"

    if _has_kitty_env_indicator(e):
        return "kitty" if (app is None or can_emit_kitty_truecolor(app, e)) else "halfblock"
    return "halfblock"


def has_native_pixel_graphics(
    env: Mapping[str, str] | None = None,
    *,
    is_headless: bool = False,
    platform_name: str | None = None,
    probe_result: Any = _UNSET,
    app: Any = None,
) -> bool:
    """Return True when the active terminal can render true inline pixel graphics."""
    return (
        detect_terminal_graphics_protocol(
            env,
            is_headless=is_headless,
            platform_name=platform_name,
            probe_result=probe_result,
            app=app,
        )
        in {"kitty", "iterm2", "sixel"}
    )


def get_recommended_image_viewer_mode(
    env: Mapping[str, str] | None = None,
    *,
    is_headless: bool = False,
    platform_name: str | None = None,
    probe_result: Any = _UNSET,
    app: Any = None,
) -> str:
    """Return ``'tui'`` for pixel-capable terminals (or headless), ``'os'`` otherwise."""
    if is_headless:
        return "tui"
    return (
        "tui"
        if has_native_pixel_graphics(
            env,
            is_headless=is_headless,
            platform_name=platform_name,
            probe_result=probe_result,
            app=app,
        )
        else "os"
    )


def format_graphics_protocol_status(
    env: Mapping[str, str] | None = None,
    *,
    is_headless: bool = False,
    platform_name: str | None = None,
    probe_result: Any = _UNSET,
    app: Any = None,
) -> str:
    """Return a concise label describing the active inline graphics protocol."""
    proto = detect_terminal_graphics_protocol(
        env,
        is_headless=is_headless,
        platform_name=platform_name,
        probe_result=probe_result,
        app=app,
    )
    if proto == "kitty":
        return "Kitty HD"
    if proto == "iterm2":
        return "iTerm2 HD"
    if proto == "sixel":
        return "Sixel HD"
    return "Halfblock" if is_headless else "Halfblock (OS Viewer)"


def _wrap_tmux_passthrough(seq: str) -> str:
    return "\x1bPtmux;" + seq.replace("\x1b", "\x1b\x1b") + "\x1b\\"


def build_sixel_overlay_sequence(
    sixel_payload: str,
    *,
    row: int,
    col: int,
    tmux_passthrough: bool = False,
) -> str:
    """Wrap a Sixel DCS payload in cursor-save/position/restore escape sequences."""
    if not sixel_payload or not sixel_payload.startswith("\x1bP"):
        raise ValueError("Invalid Sixel DCS payload")
    if row < 1 or col < 1:
        raise ValueError(f"Sixel overlay coordinates must be 1-based: row={row}, col={col}")
    body = _wrap_tmux_passthrough(sixel_payload) if tmux_passthrough else sixel_payload
    return f"\x1b7\x1b[{row};{col}H{body}\x1b8"


def build_iterm2_overlay_sequence(
    png_bytes: bytes,
    *,
    row: int,
    col: int,
    cols: int,
    rows: int,
    tmux_passthrough: bool = False,
) -> str:
    """Build an iTerm2 ``OSC 1337`` inline image sequence positioned at ``(row, col)``."""
    if not png_bytes or not png_bytes.startswith(_PNG_SIGNATURE):
        raise ValueError("iTerm2 overlay requires valid PNG bytes")
    if row < 1 or col < 1 or cols < 1 or rows < 1:
        raise ValueError(
            f"iTerm2 overlay geometry must be >= 1: row={row}, col={col}, cols={cols}, rows={rows}"
        )
    b64 = base64.b64encode(png_bytes).decode("ascii")
    osc = (
        f"\x1b]1337;File=inline=1;size={len(png_bytes)};"
        f"width={cols};height={rows};preserveAspectRatio=1:{b64}\x07"
    )
    body = _wrap_tmux_passthrough(osc) if tmux_passthrough else osc
    return f"\x1b7\x1b[{row};{col}H{body}\x1b8"


def build_kitty_upload_sequence(
    png_bytes: bytes,
    *,
    image_id: int,
    cols: int,
    rows: int,
    tmux_passthrough: bool = False,
) -> str:
    """Build Kitty APC sequences to upload PNG data and create a ``U=1`` virtual placement."""
    if not png_bytes or not png_bytes.startswith(_PNG_SIGNATURE):
        raise ValueError("Kitty upload requires valid PNG bytes")
    if not (1 <= image_id <= 0xFFFFFF):
        raise ValueError(f"Kitty image_id must fit in 24 bits: {image_id}")
    if not (1 <= cols <= 255 and 1 <= rows <= 255):
        raise ValueError(f"Kitty placeholder grid exceeds 255x255: {cols}x{rows}")

    b64 = base64.b64encode(png_bytes).decode("ascii")
    chunk_size = 4096
    chunks = [b64[i : i + chunk_size] for i in range(0, len(b64), chunk_size)] or [""]
    sequences: list[str] = []

    if len(chunks) == 1:
        sequences.append(f"\x1b_Ga=t,f=100,i={image_id},q=2;{chunks[0]}\x1b\\")
    else:
        for idx, chunk in enumerate(chunks):
            if idx == 0:
                sequences.append(f"\x1b_Ga=t,f=100,i={image_id},q=2,m=1;{chunk}\x1b\\")
            elif idx + 1 < len(chunks):
                sequences.append(f"\x1b_Gm=1,q=2;{chunk}\x1b\\")
            else:
                sequences.append(f"\x1b_Gm=0,q=2;{chunk}\x1b\\")

    sequences.append(f"\x1b_Ga=p,U=1,i={image_id},c={cols},r={rows},q=2;\x1b\\")

    if tmux_passthrough:
        sequences = [_wrap_tmux_passthrough(seq) for seq in sequences]
    return "".join(sequences)


def build_kitty_delete_sequence(image_id: int, *, tmux_passthrough: bool = False) -> str:
    """Build a Kitty APC sequence to delete image data and placements for ``image_id``."""
    cmd = f"\x1b_Ga=d,d=I,i={image_id},q=2;\x1b\\"
    return _wrap_tmux_passthrough(cmd) if tmux_passthrough else cmd


def write_terminal_graphics(app: Any, sequence: str) -> bool:
    """Write a raw terminal graphics escape sequence through Textual's active driver."""
    if not sequence or app is None or getattr(app, "is_headless", False):
        return False
    driver = getattr(app, "_driver", None)
    write_fn = getattr(driver, "write", None) if driver is not None else None
    if write_fn is None:
        return False
    try:
        write_fn(sequence)
        flush_fn = getattr(driver, "flush", None)
        if flush_fn is not None:
            flush_fn()
        return True
    except Exception:
        return False


def clear_kitty_images(app: Any, image_ids: list[int]) -> None:
    """Delete tracked Kitty Graphics image IDs from the terminal and clear the list."""
    if not image_ids:
        return
    tmux = is_tmux_session()
    seq = "".join(build_kitty_delete_sequence(kid, tmux_passthrough=tmux) for kid in image_ids)
    image_ids.clear()
    write_terminal_graphics(app, seq)


def compute_terminal_cell_grid(
    img_w: int,
    img_h: int,
    *,
    max_cols: int,
    max_rows: int,
    cell_aspect: float = 0.5,
) -> tuple[int, int]:
    """Compute aspect-preserving ``(cols, rows)`` grid bounded by ``max_cols`` and ``max_rows``."""
    bound_c = max(2, min(255, max_cols))
    bound_r = max(2, min(255, max_rows))
    if img_w <= 0 or img_h <= 0:
        return bound_c, bound_r
    safe_aspect = max(0.1, cell_aspect)
    # Approximate pixel area per cell as (1.0 x 1/cell_aspect)
    scale = min(bound_c / img_w, (bound_r / safe_aspect) / img_h)
    cols = max(2, min(bound_c, int(round(img_w * scale))))
    rows = max(2, min(bound_r, int(round(img_h * scale * safe_aspect))))
    return cols, rows


def render_kitty_placeholder_grid(*, image_id: int, cols: int, rows: int) -> Text:
    """Render a Rich ``Text`` grid of Kitty ``U=1`` Unicode placeholder characters."""
    safe_cols = max(1, min(len(_KITTY_DIACRITICS), cols))
    safe_rows = max(1, min(len(_KITTY_DIACRITICS), rows))
    fg_color = Color.from_rgb(
        (image_id >> 16) & 0xFF,
        (image_id >> 8) & 0xFF,
        image_id & 0xFF,
    )
    style = Style(color=fg_color)
    ph = chr(_KITTY_PLACEHOLDER_CP)
    col_marks = _KITTY_DIACRITICS[:safe_cols]

    canvas = Text(no_wrap=True, overflow="crop")
    for r_idx in range(safe_rows):
        if r_idx > 0:
            canvas.append("\n")
        row_mark = _KITTY_DIACRITICS[r_idx]
        line = "".join(f"{ph}{row_mark}{col_mark}" for col_mark in col_marks)
        canvas.append(line, style=style)
    return canvas


def _detect_image_extension(raw_bytes: bytes) -> str:
    """Infer file extension from image magic bytes, defaulting to ``.png``."""
    if raw_bytes.startswith(_PNG_SIGNATURE):
        return ".png"
    if raw_bytes.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if raw_bytes.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if len(raw_bytes) >= 12 and raw_bytes[:4] == b"RIFF" and raw_bytes[8:12] == b"WEBP":
        return ".webp"
    if raw_bytes.startswith(b"BM"):
        return ".bmp"
    return ".png"


def stage_screenshot_file(raw_bytes: bytes, *, image_id: str) -> Path:
    """Write ``raw_bytes`` to a temp screenshot file with Windows lock resilience."""
    if not raw_bytes:
        raise ValueError("No image bytes available to stage")
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", image_id).strip("_")[:80] or "screenshot"
    ext = _detect_image_extension(raw_bytes)
    dest_dir = Path(tempfile.gettempdir()) / "soclens_screenshots"
    dest_dir.mkdir(parents=True, exist_ok=True)
    out_path = dest_dir / f"{stem}{ext}"
    try:
        out_path.write_bytes(raw_bytes)
        return out_path
    except PermissionError:
        try:
            if out_path.is_file() and out_path.read_bytes() == raw_bytes:
                return out_path
        except OSError:
            pass
        unique_path = dest_dir / f"{stem}_{os.getpid()}_{time.time_ns() % 1_000_000}{ext}"
        unique_path.write_bytes(raw_bytes)
        return unique_path


def open_image_in_native_viewer(raw_bytes: bytes, *, image_id: str) -> Path:
    """Write ``raw_bytes`` to a temp image file and open it in the OS native viewer."""
    if not raw_bytes:
        raise ValueError("No image bytes available to open")
    out_path = stage_screenshot_file(raw_bytes, image_id=image_id)

    if sys.platform == "win32":
        startfile = getattr(os, "startfile", None)
        if startfile is None:
            raise RuntimeError(f"os.startfile is unavailable; saved temp image to {out_path}")
        try:
            startfile(str(out_path))
        except OSError as exc:
            raise RuntimeError(
                f"Unable to open OS image viewer ({exc}); saved image to {out_path}"
            ) from exc
        return out_path

    if sys.platform == "darwin":
        launcher = shutil.which("open") or "/usr/bin/open"
        subprocess.Popen(
            [launcher, str(out_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return out_path

    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        raise RuntimeError(f"No graphical viewer available; saved temp PNG to {out_path}")
    xdg_open = shutil.which("xdg-open")
    if not xdg_open:
        raise RuntimeError(f"xdg-open not found; saved temp PNG to {out_path}")
    subprocess.Popen(
        [xdg_open, str(out_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return out_path


def _format_byte_size(n_bytes: int) -> str:
    if n_bytes < 1024:
        return f"{n_bytes} B"
    if n_bytes < 1024 * 1024:
        return f"{n_bytes / 1024:.1f} KB"
    return f"{n_bytes / (1024 * 1024):.1f} MB"


def _short_ts(ts: Any) -> str:
    from soclens.timezone import format_iso_timestamp

    formatted = format_iso_timestamp(ts)
    return "" if formatted == "-" else formatted


def render_screenshot_panel(
    *,
    image_id: str,
    render_width: int,
    max_rows: int = 20,
    meta: dict[str, Any] | None = None,
    decoded: DecodedImage | None = None,
    raw_bytes: bytes | None = None,
    loading: bool = False,
    error: str | None = None,
    index: int | None = None,
    total: int | None = None,
    auto_crop: bool = True,
    kitty_placeholder: tuple[int, int, int] | None = None,
    crop_box: tuple[int, int, int, int] | None = None,
    blurred: bool = True,
    pre_blurred: bool = False,
) -> Panel:
    """Render a Playbook Alert screenshot Panel using Kitty HD or sharpened half-block."""
    meta = meta or {}
    label_parts: list[str] = []
    if index is not None and total is not None:
        label_parts.append(f"Screenshot {index}/{total}")
    else:
        label_parts.append("Screenshot")

    short_id = image_id if len(image_id) <= 30 else image_id[:27] + "..."
    label_parts.append(short_id)

    img_obj = decoded
    decode_err = error
    if img_obj is None and raw_bytes is not None and not decode_err and not loading:
        try:
            img_obj = decode_image(raw_bytes)
        except ValueError as exc:
            decode_err = str(exc)

    if img_obj is not None:
        label_parts.append(f"{img_obj.width}x{img_obj.height}")
        label_parts.append(_format_byte_size(img_obj.raw_size))
    elif raw_bytes is not None:
        label_parts.append(_format_byte_size(len(raw_bytes)))

    title_str = " | ".join(label_parts)

    subtitle_parts: list[str] = []
    created_str = _short_ts(meta.get("created"))
    if created_str:
        subtitle_parts.append(created_str)
    tag_str = str(meta.get("tag") or "").strip()
    if tag_str:
        subtitle_parts.append(f"Tag: {tag_str}")
    desc = str(meta.get("description") or "").strip()
    if desc and desc.lower() != "an image associated with the playbook alert":
        subtitle_parts.append(desc)

    body: Text
    border = "cyan"
    if loading:
        body = Text("Downloading and decoding screenshot...", style="dim")
        border = "yellow"
    elif decode_err:
        body = Text(f"Screenshot unavailable: {decode_err}", style="dim red")
        border = "red"
    elif kitty_placeholder is not None:
        kid, cols, rows = kitty_placeholder
        body = render_kitty_placeholder_grid(image_id=kid, cols=cols, rows=rows)
        subtitle_parts.append("HD")
        if blurred:
            subtitle_parts.append("Blurred ([b] to reveal)")
        if crop_box is not None:
            cw = crop_box[2] - crop_box[0]
            ch = crop_box[3] - crop_box[1]
            subtitle_parts.append(f"Cropped {cw}x{ch}")
    elif img_obj is not None:
        avail_w = max(20, render_width - 4)
        display_img = img_obj
        active_box = crop_box
        if auto_crop and active_box is None:
            display_img, active_box = auto_crop_margins(img_obj)
        elif active_box is not None and (
            display_img.width != (active_box[2] - active_box[0])
            or display_img.height != (active_box[3] - active_box[1])
        ):
            display_img = crop_decoded_image(img_obj, active_box)
        if active_box is not None:
            subtitle_parts.append(f"Auto-cropped {display_img.width}x{display_img.height}")
        if blurred and not pre_blurred:
            display_img = blur_decoded_image(display_img)
        if blurred:
            subtitle_parts.append("Blurred ([b] to reveal)")
        body = render_image_halfblock(
            display_img,
            max_width=avail_w,
            max_height=max(4, max_rows),
            sharpen=not blurred,
        )
    else:
        avail_state = str(meta.get("availability") or "").strip()
        hint = (
            f"Availability: {avail_state} — waiting to download."
            if avail_state
            else "Click 'Deep Detail' or press Enter to download screenshot."
        )
        body = Text(hint, style="dim")
        border = "dim"

    subtitle_text: Text | None = (
        Text(" | ".join(subtitle_parts), style="dim") if subtitle_parts else None
    )
    panel_style = Style(meta={"screenshot_id": image_id})
    border_rich_style = Style.parse(border) + panel_style

    return Panel(
        body,
        title=Text(title_str, style="bold cyan"),
        subtitle=subtitle_text,
        style=panel_style,
        border_style=border_rich_style,
        box=box.ROUNDED,
        padding=(0, 1),
    )
