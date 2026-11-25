"""Pure-Python deterministic binary image and negative asset generators."""

from __future__ import annotations

import base64
import hashlib
import struct
import zlib
from collections.abc import Iterator
from html import escape as html_escape

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def make_png(
    width: int,
    height: int,
    color: tuple[int, int, int, int] = (10, 80, 160, 255),
) -> bytes:
    """Generate a valid RGBA PNG (>= 50 bytes even for 1x1)."""
    if width <= 0 or height <= 0:
        raise ValueError("PNG width and height must be positive")
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    row = b"\x00" + bytes(color) * width
    raw = row * height
    idat_data = zlib.compress(raw, level=1)
    return (
        _PNG_SIGNATURE
        + _png_chunk(b"IHDR", ihdr_data)
        + _png_chunk(b"IDAT", idat_data)
        + _png_chunk(b"IEND", b"")
    )


def make_jpeg(width: int, height: int) -> bytes:
    """Generate a valid baseline JFIF JPEG with SOF0 height-before-width (>= 50 bytes)."""
    if not (1 <= width <= 65535 and 1 <= height <= 65535):
        raise ValueError("JPEG dimensions must be in [1, 65535]")

    soi = b"\xff\xd8"
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    dqt = b"\xff\xdb" + struct.pack(">H", 67) + b"\x00" + (b"\x01" * 64)

    sof_payload = struct.pack(">BHHB", 8, height, width, 1) + b"\x01\x11\x00"
    sof0 = b"\xff\xc0" + struct.pack(">H", len(sof_payload) + 2) + sof_payload

    dht_dc = b"\xff\xc4" + struct.pack(">H", 20) + b"\x00\x00\x01" + (b"\x00" * 14) + b"\x00"
    dht_ac = b"\xff\xc4" + struct.pack(">H", 20) + b"\x10\x00\x01" + (b"\x00" * 14) + b"\x00"

    sos_payload = b"\x01\x01\x00\x00\x3f\x00"
    sos = b"\xff\xda" + struct.pack(">H", len(sos_payload) + 2) + sos_payload

    scan_and_eoi = b"\x00\xff\xd9"
    return soi + app0 + dqt + sof0 + dht_dc + dht_ac + sos + scan_and_eoi


def _lzw_encode_solid_zero(pixel_count: int) -> bytes:
    """Encode ``pixel_count`` all-zero pixels into valid GIF LZW data (min_code_size=2)."""
    min_code_size = 2
    clear_code = 1 << min_code_size  # 4
    eoi_code = clear_code + 1  # 5

    bits = 0
    bit_count = 0
    out = bytearray()

    def emit(code: int, size: int) -> None:
        nonlocal bits, bit_count
        bits |= code << bit_count
        bit_count += size
        while bit_count >= 8:
            out.append(bits & 0xFF)
            bits >>= 8
            bit_count -= 8

    code_size = min_code_size + 1
    next_code = eoi_code + 1
    emit(clear_code, code_size)

    remaining = pixel_count
    run_len = 1
    while remaining > 0:
        if remaining >= run_len:
            code_to_emit = 0 if run_len == 1 else (eoi_code + run_len - 1)
            emit(code_to_emit, code_size)
            remaining -= run_len
            if next_code < 4096:
                if next_code == (1 << code_size) and code_size < 12:
                    code_size += 1
                next_code += 1
                run_len += 1
            else:
                emit(clear_code, code_size)
                code_size = min_code_size + 1
                next_code = eoi_code + 1
                run_len = 1
        else:
            emit(eoi_code + remaining - 1 if remaining > 1 else 0, code_size)
            if next_code == (1 << code_size) and code_size < 12:
                code_size += 1
            remaining = 0

    # Ensure even minimal GIF87a payloads (33-byte wrapper) exceed the 50-byte floor.
    while len(out) < 20:
        emit(clear_code, code_size)
        code_size = min_code_size + 1

    emit(eoi_code, code_size)
    if bit_count > 0:
        out.append(bits & 0xFF)

    blocks = bytearray([min_code_size])
    for offset in range(0, len(out), 255):
        chunk = out[offset : offset + 255]
        blocks.append(len(chunk))
        blocks.extend(chunk)
    blocks.append(0)
    return bytes(blocks)


def make_gif(width: int, height: int, version: bytes = b"GIF89a") -> bytes:
    """Generate a valid GIF89a or GIF87a image (>= 50 bytes even for 1x1)."""
    if version not in (b"GIF89a", b"GIF87a"):
        raise ValueError("GIF version must be b'GIF89a' or b'GIF87a'")
    if not (1 <= width <= 65535 and 1 <= height <= 65535):
        raise ValueError("GIF dimensions must be in [1, 65535]")

    lsd = struct.pack("<HHBBB", width, height, 0x80, 0, 0)
    gct = b"\x00\x00\x00\xff\xff\xff"

    extensions = b""
    if version == b"GIF89a":
        gce = b"\x21\xf9\x04\x01\x00\x00\x00\x00"
        comment = b"soclens_e2e_gif"
        comment_ext = b"\x21\xfe" + bytes([len(comment)]) + comment + b"\x00"
        extensions = gce + comment_ext

    img_desc = b"\x2c" + struct.pack("<HHHHB", 0, 0, width, height, 0)
    lzw_data = _lzw_encode_solid_zero(width * height)
    return version + lsd + gct + extensions + img_desc + lzw_data + b"\x3b"


def _vp8l_chunk(width: int, height: int, payload_size: int = 24) -> bytes:
    packed = ((height - 1) << 14) | (width - 1)
    header = b"\x2f" + struct.pack("<I", packed)
    size = max(payload_size, len(header))
    if size % 2 == 1:
        size += 1
    payload = header + b"\x00" * (size - len(header))
    return b"VP8L" + struct.pack("<I", len(payload)) + payload


def make_webp(width: int, height: int, variant: str = "VP8X") -> bytes:
    """Generate a valid RIFF/WEBP image supporting 'VP8X', 'VP8L', and 'VP8 ' (>= 50 bytes)."""
    if variant == "VP8X":
        if not (1 <= width <= 16777215 and 1 <= height <= 16777215):
            raise ValueError("WEBP VP8X dimensions must be in [1, 16777215]")
        vp8x_payload = (
            struct.pack("<I", 0)
            + (width - 1).to_bytes(3, "little")
            + (height - 1).to_bytes(3, "little")
        )
        vp8x_chunk = b"VP8X" + struct.pack("<I", len(vp8x_payload)) + vp8x_payload
        body = (
            b"WEBP"
            + vp8x_chunk
            + _vp8l_chunk(min(width, 16384), min(height, 16384), payload_size=24)
        )
    elif variant == "VP8L":
        if not (1 <= width <= 16384 and 1 <= height <= 16384):
            raise ValueError("WEBP VP8L dimensions must be in [1, 16384]")
        body = b"WEBP" + _vp8l_chunk(width, height, payload_size=40)
    elif variant in ("VP8 ", "VP8"):
        if not (1 <= width <= 16383 and 1 <= height <= 16383):
            raise ValueError("WEBP VP8 dimensions must be in [1, 16383]")
        frame_tag = b"\x10\x00\x00"
        start_code = b"\x9d\x01\x2a"
        dims = struct.pack("<HH", width & 0x3FFF, height & 0x3FFF)
        vp8_payload = frame_tag + start_code + dims + (b"\x00" * 34)
        vp8_chunk = b"VP8 " + struct.pack("<I", len(vp8_payload)) + vp8_payload
        body = b"WEBP" + vp8_chunk
    else:
        raise ValueError(f"Unsupported WEBP variant: {variant!r}")

    return b"RIFF" + struct.pack("<I", len(body)) + body


def _make_bmp_dib(width: int, height: int) -> bytes:
    header = struct.pack("<IIIHHIIIIII", 40, width, height * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    xor_mask = b"\x0a\x50\xa0\xff" * (width * height)
    and_row_bytes = ((width + 31) // 32) * 4
    and_mask = b"\x00" * (and_row_bytes * height)
    return header + xor_mask + and_mask


def make_ico(width: int, height: int, payload: str = "png") -> bytes:
    """Generate a valid single-entry ICO with embedded PNG or BMP DIB (>= 50 bytes)."""
    if width <= 0 or height <= 0:
        raise ValueError("ICO width and height must be positive")
    if payload == "png":
        img_bytes = make_png(width, height)
    elif payload == "bmp":
        img_bytes = _make_bmp_dib(width, height)
    else:
        raise ValueError(f"Unsupported ICO payload: {payload!r}")

    icondir = struct.pack("<HHH", 0, 1, 1)
    w_byte = 0 if width >= 256 else width
    h_byte = 0 if height >= 256 else height
    entry = struct.pack("<BBBBHHII", w_byte, h_byte, 0, 0, 1, 32, len(img_bytes), 22)
    return icondir + entry + img_bytes


def make_ico_multi(sizes: list[tuple[int, int]]) -> bytes:
    """Generate a valid multi-entry ICO containing PNG payloads for each (width, height)."""
    if not sizes:
        raise ValueError("sizes must be non-empty")
    icondir = struct.pack("<HHH", 0, 1, len(sizes))
    offset = 6 + 16 * len(sizes)
    entries = bytearray()
    payloads = bytearray()
    for width, height in sizes:
        img_bytes = make_png(width, height)
        w_byte = 0 if width >= 256 else width
        h_byte = 0 if height >= 256 else height
        entries.extend(
            struct.pack("<BBBBHHII", w_byte, h_byte, 0, 0, 1, 32, len(img_bytes), offset)
        )
        payloads.extend(img_bytes)
        offset += len(img_bytes)
    return icondir + bytes(entries) + bytes(payloads)


def make_svg(
    width: int = 200,
    height: int = 60,
    label: str = "BrandLogo",
    include_dims: bool = True,
    css_class: str | None = None,
) -> bytes:
    """Generate a deterministic UTF-8 SVG document (>= 50 bytes)."""
    dims_attr = f' width="{width}" height="{height}"' if include_dims else ""
    class_attr = f' class="{html_escape(css_class, quote=True)}"' if css_class else ""
    safe_label = html_escape(label)
    svg = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg"{class_attr}{dims_attr} '
        f'viewBox="0 0 {width} {height}">\n'
        f'  <rect width="{width}" height="{height}" fill="#0a50a0"/>\n'
        f'  <text x="10" y="{max(12, height // 2)}" fill="#ffffff">{safe_label}</text>\n'
        "</svg>\n"
    )
    return svg.encode("utf-8")


def make_soft_404_html() -> bytes:
    """Generate an HTML soft-404 response body (> 50 bytes)."""
    return (
        b"<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
        b"<body><h1>404 Not Found</h1>"
        b"<p>The requested brand image resource could not be located.</p>"
        b"</body></html>"
    )


def make_truncated_png() -> bytes:
    """Generate a truncated PNG payload (< 30 bytes)."""
    return _PNG_SIGNATURE + b"\x00\x00\x00\rIHDR\x00\x00"


def make_corrupted_png() -> bytes:
    """Generate a >= 50 byte PNG-magic payload with corrupted IHDR/CRC."""
    return _PNG_SIGNATURE + b"\x00\x00\x00\rIHDR" + (b"\xff" * 64)


def make_corrupted_jpeg() -> bytes:
    """Generate a >= 50 byte JPEG-magic payload missing SOF and EOI."""
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + (b"\x00" * 64)


def make_non_image_pdf() -> bytes:
    """Generate a >= 50 byte PDF payload."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"%%EOF\n"
        + (b"\x20" * 16)
    )


def make_tiny_payload() -> bytes:
    """Generate a payload strictly smaller than 50 bytes."""
    return b"tiny-image-payload"


def make_spacer_1x1_png() -> bytes:
    """Generate a valid >= 50 byte 1x1 transparent PNG tracking spacer."""
    return make_png(1, 1, (0, 0, 0, 0))


def make_banner_png(width: int = 1600, height: int = 100) -> bytes:
    """Generate a wide banner PNG for aspect-ratio exclusion tests."""
    return make_png(width, height, (200, 60, 40, 255))


def make_banner_jpeg(width: int = 1600, height: int = 100) -> bytes:
    """Generate a wide banner JPEG for aspect-ratio exclusion tests."""
    return make_jpeg(width, height)


def iter_oversized_chunks(
    size_bytes: int = 10 * 1024 * 1024 + 65536,
    chunk_size: int = 65536,
) -> Iterator[bytes]:
    """Yield deterministic PNG-prefixed chunks totaling ``size_bytes``."""
    if size_bytes <= 0 or chunk_size <= 0:
        raise ValueError("size_bytes and chunk_size must be positive")
    header = make_png(200, 60)[:size_bytes]
    sent = 0
    offset = 0
    while offset < len(header):
        piece = header[offset : offset + chunk_size]
        offset += len(piece)
        if len(piece) < chunk_size and sent + len(piece) < size_bytes:
            pad = min(chunk_size - len(piece), size_bytes - (sent + len(piece)))
            piece = piece + (b"\x00" * pad)
        sent += len(piece)
        yield piece
    fill_block = b"\x00" * chunk_size
    while sent < size_bytes:
        remaining = size_bytes - sent
        if remaining >= chunk_size:
            sent += chunk_size
            yield fill_block
        else:
            sent += remaining
            yield b"\x00" * remaining


def make_oversized_payload(size_bytes: int = 10 * 1024 * 1024 + 65536) -> bytes:
    """Materialize an oversized PNG-prefixed payload of ``size_bytes``."""
    return b"".join(iter_oversized_chunks(size_bytes=size_bytes))


def sha256_hex(data: bytes) -> str:
    """Return lowercase SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def md5_hex(data: bytes) -> str:
    """Return lowercase MD5 hex digest."""
    return hashlib.md5(data).hexdigest()


def sha1_hex(data: bytes) -> str:
    """Return lowercase SHA-1 hex digest."""
    return hashlib.sha1(data).hexdigest()


def to_data_uri(data: bytes, mime_type: str) -> str:
    """Encode raw bytes into a base64 ``data:`` URI."""
    encoded = base64.b64encode(data).decode("ascii")
    return f"data:{mime_type};base64,{encoded}"
