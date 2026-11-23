"""Render the complete PCSG00602 FFU glyph set from one Chinese typeface."""
import csv
import hashlib
import struct

from fontTools.ttLib import TTFont
from PIL import Image, ImageDraw, ImageFilter
from PIL import ImageFont

from extract_font import FONT_ROOT, ROOT, glyph_table
from verify_eboot_font import verify_font

FONT_DIR = ROOT / "06_中文字体"
TYPEFACE = FONT_DIR / "NotoSansCJKsc" / "NotoSansCJKsc-Regular.otf"
OUTPUT = FONT_DIR / "chinese_font"
FONT_NAMES = ("sysfont.ffu", "advfont1.ffu")
SCALE = 4
HEIGHT = 40
BASELINE = 35


def code_bytes(code):
    return code.to_bytes(1 if code < 256 else 2, "big")


def encode_text(text, codes):
    return b"".join(codes[character] for character in text)


def decode_text(raw, characters):
    text = []
    cursor = 0
    while cursor < len(raw):
        lead = raw[cursor]
        length = 2 if 0x81 <= lead <= 0x9F or 0xE0 <= lead <= 0xFC else 1
        if cursor + length > len(raw):
            raise ValueError("Incomplete font code at the end of a string")
        code = int.from_bytes(raw[cursor:cursor + length], "big")
        text.append(characters[code])
        cursor += length
    return "".join(text)


def prepare_codes(original, required, previous_characters=()):
    native = {
        code: (code_bytes(code).decode("cp932"), width)
        for code, _, _, _, width, *_ in glyph_table(original)
    }
    slots = dict(native)
    codes = {character: code_bytes(code) for code, (character, _) in native.items()}
    for character in codes:
        preferred = character.encode("cp932")
        preferred_code = int.from_bytes(preferred, "big")
        if preferred_code in native and native[preferred_code][0] == character:
            codes[character] = preferred

    # CP932 reserves F0–F9 for user-defined characters. Retain every existing code.
    free = (
        (lead << 8) | trail
        for lead in range(0xF0, 0xFA)
        for trail in range(0x40, 0xFD)
        if trail not in (0x5B, 0x5C, 0x5D, 0x7F) and ((lead << 8) | trail) not in native
    )
    missing_codes = required - codes.keys()
    # Existing saves and backlog text can contain private-use codes from the first release.
    previous_codes = missing_codes.intersection(previous_characters)
    for character in sorted(previous_codes) + sorted(missing_codes - previous_codes):
        code = next(free, None)
        if code is None:
            raise ValueError("The font ran out of user-defined CP932 codes")
        slots[code] = (character, 40)
        codes[character] = code_bytes(code)
    return native, slots, codes


def rasterize(font, character, width):
    mask = Image.new("L", (width * SCALE, HEIGHT * SCALE))

    def draw_centered(value, y):
        advance = round(font.getlength(value))
        left, _, right, _ = font.getbbox(value, anchor="ls")
        advance = max(advance, right) - min(0, left)
        canvas = Image.new("L", (max(width * SCALE, advance + 2 * SCALE), HEIGHT * SCALE))
        left = (canvas.width - advance) // 2 - min(0, left)
        ImageDraw.Draw(canvas).text((left, y * SCALE), value, font=font, fill=255, anchor="ls")
        if canvas.width != mask.width:
            canvas = canvas.resize(mask.size, Image.Resampling.LANCZOS)
        return canvas

    if character == "\u2252":
        # Noto does not encode ≒. Form it from the same face's equals sign and period.
        mask = draw_centered("=", BASELINE)
        period = draw_centered(".", BASELINE)
        dot = period.crop(period.getbbox())
        mask.paste(dot, (7 * SCALE, 10 * SCALE), dot)
        mask.paste(dot, (28 * SCALE, 28 * SCALE), dot)
    else:
        mask = draw_centered(character, BASELINE)
    return mask.resize((width, HEIGHT), Image.Resampling.LANCZOS)


def pack_glyph(mask):
    # The game palette has six translucent-black entries followed by ten opaque
    # gray-to-white entries. Render a dark antialiased outline around the face.
    surround = mask.filter(ImageFilter.MaxFilter(3)).tobytes()
    face = mask.tobytes()
    stride = ((mask.width + 7) // 8) * 4
    output = bytearray()
    for y in range(mask.height):
        start = y * mask.width
        row = bytes(
            6 + (fill * 9 + 127) // 255 if fill >= 32 else (outline * 5 + 127) // 255
            for fill, outline in zip(face[start:start + mask.width],
                                     surround[start:start + mask.width])
        ).ljust(stride * 2, b"\0")
        output.extend((high << 4) | low for high, low in zip(row[::2], row[1::2]))
    return output


def save_preview(path, data, codes):
    palette = [(r, g, b, a) for b, g, r, a in struct.iter_unpack("4B", data[0x28:0x68])]
    records = {code: (at, width, height, stride, size)
               for code, _, _, at, width, height, stride, size in glyph_table(data)}
    lines = ("中文字体预览　简体中文与全角标点。", "剧情对话：这一次，换我守护你。", "「文字」！？　ABC abc 123　あいうアイウ")
    line_widths = [sum(records[int.from_bytes(codes[character], "big")][1] for character in line)
                   for line in lines]
    sample = Image.new("RGBA", (max(line_widths) + 20, 164), "#435163")
    for line_index, line in enumerate(lines):
        x = 10
        for character in line:
            at, width, height, stride, size = records[int.from_bytes(codes[character], "big")]
            glyph = Image.new("RGBA", (stride * 2, height))
            glyph.putdata([palette[index] for value in data[at:at + size]
                           for index in (value >> 4, value & 15)])
            sample.alpha_composite(glyph.crop((0, 0, width, height)), (x, 8 + 52 * line_index))
            x += width
    sample.convert("RGB").save(path)


def build_font(required, output=OUTPUT, previous_characters=()):
    original = (FONT_ROOT / FONT_NAMES[0]).read_bytes()
    if original != (FONT_ROOT / FONT_NAMES[1]).read_bytes():
        raise ValueError("Original system and scenario fonts differ")
    native, slots, codes = prepare_codes(original, required, previous_characters)
    with TTFont(TYPEFACE) as face:
        cmap = face.getBestCmap()
        if any(ord(character) not in cmap for character in required):
            missing = sorted(character for character in required if ord(character) not in cmap)
            raise ValueError(f"The chosen typeface lacks translation characters: {missing}")
        missing = {character for character, _ in slots.values() if ord(character) not in cmap}
        if missing - {"\u2252"}:
            raise ValueError(f"The chosen typeface lacks original characters: {sorted(missing)}")
    font = ImageFont.truetype(str(TYPEFACE), 36 * SCALE)

    ranges, metrics, pixels = [], bytearray(), bytearray()
    cached = {}
    for index, (code, (character, width)) in enumerate(sorted(slots.items())):
        if not ranges or ranges[-1][1] != code:
            ranges.append([code, code + 1, index])
        else:
            ranges[-1][1] += 1
        key = (character, width)
        if key not in cached:
            glyph = pack_glyph(rasterize(font, character, width))
            if bool(any(glyph)) == character.isspace():
                raise ValueError(f"Unexpected blank/visible glyph for {character!r} at {code:04X}")
            cached[key] = glyph
        glyph = cached[key]
        metrics.extend(struct.pack("<BBHI", width, HEIGHT, len(glyph), len(pixels)))
        pixels.extend(glyph)

    ranges_at = 0x428
    metrics_at = ranges_at + 12 * len(ranges)
    pixels_at = metrics_at + len(metrics)
    header = bytearray(original[:ranges_at])
    struct.pack_into("<HI", header, 2, len(ranges), len(slots))
    struct.pack_into("<4I", header, 0x10, pixels_at + len(pixels), ranges_at, metrics_at, pixels_at)
    data = bytes(header) + b"".join(struct.pack("<3I", *row) for row in ranges) + metrics + pixels
    checks = verify_font(data)

    output.mkdir(parents=True, exist_ok=True)
    for name in FONT_NAMES:
        (output / name).write_bytes(data)
    with (output / "chinese_code_table.tsv").open("w", encoding="utf-8-sig", newline="") as dest:
        table = csv.writer(dest, delimiter="\t")
        table.writerow(("code_hex", "character", "unicode", "width", "used_in_translation"))
        for code, (character, width) in sorted(slots.items()):
            table.writerow((code_bytes(code).hex().upper(), character, f"U+{ord(character):04X}",
                            width, int(character in required)))
    save_preview(output / "font_preview.png", data, codes)
    return codes, {code: character for code, (character, _) in slots.items()}, {
        "typeface": TYPEFACE.name,
        "typeface_sha256": hashlib.sha256(TYPEFACE.read_bytes()).hexdigest(),
        "glyphs": len(slots),
        "original_codes_redrawn": len(native),
        "new_codes": len(slots) - len(native),
        "translation_characters": len(required),
        "missing_translation_characters": 0,
        "composed_from_same_typeface": sorted(missing),
        "identical_ffu_sha256": hashlib.sha256(data).hexdigest(),
        "eboot_verification": checks,
    }
