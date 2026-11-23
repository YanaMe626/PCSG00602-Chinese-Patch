"""Export the PCSG00602 UFT glyph atlas and the in-game Shift-JIS map."""
import csv
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
FONT_ROOT = ROOT / "02_解包资源" / "SYSTEM" / "WINDOW" / "FONT"
OUT = ROOT / "06_中文字体" / "original_font"
ATLAS_COLUMNS = 64


def glyph_table(data):
    magic, range_count, count, fmt, height, width, endian, encoding = struct.unpack_from(
        "<2sHIBBBBB", data
    )
    size, ranges, metrics, pixels = struct.unpack_from("<4I", data, 0x10)
    if (magic, fmt, height, width, endian, encoding) != (b"UF", 3, 40, 40, 1, 0):
        raise ValueError("Unexpected PCSG00602 UFT header")
    if not (size == len(data) and ranges == 0x428 and
            metrics == ranges + range_count * 12 and pixels == metrics + count * 8):
        raise ValueError("UFT section boundaries do not match the header")
    last_stop, glyph_index, bitmap_end = 0, 0, pixels
    for start, stop, base in struct.iter_unpack("<III", data[ranges:metrics]):
        if not last_stop <= start < stop or base != glyph_index:
            raise ValueError("UFT character ranges overlap or leave a gap in the glyph records")
        last_stop = stop
        for code in range(start, stop):
            record = metrics + 8 * glyph_index
            glyph_width, glyph_height, length, offset = struct.unpack_from("<BBHI", data, record)
            bitmap = pixels + offset
            stride = ((glyph_width + 7) // 8) * 4
            if (glyph_width not in (20, 40) or glyph_height != height or
                    length != stride * height or bitmap != bitmap_end or bitmap + length > size):
                raise ValueError(f"Unexpected bitmap for character {code:04X}")
            yield code, glyph_index, record, bitmap, glyph_width, glyph_height, stride, length
            glyph_index += 1
            bitmap_end = bitmap + length
    if glyph_index != count or bitmap_end != size:
        raise ValueError("UFT ranges do not cover all glyphs or bitmaps")


def main():
    system_font = (FONT_ROOT / "sysfont.ffu").read_bytes()
    dialogue_font = (FONT_ROOT / "advfont1.ffu").read_bytes()
    if system_font != dialogue_font:
        raise ValueError("This release is expected to share one glyph set across both fonts")
    data = system_font
    glyphs = list(glyph_table(data))
    palette = [(r, g, b, a) for b, g, r, a in struct.iter_unpack("4B", data[0x28:0x68])]
    pixels_for_byte = [(palette[byte >> 4], palette[byte & 15]) for byte in range(256)]
    atlas = Image.new("RGBA", (ATLAS_COLUMNS * 40, ((len(glyphs) + 63) // 64) * 40))
    OUT.mkdir(parents=True, exist_ok=True)
    samples = " A1az\uff71\uff9d\u3042\u3044\u30a2\u4e9c\u5fcd\u604b\u6f22\u8a9e\u2460\u3000"
    preview = Image.new("RGB", (56 * len(samples), 72), "#263346")
    draw = ImageDraw.Draw(preview)
    widths, blank_codes = Counter(), []
    with (OUT / "game_code_table.tsv").open("w", encoding="utf-8-sig", newline="") as table, \
         (OUT / "game_cp932.tbl").open("w", encoding="utf-8", newline="\n") as tbl:
        writer = csv.writer(table, delimiter="\t")
        writer.writerow(("code_hex", "character", "unicode", "glyph_index", "width", "height",
                         "stride_bytes", "record_offset", "bitmap_offset", "bitmap_size",
                         "atlas_x", "atlas_y", "blank"))
        for code, index, record, offset, width, height, stride, length in glyphs:
            raw_code = code.to_bytes(1 if code < 0x100 else 2, "big")
            character = raw_code.decode("cp932")
            hex_code = raw_code.hex().upper()
            raw = data[offset:offset + length]
            glyph = Image.new("RGBA", (stride * 2, height))
            glyph.putdata([color for byte in raw for color in pixels_for_byte[byte]])
            glyph = glyph.crop((0, 0, width, height))
            x, y = index % ATLAS_COLUMNS * 40, index // ATLAS_COLUMNS * 40
            atlas.paste(glyph, (x, y))
            if not any(raw):
                blank_codes.append(hex_code)
            widths[width] += 1
            writer.writerow((hex_code, character, f"U+{ord(character):04X}", index, width,
                             height, stride, f"0x{record:X}", f"0x{offset:X}", length, x, y,
                             int(not any(raw))))
            tbl.write(f"{hex_code}={character}\n")
            if character in samples:
                px = samples.index(character) * 56
                preview.paste(glyph, (px + (56 - width) // 2, 4), glyph)
                draw.text((px + 6, 49), hex_code, fill="white")
    atlas.save(OUT / "font_atlas.png")
    preview.save(OUT / "font_preview.png")
    ranges_offset, metrics_offset, pixels_offset = struct.unpack_from("<3I", data, 0x14)
    report = {
        "source": ["SYSTEM.cpk:WINDOW/FONT/sysfont.ffu", "SYSTEM.cpk:WINDOW/FONT/advfont1.ffu"],
        "identical_fonts": True,
        "sha256": hashlib.sha256(data).hexdigest(),
        "file_size": len(data),
        "glyph_count": len(glyphs),
        "glyph_width_counts": widths,
        "blank_codes": blank_codes,
        "atlas_dimensions": atlas.size,
        "ranges_offset": hex(ranges_offset),
        "range_count": (metrics_offset - ranges_offset) // 12,
        "glyph_records_offset": hex(metrics_offset),
        "pixel_data_offset": hex(pixels_offset),
        "pixel_format": "4bpp; high nibble first",
        "code_table_source": "FFU ranges; Unicode names decoded with CP932",
    }
    (OUT / "font_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Exported {len(glyphs)} glyphs; blank glyph codes: {', '.join(blank_codes)}")


if __name__ == "__main__":
    main()
