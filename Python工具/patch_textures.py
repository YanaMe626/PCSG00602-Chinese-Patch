"""Transplant the supplied Chinese artwork into the PCSG00602 texture slots."""
import argparse
import json
import struct
from collections import defaultdict
from pathlib import Path

import numpy as np
from PIL import Image, ImageFilter

from cpk import directory, read_entry
from patch_texture_cpk import rebuild

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "11_游戏贴图"
ARCHIVES = ROOT / "02_解包资源/PCSG00602_decrypted/data"
OUTPUT = ROOT / "07_修改后的资源/PCSG00602_中文贴图"
RESAMPLE = Image.Resampling.LANCZOS

# Rectangles use the 1:2 reference scale. Outside these areas the original pixels
# remain in place. Three-element rules move a strip into a different Vita slot.
HEADER = (176, 5, 404, 22)
LOGO = (314, 34, 435, 76)
RESULT_DIR = "ORIGINAL/DISCIPLINE/CL3/DISCIPLINE_RESULTCW_"
ROWS = tuple((2, y, 219, y + 24) for y in range(104, 319, 32))
MOVIE_ROWS = tuple((*box, (box[0], box[1] + 32)) for box in ROWS[:6])
SPECS = (
    ("0e94dde8", "SYSTEM", "GLOBAL/UI_ADV_INFOWIN.tid", 0,
     ((7, 95, 258, 119),)),
    ("1d4f8e95", "GAME", "RESULT/UI_RESULT_PARTS3.tid", 0, None),
    ("1f955fab", "GAME", "GALLERY/SOUND/UI_SOUND_TRUNK_PARTS01.tid", 0,
     (HEADER, LOGO, (279, 159, 359, 176), (231, 175, 496, 192))),
    ("293f0daf", "SYSTEM", "GLOBAL/UI_OPTION_TOP_PARTS.tid", 0,
     (LOGO, (343, 95, 509, 128))),
    ("3fe23fb2", "GAME", "ADV/BG/7060.tid", 0, None),
    ("4d8454e2", "GAME", "ORIGINAL/DISCIPLINE/DISCIPLINE_PARTS2.tid", 0,
     (HEADER, LOGO, (329, 145, 380, 165), (398, 238, 510, 256))),
    ("57b690bf", "GAME", "ORIGINAL/CHARA_SELECT/UI_CHARA_SEL1.tid", 0,
     (HEADER, LOGO, (0, 112, 403, 287),
      (0, 295, 336, 325), (0, 328, 224, 359), (351, 311, 512, 329))),
    ("5b5edd53", "GAME", "ORIGINAL/DISCIPLINE/DISCIPLINE_PARTS1.tid", 0,
     ((0, 157, 337, 217), (0, 347, 224, 413))),
    ("76bc8aac", "GAME", "GALLERY/CG/UI_CG_GALLERY_PARTS.tid", 0,
     (HEADER, LOGO, *ROWS[:6], (226, 110, 279, 133), (239, 295, 511, 328))),
    ("7711fb96", "SYSTEM", "GLOBAL/UI_ADV_WINDOW.tid", 0,
     ((1, 360, 338, 383), (170, 398, 251, 420), (259, 398, 339, 420))),
    ("82426180", "GAME", "GALLERY/MOVIE/UI_MOVIE_TEX_PARTS01.tid", 0,
     (HEADER, LOGO, *MOVIE_ROWS, (*ROWS[6], (2, 104)), (334, 310, 512, 328))),
    ("8dad5d00", "SYSTEM", "GLOBAL/UI_PALETTE_MENU.tid", 0,
     ((0, 146, 287, 178), (0, 186, 287, 219))),
    ("93c2f602", "GAME", "RESULT/UI_RESULT_PARTS1.tid", 0,
     (HEADER, LOGO, (0, 111, 487, 284), (464, 310, 511, 329))),
    ("968909e1", "GAME", "TITLE/UI_TITLE_PARTS.tid", 0,
     ((6, 23, 237, 50), (0, 77, 226, 174))),
    ("b9e7094e", "GAME", RESULT_DIR + "2.CL3", 2109952, ((3, 148, 183, 216),)),
    ("c8c898f6", "GAME", "GALLERY/GALLERY_UI_PARTS_TEX.tid", 0,
     (HEADER, LOGO, (15, 102, 208, 181), (344, 238, 510, 256))),
    ("cfb63764", "SYSTEM", "GLOBAL/WND_BACKLOG.tid", 0,
     ((307, 205, 471, 233), (184, 235, 508, 256))),
    ("e7ee1671", "GAME", RESULT_DIR + "0.CL3", 2109888, ((3, 148, 197, 216),)),
    ("e7ee1671", "GAME", RESULT_DIR + "1.CL3", 2107584, ((3, 148, 197, 216),)),
    ("e9430766", "GAME", "ADV/NAME_ENTRY/UI_NAME_ENTRY_PARTS01.tid", 0,
     (HEADER, LOGO, (112, 343, 337, 405), (414, 493, 511, 512))),
    ("fd9d2a75", "GAME", "DICTIONARY/UI_DICTIONARY_PARTS.tid", 0,
     (HEADER, LOGO, (0, 195, 318, 256), (376, 204, 511, 256))),
    # The sequel skins share these slots but their artwork and extra characters differ.
    ("0e94dde8", "SYSTEM", "GLOBAL/SETUGEKKA/UI_ADV_INFOWIN_S.tid", 0,
     ((7, 95, 258, 119),)),
    ("4d8454e2", "GAME", "ORIGINAL/DISCIPLINE/SETUGEKKA/DISCIPLINE_PARTS1_S.tid", 0,
     (HEADER, LOGO, (329, 145, 380, 165), (398, 238, 510, 256))),
    ("57b690bf", "GAME", "ORIGINAL/CHARA_SELECT/SETUGEKKA/UI_CHARA_SEL1_S.tid", 0,
     (HEADER, LOGO, (351, 311, 512, 329))),
    ("7711fb96", "SYSTEM", "GLOBAL/SETUGEKKA/UI_ADV_TALKWIN_S.tid", 0,
     ((1, 360, 338, 383), (170, 398, 251, 420), (259, 398, 339, 420))),
    ("8dad5d00", "SYSTEM", "GLOBAL/SETUGEKKA/UI_PALETTEMENU_S.tid", 0,
     ((0, 146, 287, 178), (0, 186, 287, 219))),
    ("93c2f602", "GAME", "RESULT/SETUGEKKA/UI_RESULT_PARTS1_S.tid", 0,
     (HEADER, LOGO, (464, 310, 511, 329))),
    ("cfb63764", "SYSTEM", "GLOBAL/SETUGEKKA/UI_ADV_BACKLOGWIN_S.tid", 0,
     ((307, 205, 471, 233), (184, 235, 508, 256))),
    ("e9430766", "GAME", "ADV/NAME_ENTRY/UI_NAME_ENTRY_PARTS03.tid", 0,
     (HEADER, LOGO, (112, 343, 337, 405), (414, 493, 511, 512))),
)


def texture(data, offset):
    dims = struct.unpack_from("<III", data, offset + 0x44)
    length, start = struct.unpack_from("<II", data, offset + 0x58)
    width, height, depth = dims
    begin, end = offset + start, offset + start + length
    if (data[offset:offset + 4] not in (b"TID\x92", b"TID\x82") or depth != 32 or
            start != 128 or length != width * height * 4 or end > len(data)):
        raise ValueError(f"Unsupported TID at 0x{offset:X}")
    image = Image.frombytes("RGBA", (width, height), data[begin:end], "raw", "ARGB")
    return image, begin, end


def encode(image):
    array = np.asarray(image, dtype=np.uint8)
    return np.ascontiguousarray(array[:, :, [3, 0, 1, 2]]).tobytes()


def extract_alpha(image):
    """Recover text alpha from a white-matte JPEG and restore an outline."""
    rgb = np.asarray(image.convert("RGB"), dtype=np.float32)
    strength = 255.0 - rgb.min(axis=2)
    alpha = np.clip((strength - 32) * (255 / 180), 0, 255)
    rgb = 255 - np.minimum(255, (255 - rgb) * 255 / np.maximum(1, alpha[..., None]))
    ink = Image.fromarray(np.dstack((rgb, alpha)).astype(np.uint8))
    shadow = Image.new("RGBA", ink.size, "white")
    shadow.putalpha(ink.getchannel("A").filter(ImageFilter.MaxFilter(3)))
    return Image.alpha_composite(shadow, ink)


def copy_rule(original, translated, rule, jpeg):
    source = rule[:4]
    x, y = rule[4] if len(rule) == 5 else source[:2]
    w, h = source[2] - source[0], source[3] - source[1]
    if (min(*source, x, y) < 0 or source[2] > translated.width or source[3] > translated.height or
            2 * (x + w) > original.width or 2 * (y + h) > original.height):
        raise ValueError(f"Texture rectangle exceeds the source or target: {rule}")
    patch = translated.crop(source)
    dst_box = (2 * x, 2 * y, 2 * (x + w), 2 * (y + h))
    dest = original.crop(dst_box)
    # Banners and colored buttons are already backed by artwork in the texture.
    # Standalone JPEG text requires its white matte to be removed first.
    baked = rule == HEADER or len(rule) == 5 or source == (329, 145, 380, 165)
    if jpeg and not baked:
        patch = extract_alpha(patch)
    patch = patch.resize(dest.size, RESAMPLE)
    if baked:
        # The banner rectangle includes original background under the text.
        # Keep the original alpha, including the transparent corners of the tabs.
        patch.putalpha(dest.getchannel("A"))
    original.paste(patch, dst_box[:2])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--textures-only", action="store_true")
    args = parser.parse_args()
    grouped = defaultdict(list)
    for prefix, arc, path, offset, regions in SPECS:
        grouped[arc].append((prefix, path, offset, regions))
    manifest = {"textures": [], "archives": {}}
    for arc, specs in grouped.items():
        replacements = {}
        src = ARCHIVES / f"{arc}.cpk"
        with src.open("rb") as file:
            entries = {row["path"]: row for row in directory(file)}
            for prefix, path, offset, regions in specs:
                source, = INPUT.glob(prefix + "*")
                raw = read_entry(file, entries[path])
                original, begin, end = texture(raw, offset)
                translated = Image.open(source).convert("RGBA")
                if regions is None:
                    if (2 * translated.width, 2 * translated.height) != original.size:
                        raise ValueError(f"Unexpected source size {source.name}")
                    original = translated.resize(original.size, RESAMPLE)
                else:
                    for rule in regions:
                        copy_rule(original, translated, rule, source.suffix.lower() == ".jpg")
                repacked = raw[:begin] + encode(original) + raw[end:]
                check, _, _ = texture(repacked, offset)
                if len(repacked) != len(raw) or check.tobytes() != original.tobytes():
                    raise ValueError(f"TID verification failed for {path}")
                dest = OUTPUT / "textures" / arc / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(repacked)
                preview = OUTPUT / "previews" / arc / Path(path).with_suffix(".png")
                preview.parent.mkdir(parents=True, exist_ok=True)
                original.save(preview)
                replacements[path] = dest
                manifest["textures"].append({"input": source.name, "archive": f"{arc}.cpk",
                    "entry": path, "tid_offset": f"0x{offset:X}", "texture_dimensions": original.size,
                    "entry_bytes": len(raw), "preview": str(preview.relative_to(OUTPUT))})
        if not args.textures_only:
            target = OUTPUT / "data" / src.name
            target.parent.mkdir(exist_ok=True)
            manifest["archives"][src.name] = rebuild(src, target, replacements)
            print(src.name, manifest["archives"][src.name], flush=True)
    (OUTPUT / "texture_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"{len(manifest['textures'])} texture entries", flush=True)


if __name__ == "__main__":
    main()
