"""Rebuild both PCSG00602 fonts and import the two translated TSVs into CPKs."""
import csv
import hashlib
import json
import struct
from bisect import bisect_right
from collections import Counter, defaultdict
from itertools import accumulate, zip_longest
from pathlib import Path
from tempfile import TemporaryDirectory

from build_chinese_font import FONT_NAMES, OUTPUT as FONT_OUTPUT, build_font, decode_text, encode_text
from cpk import directory, read_entry
from extract_text import ARCHIVES, OUT as ORIGINAL_TEXT, ROOT, SCRIPT_END, SCRIPT_START
from patch_texture_cpk import rebuild

TRANSLATIONS = ROOT / "05_AI翻译"
OUTPUT = ROOT / "07_修改后的资源"
SUPPLEMENTAL_STORY = TRANSLATIONS / "story_name_variants_zh.tsv"
SOURCE_BYTES = "cp932_hex"
SOURCE_DIGEST = "source_sha256"


def load_translation(original, translated):
    grouped = defaultdict(list)
    with original.open(encoding="utf-8-sig", newline="") as source, \
         translated.open(encoding="utf-8-sig", newline="") as target:
        originals = csv.DictReader(source, delimiter="\t")
        translations = csv.DictReader(target, delimiter="\t")
        metadata_fields = [key for key in originals.fieldnames if key != SOURCE_BYTES]
        if translations.fieldnames not in (metadata_fields, originals.fieldnames):
            raise ValueError(f"Column mismatch in {translated.name}")
        for old, new in zip_longest(originals, translations):
            if (old is None or new is None or None in new or any(v is None for v in new.values())
                    or any(old[key] != new[key] for key in new if key != "text")):
                raise ValueError(f"Original row mismatch at {translated.name}:{translations.line_num}")
            if "\0" in new["text"]:
                raise ValueError(f"NUL in translation at {translated.name}:{translations.line_num}")
            new[SOURCE_BYTES] = old[SOURCE_BYTES]
            grouped[new["path"]].append(new)
    return grouped


def append_story_supplement(groups, translated):
    locations = {
        (row["path"], int(row["instruction_offset"], 16), int(row["parameter"]))
        for rows in groups.values() for row in rows
    }
    with translated.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source, delimiter="\t")
        sample = next(iter(groups.values()))[0]
        fields = set(sample)
        if set(reader.fieldnames or ()) not in (fields, fields - {SOURCE_BYTES} | {SOURCE_DIGEST}):
            raise ValueError(f"Column mismatch in {translated.name}")
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"Invalid supplemental row at {translated.name}:{reader.line_num}")
            location = (row["path"], int(row["instruction_offset"], 16), int(row["parameter"]))
            if location in locations or "\0" in row["text"]:
                raise ValueError(f"Invalid supplemental text at {translated.name}:{reader.line_num}")
            locations.add(location)
            groups[row["path"]].append(row)


def u32(data, at):
    return struct.unpack_from("<I", data, at)[0]


def set_u32(data, at, value):
    struct.pack_into("<I", data, at, value)


def script_layout(data):
    if not data.startswith(b"STCM2L"):
        raise ValueError("Invalid STCM2L signature")
    start = data.index(SCRIPT_START, 0x50) + len(SCRIPT_START)
    export, export_count, _, collection = struct.unpack_from("<4I", data, 0x20)
    stop = export - len(SCRIPT_END)
    exports_end = export + 40 * export_count
    if not (data[stop:export] == SCRIPT_END
            and data[exports_end:collection] == b"COLLECTION_LINK\0"
            and len(data) == collection + 64
            and struct.unpack_from("<16I", data, collection) == (0, len(data), *([0] * 14))):
        raise ValueError("Unexpected STCM2L export or collection layout")
    instructions = {}
    position = start
    while position < stop:
        call, opcode, count, size = struct.unpack_from("<4I", data, position)
        end = position + size
        if (call not in (0, 1) or count > 16 or size % 4
                or not position + 16 + 12 * count <= end <= stop):
            raise ValueError(f"Invalid instruction at {position:#x}")
        instructions[position] = (call, opcode, count, end)
        position = end
    if position != stop:
        raise ValueError("Code section does not end at EXPORT_DATA")
    return instructions, export, export_count, collection


def read_script_slot(data, instruction, layout, parameter):
    call, opcode, count, end = layout
    if not 0 <= parameter < count:
        raise ValueError(f"Invalid parameter {parameter} at {instruction:#x}")
    pointer = u32(data, instruction + 16 + 12 * parameter)
    if not instruction + 16 + 12 * count <= pointer <= end - 16:
        raise ValueError(f"Translation pointer at {instruction:#x} is outside its inline data")
    kind, units, _, length = struct.unpack_from("<4I", data, pointer)
    at = pointer + 16
    if kind != 0 or length != units * 4 or not 0 < length <= end - at:
        raise ValueError(f"Invalid inline text length at {at:#x}")
    storage = data[at:at + length]
    raw, terminator, padding = storage.partition(b"\0")
    if not terminator or any(padding):
        raise ValueError(f"Nonzero text padding at {at:#x}")
    return at, length, raw


def translated_bytes(row, old_raw, codes):
    if SOURCE_BYTES in row:
        source_matches = old_raw == bytes.fromhex(row[SOURCE_BYTES])
    else:
        source_matches = hashlib.sha256(old_raw).hexdigest() == row[SOURCE_DIGEST]
    if not source_matches:
        raise ValueError(f"Source text bytes differ at {row['text_offset']}")
    if row["text"] == old_raw.decode("cp932"):
        return old_raw
    return encode_text(row["text"], codes)


def patch_story(data, rows, codes):
    instructions, export, export_count, collection = script_layout(data)
    slots = {}
    positions = []
    stats = Counter(rows=len(rows))
    for row in rows:
        instruction = int(row["instruction_offset"], 16)
        parameter = int(row["parameter"])
        layout = instructions[instruction]
        call, opcode, _, _ = layout
        at, size, raw = read_script_slot(data, instruction, layout, parameter)
        if (at != int(row["text_offset"], 16) or size != int(row["storage_size"])
                or row["operation_type"] != ("call" if call else "opcode")
                or opcode != int(row["opcode_or_call_offset"], 16)):
            raise ValueError(f"Scenario metadata mismatch at {instruction:#x}")
        encoded = translated_bytes(row, raw, codes)
        new_size = max(size, (len(encoded) + 4) & ~3)
        slot = size, new_size, encoded
        if at in slots and slots[at] != slot:
            raise ValueError(f"Conflicting translations for shared text at {at:#x}")
        slots[at] = slot
        positions.append((instruction, parameter))
        stats["changed"] += encoded != raw
        stats["expanded_rows"] += new_size != size

    insertions = sorted((at + size, new_size - size)
                        for at, (size, new_size, _) in slots.items() if new_size > size)
    boundaries = [at for at, _ in insertions]
    added = [0, *accumulate(amount for _, amount in insertions)]

    def relocate(offset):
        return offset + added[bisect_right(boundaries, offset)]

    patched = bytearray()
    previous = 0
    for at, amount in insertions:
        patched.extend(data[previous:at])
        patched.extend(bytes(amount))
        previous = at
    patched.extend(data[previous:])

    if insertions:
        for instruction, (call, opcode, count, end) in instructions.items():
            new_instruction = relocate(instruction)
            set_u32(patched, new_instruction + 12, relocate(end) - new_instruction)
            if call:
                if opcode not in instructions:
                    raise ValueError(f"Invalid call target {opcode:#x} at {instruction:#x}")
                set_u32(patched, new_instruction + 4, relocate(opcode))
            for i in range(count):
                at = instruction + 16 + i * 12
                a, b, c = struct.unpack_from("<3I", data, at)
                new_at = relocate(at)
                if a in (0xFFFFFF40, 0xFFFFFF41):
                    if b not in instructions or c != 0x40000000:
                        raise ValueError(f"Invalid jump target {b:#x} at {instruction:#x}")
                    set_u32(patched, new_at + 4, relocate(b))
                else:
                    if a == 0xFFFFFF42:
                        raise ValueError(f"Unexpected collection-link parameter at {instruction:#x}")
                    for index, field in enumerate((a, b, c)):
                        if field >> 30 == 0:
                            if not 0 < field < export:
                                raise ValueError(f"Invalid data target {field:#x} at {instruction:#x}")
                            set_u32(patched, new_at + index * 4, relocate(field))
        for index in range(export_count):
            at = export + 40 * index
            if u32(data, at) != 0 or u32(data, at + 36) not in instructions:
                raise ValueError(f"Unexpected export record at {at:#x}")
            set_u32(patched, relocate(at + 36), relocate(u32(data, at + 36)))
        set_u32(patched, 0x20, relocate(export))
        set_u32(patched, 0x2C, relocate(collection))
        set_u32(patched, relocate(collection) + 4, len(patched))

    for at, (_, size, raw) in slots.items():
        new_at = relocate(at)
        set_u32(patched, new_at - 12, size // 4)
        set_u32(patched, new_at - 4, size)
        patched[new_at:new_at + size] = raw.ljust(size, b"\0")
    return patched, [(relocate(at), arg) for at, arg in positions], stats


def verify_story(data, rows, positions, characters):
    layout, _, _, _ = script_layout(data)
    for row, (at, argument) in zip(rows, positions, strict=True):
        _, _, raw = read_script_slot(data, at, layout[at], argument)
        if decode_text(raw, characters) != row["text"]:
            raise ValueError(f"Scenario text readback differs at {at:#x}, argument {argument}")


def gstr_layout(data):
    if data[:4] != b"GSTL":
        raise ValueError("Invalid GSTL signature")
    rows, count, stride, _, end, pool_count, pool = struct.unpack_from("<7I", data, 0x14)
    if stride != 12 or rows + count * stride != end or not end <= pool < len(data):
        raise ValueError("Invalid GSTL table")
    strings = {}
    start = pool
    for _ in range(pool_count):
        stop = data.index(0, start)
        strings[start - pool] = data[start:stop]
        start = stop + 1
    if start != len(data):
        raise ValueError("GSTL pool count does not match the file size")
    return range(rows, end, stride), pool, strings


def patch_system(data, rows, codes):
    positions, pool, strings = gstr_layout(data)
    patched = bytearray(data[:pool])
    offsets = {}
    stats = Counter(rows=len(rows))

    def intern(raw):
        if raw not in offsets:
            offsets[raw] = len(patched) - pool
            patched.extend(raw + b"\0")
        return offsets[raw]

    for row, at in zip(rows, positions, strict=True):
        name, key, text = struct.unpack_from("<3I", data, at)
        if (int(row["id"]) != key or row["symbol"].encode("ascii") != strings[name]
                or int(row["text_offset"], 16) != pool + text):
            raise ValueError(f"System string metadata mismatch at row {key}")
        raw = strings[text]
        encoded = translated_bytes(row, raw, codes)
        struct.pack_into("<3I", patched, at, intern(strings[name]), key, intern(encoded))
        stats["changed"] += encoded != raw
    set_u32(patched, 0x28, len(offsets))
    return patched, None, stats


def verify_system(data, rows, _, characters):
    positions, _, strings = gstr_layout(data)
    for row, at in zip(rows, positions, strict=True):
        name, key, text = struct.unpack_from("<3I", data, at)
        if ((key, strings[name].decode("ascii")) != (int(row["id"]), row["symbol"])
                or decode_text(strings[text], characters) != row["text"]):
            raise ValueError(f"System string readback differs at row {key}")


def build_archive(name, rows_by_path, patch, verify, codes, characters, workspace, fonts=None):
    source = ARCHIVES / name
    target = workspace / name
    replacements = dict(fonts or {})
    positions_by_path = {}
    totals = Counter()
    with source.open("rb") as archive:
        for entry in directory(archive):
            path = entry["path"]
            if path not in rows_by_path:
                continue
            try:
                patched, positions, stats = patch(read_entry(archive, entry), rows_by_path[path], codes)
            except (ValueError, KeyError, struct.error) as exc:
                raise ValueError(f"{name}:{path}: {exc}") from exc
            replacement = workspace / name.removesuffix(".cpk") / path
            replacement.parent.mkdir(parents=True, exist_ok=True)
            replacement.write_bytes(patched)
            replacements[path] = replacement
            positions_by_path[path] = positions
            totals.update(stats)
    if rows_by_path.keys() != positions_by_path.keys():
        raise ValueError(f"Text resource missing from {name}")
    report = rebuild(source, target, replacements, allow_resize=True)
    with target.open("rb") as archive:
        for entry in directory(archive):
            path = entry["path"]
            if path in rows_by_path:
                verify(read_entry(archive, entry), rows_by_path[path], positions_by_path[path], characters)
    return {**report, **totals, "text_files": len(rows_by_path),
            "text_rows_verified_after_repack": totals["rows"]}


def main():
    inputs = {
        "STORY.cpk": ("story_text.tsv", "story_text_merged_114201_114677.tsv", patch_story, verify_story),
        "SYSTEM.cpk": ("system_strings.tsv", "system_strings_translated.tsv", patch_system, verify_system),
    }
    groups = {
        name: load_translation(ORIGINAL_TEXT / original, TRANSLATIONS / translation)
        for name, (original, translation, _, _) in inputs.items()
    }
    story_rows_before = sum(map(len, groups["STORY.cpk"].values()))
    required = set()
    for paths in groups.values():
        for rows in paths.values():
            for row in rows:
                required.update(row["text"])
    previous_characters = required.copy()
    if SUPPLEMENTAL_STORY.is_file():
        append_story_supplement(groups["STORY.cpk"], SUPPLEMENTAL_STORY)
        for rows in groups["STORY.cpk"].values():
            for row in rows:
                required.update(row["text"])
    OUTPUT.mkdir(exist_ok=True)
    with TemporaryDirectory(prefix="text-build-", dir=OUTPUT) as temporary:
        workspace = Path(temporary)
        generated_fonts = workspace / "font"
        codes, characters, font_report = build_font(required, generated_fonts, previous_characters)
        print(f"Verified {font_report['glyphs']} new glyph records in the game decoder", flush=True)
        fonts = {f"WINDOW/FONT/{name}": generated_fonts / name for name in FONT_NAMES}
        report = {"font": font_report, "archives": {}}
        for name, (_, translation, patch, verify) in inputs.items():
            summary = build_archive(name, groups[name], patch, verify, codes, characters, workspace,
                                    fonts if name == "SYSTEM.cpk" else None)
            summary["translation_file"] = translation
            summary["translation_sha256"] = hashlib.sha256((TRANSLATIONS / translation).read_bytes()).hexdigest()
            if name == "STORY.cpk" and SUPPLEMENTAL_STORY.is_file():
                summary["supplemental_file"] = SUPPLEMENTAL_STORY.name
                summary["supplemental_sha256"] = hashlib.sha256(SUPPLEMENTAL_STORY.read_bytes()).hexdigest()
                summary["supplemental_rows"] = summary["rows"] - story_rows_before
            report["archives"][name] = summary
            print(f"{name}: verified {summary['rows']} text rows in {summary['text_files']} files", flush=True)

        FONT_OUTPUT.mkdir(exist_ok=True)
        for item in generated_fonts.iterdir():
            item.replace(FONT_OUTPUT / item.name)
        for name in inputs:
            (workspace / name).replace(OUTPUT / name)
        (OUTPUT / "text_import_report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
