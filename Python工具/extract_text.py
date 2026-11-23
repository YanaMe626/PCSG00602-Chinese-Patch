"""Extract source text from PCSG00602 STCM2L and GSTL records."""
import csv
import json
import re
import struct
from collections import Counter
from functools import lru_cache
from pathlib import Path

from cpk import directory, read_entry

ROOT = Path(__file__).resolve().parents[1]
ARCHIVES = ROOT / "02_解包资源" / "PCSG00602_decrypted" / "data"
OUT = ROOT / "04_日文原文"
SCRIPT_START = b"CODE_START_\0"
SCRIPT_END = b"EXPORT_DATA\0"
JAPANESE = re.compile(r"[\u3000-\u30ff\u4e00-\u9fff\uff01-\uff9f]")
PADDED_STRING = re.compile(rb"[^\x00]+\x00{1,4}")
STACK_ARG = 0xFFFFFF00
MESSAGE_SUBTYPE = {0x65: "dialogue", 0xC9: "speaker"}


def text_role(data, entry, call, opcode, count, end, index):
    if call == 0 and opcode == 0x213 and count == 5 and index == 1:
        return "choice"
    if call == 0 and opcode == 0x226 and count == 8 and index == 2:
        subtype_at, = struct.unpack_from("<I", data, entry + 16)
        if entry + 16 + 12 * count <= subtype_at <= end - 20:
            if struct.unpack_from("<4I", data, subtype_at) == (0, 1, 1, 4):
                subtype, = struct.unpack_from("<I", data, subtype_at + 16)
                return MESSAGE_SUBTYPE.get(subtype, "")
    return ""


def system_strings(data):
    if not data.startswith(b"GSTL"):
        raise ValueError("Unexpected GSTR signature")
    rows, count, stride = struct.unpack_from("<3I", data, 0x14)
    pool, = struct.unpack_from("<I", data, 0x2C)
    if not (stride == 12 and rows + count * stride <= pool < len(data)):
        raise ValueError("Invalid GSTL table layout")
    for row in range(rows, rows + count * stride, stride):
        name_rel, key, text_rel = struct.unpack_from("<3I", data, row)
        name_at, text_at = pool + name_rel, pool + text_rel
        symbol = data[name_at:data.index(0, name_at)].decode("ascii")
        raw = data[text_at:data.index(0, text_at)]
        yield key, symbol, f"0x{text_at:X}", raw.hex(" ").upper(), raw.decode("cp932")


def script_strings(data):
    if not data.startswith(b"STCM2L"):
        raise ValueError("Unexpected scenario signature")
    marker = data.index(SCRIPT_START, 0x50)
    entry = marker + len(SCRIPT_START)
    export, = struct.unpack_from("<I", data, 0x20)
    stop = export - len(SCRIPT_END)
    if not (marker % 4 == 0 and entry <= stop and data[stop:export] == SCRIPT_END):
        raise ValueError("Invalid STCM2L code section")
    code_start = entry

    @lru_cache(maxsize=None)
    def forwarded_role(callee, index, depth=0):
        if depth == 4:
            return ""
        slot = STACK_ARG + index
        for _ in range(5):
            if not code_start <= callee <= stop - 16:
                return ""
            call, opcode, count, size = struct.unpack_from("<4I", data, callee)
            end = callee + size
            if not (call in (0, 1) and count <= 16 and callee + 16 + 12 * count <= end <= stop):
                return ""
            for i in range(count):
                arg = struct.unpack_from("<3I", data, callee + 16 + 12 * i)
                if arg != (slot, 0x40000000, 0x40000000):
                    continue
                role = (forwarded_role(opcode, i, depth + 1) if call else
                        text_role(data, callee, call, opcode, count, end, i))
                if role:
                    return role
            # The observed wrappers only call another wrapper or set up a local
            # value before the native message command.
            if call == 0 and opcode not in (0x11, 0xFFFFFF14):
                return ""
            callee = end
        return ""

    while entry < stop:
        call, opcode, count, size = struct.unpack_from("<4I", data, entry)
        payload = entry + 16 + 12 * count
        end = entry + size
        if call not in (0, 1) or count > 16 or not payload <= end <= stop:
            raise ValueError(f"Invalid STCM2L instruction at 0x{entry:X}")
        for i in range(count):
            pointer, _, _ = struct.unpack_from("<3I", data, entry + 16 + 12 * i)
            if not payload <= pointer <= end - 16:
                continue
            kind, units, _, length = struct.unpack_from("<4I", data, pointer)
            text_at = pointer + 16
            if kind != 0 or units * 4 != length or not 0 < length <= end - text_at:
                continue
            storage = data[text_at:text_at + length]
            if not PADDED_STRING.fullmatch(storage):
                continue
            raw = storage.rstrip(b"\0")
            try:
                text = raw.decode("cp932")
            except UnicodeDecodeError:
                continue
            if not all(c.isprintable() or c in "\t\r\n\u3000" for c in text):
                continue
            role = (forwarded_role(opcode, i) if call else
                    text_role(data, entry, call, opcode, count, end, i))
            if role or JAPANESE.search(text):
                yield (role, f"0x{entry:X}", "call" if call else "opcode", f"0x{opcode:X}", i,
                       f"0x{text_at:X}", length, raw.hex(" ").upper(), text)
        entry = end


def extract(archive, suffix, out_name, parse, columns):
    count = file_count = 0
    empty = []
    with (ARCHIVES / archive).open("rb") as source, \
         (OUT / out_name).open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.writer(target, delimiter="\t")
        writer.writerow(("path", *columns))
        for entry in directory(source):
            path = entry["path"]
            if not path.lower().endswith(suffix):
                continue
            file_count += 1
            before = count
            try:
                for row in parse(read_entry(source, entry)):
                    writer.writerow((path, *row))
                    count += 1
            except (ValueError, struct.error) as exc:
                raise ValueError(f"{archive}:{path}: {exc}") from exc
            if count == before:
                empty.append(path)
            if file_count % 50 == 0:
                print(f"{archive}: processed {file_count} files", flush=True)
    return {"files": file_count, "rows": count, "files_without_rows": empty}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    system = extract("SYSTEM.cpk", ".gstr", "system_strings.tsv", system_strings,
                     ("id", "symbol", "text_offset", "cp932_hex", "text"))
    columns = ("role", "instruction_offset", "operation_type", "opcode_or_call_offset",
               "parameter", "text_offset", "storage_size", "cp932_hex", "text")
    story = extract("STORY.cpk", ".dat", "story_string_candidates.tsv", script_strings, columns)
    roles = Counter()
    with (OUT / "story_string_candidates.tsv").open(encoding="utf-8-sig", newline="") as source, \
         (OUT / "story_text.tsv").open("w", encoding="utf-8-sig", newline="") as target:
        reader = csv.DictReader(source, delimiter="\t")
        writer = csv.DictWriter(target, reader.fieldnames, delimiter="\t")
        writer.writeheader()
        for row in reader:
            if row["role"]:
                writer.writerow(row)
                roles[row["role"]] += 1
    report = {"system": system, "story": story,
              "classified_story_rows": roles,
              "story_coverage": "Inline, CP932-decodable STCM2L data and observed text opcodes"}
    (OUT / "text_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
