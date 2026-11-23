"""Rebuild the PCSG00602 CPKs with uncompressed replacement entries."""
import hashlib
import shutil
import struct
from pathlib import Path

from cpk import directory, packet, read_entry


def update_utf_numbers(data, updates):
    """Write existing per-row fields while preserving the @UTF schema and strings."""
    rows, strings, blob, _, cols, stride, count = struct.unpack_from(">IIIIHHI", data, 8)
    pos = 32
    row_offset = 0
    fields = {}
    sizes = (1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 4, 8)
    for _ in range(cols):
        flag, name = struct.unpack_from(">BI", data, pos)
        pos += 5
        storage, kind = flag & 0xF0, flag & 0xF
        start = 8 + strings + name
        name = data[start:data.index(0, start, 8 + blob)].decode()
        size = sizes[kind]
        if storage == 0x30:
            pos += size
        elif storage == 0x50:
            fields[name] = row_offset, size, kind
            row_offset += size
    if row_offset != stride:
        raise ValueError("Unexpected @UTF row layout")
    for row, changes in updates.items():
        if not 0 <= row < count:
            raise ValueError("Row outside @UTF packet")
        for name, value in changes.items():
            offset, size, kind = fields[name]
            if kind not in (0, 2, 4, 6):
                raise ValueError(f"Unsupported numeric field {name}")
            begin = 8 + rows + row * stride + offset
            data[begin:begin + size] = value.to_bytes(size, "big")


def patch_packet(file, offset, changes):
    file.seek(offset + 8)
    length, = struct.unpack("<Q", file.read(8))
    data = bytearray(file.read(length))
    update_utf_numbers(data, changes)
    file.seek(offset + 16)
    file.write(data)


def verify(source, target, replacements):
    checked = 0
    with source.open("rb") as original, target.open("rb") as patched:
        header = next(packet(patched, 0, b"CPK "))
        if header["EtocOffset"] + header["EtocSize"] != target.stat().st_size:
            raise ValueError("Unexpected ETOC end")
        list(packet(patched, header["EtocOffset"], b"ETOC"))
        before, after = directory(original), directory(patched)
        for old, new in zip(before, after, strict=True):
            path = old["path"]
            if (new["path"], new["ID"]) != (path, old["ID"]):
                raise ValueError(f"CPK directory mismatch for {path}")
            if new["offset"] % header["Align"]:
                raise ValueError(f"Unaligned entry {path}")
            if path in replacements:
                if read_entry(patched, new) != replacements[path].read_bytes():
                    raise ValueError(f"Replacement readback differs for {path}")
            else:
                if (old["FileSize"], old["ExtractSize"]) != (new["FileSize"], new["ExtractSize"]):
                    raise ValueError(f"Unchanged entry sizes differ for {path}")
                original.seek(old["offset"])
                patched.seek(new["offset"])
                if original.read(old["FileSize"]) != patched.read(new["FileSize"]):
                    raise ValueError(f"Untouched data changed for {path}")
                checked += 1
    with target.open("rb") as file:
        return {"replaced": len(replacements), "unchanged_entries_verified": checked,
                "bytes": target.stat().st_size, "sha256": hashlib.file_digest(file, "sha256").hexdigest()}


def rebuild(source, target, replacements, *, allow_resize=False):
    temp = target.with_suffix(".cpk.tmp")
    with source.open("rb") as original, temp.open("w+b") as patched:
        header = next(packet(original, 0, b"CPK "))
        entries = directory(original)
        if not replacements.keys() <= {row["path"] for row in entries}:
            raise ValueError("Replacement path missing from the original CPK")
        toc, content, etoc, align = (header[k] for k in (
            "TocOffset", "ContentOffset", "EtocOffset", "Align"
        ))
        if not (toc < content < etoc and header["EnableFileCrc"] == header["EnableTocCrc"] == 0):
            raise ValueError("Unexpected CPK layout or checksum mode")
        original.seek(0)
        patched.write(original.read(content))
        changes = {}
        packed_delta = 0
        extracted_delta = 0
        for row, entry in sorted(enumerate(entries), key=lambda item: item[1]["offset"]):
            path = entry["path"]
            offset = patched.tell()
            if path in replacements:
                data = replacements[path].read_bytes()
                if data.startswith(b"CRILAYLA") or (not allow_resize and len(data) != entry["ExtractSize"]):
                    raise ValueError(f"Invalid replacement size or marker for {path}")
            else:
                original.seek(entry["offset"])
                data = original.read(entry["FileSize"])
                if len(data) != entry["FileSize"]:
                    raise ValueError(f"Truncated original {path}")
            patched.write(data)
            padding = -patched.tell() % align
            patched.write(b"\0" * padding)
            changes[row] = {"FileOffset": offset - toc, "FileSize": len(data)}
            if path in replacements and len(data) != entry["ExtractSize"]:
                changes[row]["ExtractSize"] = len(data)
                extracted_delta += len(data) - entry["ExtractSize"]
            packed_delta += len(data) - entry["FileSize"]
        new_etoc = patched.tell()
        original.seek(etoc)
        shutil.copyfileobj(original, patched)
        patch_packet(patched, toc, changes)
        header_changes = {
            "ContentSize": new_etoc - content, "EtocOffset": new_etoc,
            "EnabledPackedSize": header["EnabledPackedSize"] + packed_delta,
        }
        if allow_resize:
            # This game's archives store the aggregate sizes of multiple views
            # of the same entries. Preserve the relationships in the source.
            raw_size = sum(entry["ExtractSize"] for entry in entries)
            stored_size = sum(entry["FileSize"] for entry in entries)
            if (header["EnabledPackedSize"], header["EnabledDataSize"]) != (
                2 * raw_size, raw_size + stored_size
            ):
                raise ValueError("Unexpected aggregate sizes in the source CPK")
            header_changes["EnabledPackedSize"] = 2 * (raw_size + extracted_delta)
            header_changes["EnabledDataSize"] = raw_size + extracted_delta + stored_size + packed_delta
        patch_packet(patched, 0, {0: header_changes})
    report = verify(source, temp, replacements)
    temp.replace(target)
    return report
