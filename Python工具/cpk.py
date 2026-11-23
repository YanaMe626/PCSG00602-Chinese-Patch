"""List and extract named entries from the PCSG00602 CPK archives."""
import argparse
import csv
import struct
import sys
from pathlib import Path, PurePosixPath

UTF_FORMATS = "BbHhIiQqfdI"


def utf_rows(data):
    magic, size, rows, strings, blob, _, cols, stride, count = struct.unpack_from(
        ">4sIIIIIHHI", data
    )
    if magic != b"@UTF" or size + 8 > len(data):
        raise ValueError("Invalid CPK @UTF packet")
    rows, strings, blob = rows + 8, strings + 8, blob + 8

    def string(offset):
        start = strings + offset
        return data[start:data.index(0, start, blob)].decode("utf-8")

    def value(offset, kind):
        if kind == 11:
            start, length = struct.unpack_from(">II", data, offset)
            return data[blob + start:blob + start + length], offset + 8
        fmt = ">" + UTF_FORMATS[kind]
        item = struct.unpack_from(fmt, data, offset)[0]
        return (string(item) if kind == 10 else item), offset + struct.calcsize(fmt)

    columns = []
    cursor = 32
    for _ in range(cols):
        flag, name = struct.unpack_from(">BI", data, cursor)
        cursor += 5
        storage, kind = flag & 0xF0, flag & 0x0F
        default = None
        if storage == 0x30:
            default, cursor = value(cursor, kind)
        elif storage not in (0x10, 0x50):
            raise ValueError(f"Unknown @UTF storage: 0x{storage:X}")
        columns.append((string(name), storage, kind, default))
    for number in range(count):
        cursor = rows + stride * number
        row = {}
        for name, storage, kind, default in columns:
            item = default
            if storage == 0x50:
                item, cursor = value(cursor, kind)
            row[name] = item
        if cursor != rows + stride * (number + 1):
            raise ValueError("@UTF row width mismatch")
        yield row


def packet(file, offset, magic):
    file.seek(offset)
    tag, _, length = struct.unpack("<4sIQ", file.read(16))
    if tag != magic:
        raise ValueError(f"Invalid {magic!r} packet at 0x{offset:X}")
    return utf_rows(file.read(length))


def directory(file):
    header = next(packet(file, 0, b"CPK "))
    toc = header["TocOffset"]
    base = min(toc, header["ContentOffset"])
    entries = list(packet(file, toc, b"TOC "))
    if header["Files"] != len(entries):
        raise ValueError("CPK file count mismatch")
    for row in entries:
        path = PurePosixPath(row["DirName"].lstrip("/"), row["FileName"])
        if path.is_absolute() or any(part in ("..", ".") or ":" in part or "\\" in part
                                     for part in path.parts):
            raise ValueError(f"Unexpected CPK path {path}")
        row["path"] = path.as_posix()
        row["offset"] = base + row["FileOffset"]
    return entries


def crilayla(data):
    if data[:8] != b"CRILAYLA":
        raise ValueError("Expected CRILAYLA data")
    n, compressed = struct.unpack_from("<II", data, 8)
    start = 16 + compressed
    if start + 256 > len(data):
        raise ValueError("Truncated CRILAYLA data")
    result = bytearray(data[start:start + 256]) + bytearray(n)
    pos, buffer, bits = start, 0, 0

    def take(count):
        nonlocal pos, buffer, bits
        while bits < count:
            pos -= 1
            if pos < 16:
                raise ValueError("Truncated CRILAYLA bitstream")
            buffer = (buffer << 8) | data[pos]
            bits += 8
        bits -= count
        value = buffer >> bits
        buffer &= (1 << bits) - 1
        return value

    out = len(result) - 1
    while out >= 256:
        if not take(1):
            result[out] = take(8)
            out -= 1
            continue
        back = out + take(13) + 3
        length = 3
        for width in (2, 3, 5, 8):
            value = take(width)
            length += value
            if value != (1 << width) - 1:
                break
        else:
            while True:
                value = take(8)
                length += value
                if value != 255:
                    break
        if back >= len(result) or out - length < 255:
            raise ValueError("Invalid CRILAYLA back-reference")
        for _ in range(length):
            result[out] = result[back]
            out -= 1
            back -= 1
    return bytes(result)


def read_entry(file, row):
    file.seek(row["offset"])
    data = file.read(row["FileSize"])
    if len(data) != row["FileSize"]:
        raise ValueError(f"Truncated CPK entry {row['path']}")
    if data.startswith(b"CRILAYLA"):
        data = crilayla(data)
    if len(data) != row["ExtractSize"]:
        raise ValueError(f"CPK entry size mismatch for {row['path']}")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--extract", type=Path)
    parser.add_argument("--match", default="*", help="Case-insensitive glob over full CPK paths")
    args = parser.parse_args()
    out = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    out.writerow(("path", "offset", "stored_size", "size"))
    with args.archive.open("rb") as file:
        from fnmatch import fnmatchcase

        for row in directory(file):
            if not fnmatchcase(row["path"].lower(), args.match.lower()):
                continue
            out.writerow((row["path"], f"0x{row['offset']:X}", row["FileSize"], row["ExtractSize"]))
            if args.extract is not None:
                target = args.extract.joinpath(*PurePosixPath(row["path"]).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(read_entry(file, row))


if __name__ == "__main__":
    main()
