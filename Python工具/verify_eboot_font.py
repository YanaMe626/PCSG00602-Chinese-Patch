"""Run the original Thumb decoder and glyph lookup against the exported map."""
import hashlib
import json
import struct

from unicorn import UC_ARCH_ARM, UC_MODE_THUMB, Uc
from unicorn.arm_const import (
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP,
)

from extract_font import FONT_ROOT, OUT, ROOT, glyph_table

LOOKUP = 0x810C25A4
DECODE = 0x810C33CC
CONTEXT = 0x100000
FONT = 0x1000000
RETURN = 0x800000
STACK = 0x810000
STRING = CONTEXT + 0x30000
STATE = STRING + 0x10


def verify_font(data, additional_codes=()):
    elf = (ROOT / "02_解包资源" / "PCSG00602_decrypted" / "PCSG00602.elf").read_bytes()
    verified = json.loads((ROOT / "03_文件结构分析/ghidra/decryption_report.json").read_text())
    if hashlib.sha256(elf).hexdigest() != verified["elf_sha256"]:
        raise ValueError("ELF differs from the verified retail build")
    header = struct.unpack_from("<16sHHIIIIIHHHHHH", elf)
    machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for index in range(header[10]):
        kind, offset, address, _, length, memsize, _, _ = struct.unpack_from(
            "<8I", elf, header[5] + index * header[9]
        )
        if kind == 1:
            machine.mem_map(address, (memsize + 4095) & ~4095)
            machine.mem_write(address, elf[offset:offset + length])
    machine.mem_map(CONTEXT, 0x40000)
    machine.mem_map(FONT, (len(data) + 4095) & ~4095)
    machine.mem_map(STACK, 0x10000)
    machine.mem_write(FONT, data)
    machine.mem_write(CONTEXT + 4, struct.pack("<I", FONT))

    def run(entry, arg, result=0):
        machine.reg_write(UC_ARM_REG_SP, STACK + 0xFFF0)
        machine.reg_write(UC_ARM_REG_LR, RETURN | 1)
        machine.reg_write(UC_ARM_REG_R0, CONTEXT)
        machine.reg_write(UC_ARM_REG_R1, arg)
        machine.reg_write(UC_ARM_REG_R2, result)
        machine.emu_start(entry | 1, RETURN, count=3000)
        if machine.reg_read(UC_ARM_REG_PC) != RETURN:
            raise ValueError(f"Thumb function did not return at 0x{entry:X}")
        return machine.reg_read(UC_ARM_REG_R0)

    records = {code: offset for code, _, offset, *_ in glyph_table(data)}
    for code in range(0x10000):
        expected = FONT + records[code] if code in records else 0
        if run(LOOKUP, code) != expected:
            raise ValueError(f"Lookup mismatch at code {code:04X}")
    codes = records.keys() | set(additional_codes)
    for code in sorted(codes):
        raw = code.to_bytes(1 if code < 256 else 2, "big")
        machine.mem_write(STRING, raw.ljust(4, b"\0"))
        status = run(DECODE, STRING, STATE)
        if status != 0 or struct.unpack("<II", machine.mem_read(STATE, 8)) != (code, len(raw)):
            raise ValueError(f"Decoder mismatch at code {code:04X}")
    return {"lookup_address": hex(LOOKUP), "lookup_codes_checked": 0x10000,
            "decoder_address": hex(DECODE), "decoder_codes_checked": len(codes),
            "mismatches": 0}


def main():
    report = verify_font((FONT_ROOT / "sysfont.ffu").read_bytes())
    (OUT / "eboot_verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
