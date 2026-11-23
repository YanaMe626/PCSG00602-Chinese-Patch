"""Recover PCSG00602 resources and verify the ELF against the retail SELF."""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import threading
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from Crypto.Cipher import AES

ROOT = Path(__file__).resolve().parents[1]
TITLE = "PCSG00602"
SOURCE = ROOT / "01_游戏文件"
OUTPUT = ROOT / "02_解包资源" / f"{TITLE}_decrypted"
REPORTS = ROOT / "03_文件结构分析" / "ghidra"
SELF_DIGEST_RECORD = bytes.fromhex("627CB1808AB938E32C8C091708726A579E2586E4")


class LocalF00D(BaseHTTPRequestHandler):
    """Loopback adapter for psvpfsparser using Vita3K's native key transform."""

    contract_key: bytes

    def log_message(self, *_):
        pass

    def do_GET(self):
        try:
            key = bytes.fromhex(parse_qs(urlparse(self.path).query)["key"][0])
            if len(key) not in (16, 32):
                raise ValueError("Invalid key length")
        except (KeyError, ValueError):
            self.send_error(400)
            return
        driver_key = AES.new(self.contract_key, AES.MODE_ECB).decrypt(key)
        data = json.dumps({"key": key.hex(), "drv_key": driver_key.hex()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def decrypt_pfs(key):
    contract_key = bytes.fromhex(os.environ.get("NINKOI_PFS_CONTRACT_KEY", ""))
    if len(contract_key) != 16:
        raise ValueError("Set NINKOI_PFS_CONTRACT_KEY to the local PFS tool's 16-byte key in hex")
    parser = ROOT / "tools" / "pfsparser" / "psvpfsparser.exe"
    LocalF00D.contract_key = contract_key
    with ThreadingHTTPServer(("127.0.0.1", 0), LocalF00D) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        args = [str(parser), "-i", str(SOURCE), "-o", str(OUTPUT), "-k", key.hex(),
                "-f", f"http://127.0.0.1:{server.server_port}"]
        try:
            result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    timeout=900)
        finally:
            server.shutdown()
    log = result.stdout.decode("utf-8", "replace")
    log = re.sub(r"(?i)\b[0-9a-f]{32,64}\b", "[redacted]", log)
    (REPORTS / "pfs_decrypt.log").write_text(log, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"PFS parser exited with {result.returncode}")


def main():
    REPORTS.mkdir(parents=True, exist_ok=True)
    rif = (SOURCE / "sce_sys/package/work.bin").read_bytes()
    content_id = rif[0x10:0x40].rstrip(b"\0").decode("ascii")
    if not content_id.startswith(f"JP0031-{TITLE}_"):
        raise ValueError(f"Unexpected game identity {content_id}")
    key = rif[0x50:0x60]
    paths = ["eboot.bin", *(f"data/{name}" for name in ("SYSTEM.cpk", "STORY.cpk", "GAME.cpk"))]
    expected_magic = [b"SCE\0", b"CPK ", b"CPK ", b"CPK "]

    def output_ready():
        for name, magic in zip(paths, expected_magic, strict=True):
            output = OUTPUT / name
            if not output.is_file() or output.stat().st_size != (SOURCE / name).stat().st_size:
                return False
            with output.open("rb") as file:
                if file.read(4) != magic:
                    return False
        return True

    if not output_ready():
        print(f"Decrypting PFS for {content_id}", flush=True)
        decrypt_pfs(key)
    if not output_ready():
        raise ValueError("PFS output is missing or has unexpected headers or lengths")

    sys.path.insert(0, str(ROOT / "tools" / "psvdec"))
    from self2elf import self2elf
    from io import BytesIO

    self_data = (OUTPUT / "eboot.bin").read_bytes()
    dest = BytesIO()
    with (REPORTS / "self_decrypt.log").open("w", encoding="utf-8") as log, redirect_stdout(log):
        self2elf(BytesIO(self_data), dest, key, silent=True)
    elf = dest.getvalue()
    if elf[:6] != b"\x7fELF\x01\x01" or struct.unpack_from("<H", elf, 18)[0] != 40:
        raise ValueError("Expected little-endian ARM ELF32")
    pos = self_data.find(SELF_DIGEST_RECORD)
    digest = hashlib.sha256(elf).digest()
    start = pos + len(SELF_DIGEST_RECORD)
    if pos < 0 or self_data[start:start + 32] != digest:
        raise ValueError("ELF SHA-256 mismatch with the retail SELF")
    elf_path = OUTPUT / f"{TITLE}.elf"
    elf_path.write_bytes(elf)
    report = {"content_id": content_id, "elf_size": len(elf), "elf_sha256": digest.hex(),
              "elf_self_digest_verified": True, "pfs_paths": paths}
    (REPORTS / "decryption_report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Verified {elf_path.name}: {digest.hex()}", flush=True)


if __name__ == "__main__":
    main()
