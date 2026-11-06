#!/usr/bin/env python3
"""Extract the stock liuqin partitions UniXNU needs from a Xiaomi full OTA package.

Inputs are read, never written back. The package is a Xiaomi recovery/full OTA zip of the
Xiaomi Pad 6 Pro (liuqin) whose payload.bin carries full (REPLACE*) operations. It may be a
local file or an https URL; for a URL only the zip directory, the payload manifest and the
blobs of the selected partitions are fetched with HTTP range requests.

Outputs (in --out, never committed):
  <partition>.img          vendor_boot, uefi, dtbo by default
  liuqin-cape.dtb          the "Cape SoC" base DTB of vendor_boot, for the boot image
  stock-manifest.json      sizes and sha256 of everything written

  python3 tools/fetch-liuqin-stock.py --package liuqin-ota.zip --out ../liuqin-stock
  python3 tools/fetch-liuqin-stock.py --package https://.../liuqin-ota_full-...zip --out ../liuqin-stock

uefi.img is the stock uefi.elf: give it to uefi-liuqin scripts/import-liuqin-binaries.py.
"""
from __future__ import annotations

import argparse
import bz2
import hashlib
import json
import lzma
import struct
import sys
import urllib.request
import zlib
from pathlib import Path

DEFAULT_PARTITIONS = ["vendor_boot", "uefi", "dtbo"]


class Source:
    def __init__(self, spec: str):
        self.spec = spec
        self.remote = spec.startswith(("http://", "https://"))
        if self.remote:
            req = urllib.request.Request(spec, method="HEAD", headers={"User-Agent": "liuqin-stock-fetch"})
            with urllib.request.urlopen(req, timeout=60) as r:
                self.size = int(r.headers["Content-Length"])
                if r.headers.get("Accept-Ranges", "").lower() != "bytes":
                    raise SystemExit("the server does not advertise byte ranges; download the package and pass the file")
        else:
            self.handle = open(spec, "rb")
            self.handle.seek(0, 2)
            self.size = self.handle.tell()

    def read(self, offset: int, length: int) -> bytes:
        if length <= 0:
            return b""
        if not self.remote:
            self.handle.seek(offset)
            return self.handle.read(length)
        out = bytearray()
        while len(out) < length:
            start = offset + len(out)
            end = min(offset + length, start + (64 << 20)) - 1
            req = urllib.request.Request(self.spec, headers={"Range": f"bytes={start}-{end}", "User-Agent": "liuqin-stock-fetch"})
            with urllib.request.urlopen(req, timeout=300) as r:
                if r.status != 206:
                    raise SystemExit(f"range request returned HTTP {r.status}")
                out += r.read()
        return bytes(out)


def zip_member(src: Source, name: str) -> tuple[int, int]:
    """Offset and size of a stored zip member (payload.bin is stored, not deflated)."""
    tail = src.read(max(0, src.size - 0x10000 - 22), min(src.size, 0x10000 + 22))
    eocd = tail.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise SystemExit("not a zip file")
    cd_size, cd_off = struct.unpack_from("<II", tail, eocd + 12)
    count = struct.unpack_from("<H", tail, eocd + 10)[0]
    z64 = tail.rfind(b"PK\x06\x06")
    if cd_off == 0xFFFFFFFF and z64 >= 0:
        count, cd_size, cd_off = struct.unpack_from("<QQQ", tail, z64 + 32)
    cd = src.read(cd_off, cd_size)
    pos = 0
    for _ in range(count):
        (sig, _, _, flags, method, _, _, _, csize, usize, nlen, xlen, clen, _, _, _, lho) = struct.unpack_from("<IHHHHHHIIIHHHHHII", cd, pos)
        fname = cd[pos + 46:pos + 46 + nlen].decode("utf-8", "replace")
        extra = cd[pos + 46 + nlen:pos + 46 + nlen + xlen]
        if fname == name:
            if method != 0:
                raise SystemExit(f"{name} is compressed in the zip (method {method}); unzip it and pass payload.bin")
            vals = [usize, csize, lho]
            e = 0
            while e + 4 <= len(extra):
                tag, sz = struct.unpack_from("<HH", extra, e)
                if tag == 1:
                    fields = list(struct.unpack_from(f"<{sz // 8}Q", extra, e + 4))
                    for i, v in enumerate(vals):
                        if v == 0xFFFFFFFF and fields:
                            vals[i] = fields.pop(0)
                e += 4 + sz
            usize, csize, lho = vals
            local = src.read(lho, 30)
            lnlen, lxlen = struct.unpack_from("<HH", local, 26)
            return lho + 30 + lnlen + lxlen, usize
        pos += 46 + nlen + xlen + clen
    raise SystemExit(f"{name} not in the package")


# --- minimal protobuf reader for update_engine's DeltaArchiveManifest ---------------------

def varint(buf: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        b = buf[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, pos
        shift += 7


def fields(buf: bytes):
    pos = 0
    while pos < len(buf):
        key, pos = varint(buf, pos)
        num, wire = key >> 3, key & 7
        if wire == 0:
            val, pos = varint(buf, pos)
        elif wire == 2:
            ln, pos = varint(buf, pos)
            val = buf[pos:pos + ln]
            pos += ln
        elif wire == 1:
            val = buf[pos:pos + 8]
            pos += 8
        elif wire == 5:
            val = buf[pos:pos + 4]
            pos += 4
        else:
            raise ValueError(f"protobuf wire type {wire}")
        yield num, val


def parse_manifest(buf: bytes) -> tuple[int, dict]:
    block_size = 4096
    parts = {}
    for num, val in fields(buf):
        if num == 3:
            block_size = val
        elif num == 13:
            name, ops, size = None, [], None
            for pn, pv in fields(val):
                if pn == 1:
                    name = pv.decode()
                elif pn == 8:
                    op = {"type": 0, "offset": 0, "length": 0, "extents": []}
                    for on, ov in fields(pv):
                        if on == 1:
                            op["type"] = ov
                        elif on == 2:
                            op["offset"] = ov
                        elif on == 3:
                            op["length"] = ov
                        elif on == 6:
                            ext = dict(fields(ov))
                            op["extents"].append((ext.get(1, 0), ext.get(2, 0)))
                    ops.append(op)
                elif pn == 7:
                    size = dict(fields(pv)).get(1)
            parts[name] = {"ops": ops, "size": size}
    return block_size, parts


REPLACE, REPLACE_BZ, ZERO, DISCARD, REPLACE_XZ, REPLACE_ZSTD = 0, 1, 6, 7, 8, 14


def decompress(kind: int, data: bytes) -> bytes:
    if kind == REPLACE:
        return data
    if kind == REPLACE_BZ:
        return bz2.decompress(data)
    if kind == REPLACE_XZ:
        return lzma.decompress(data)
    if kind == REPLACE_ZSTD:
        try:
            import zstandard
        except ImportError:
            raise SystemExit("this payload uses zstd: pip install zstandard")
        return zstandard.ZstdDecompressor().decompressobj().decompress(data)
    raise SystemExit(f"operation type {kind} is not a full-image operation; use a full OTA package")


def extract(src: Source, base: int, data_start: int, block: int, part: dict) -> bytes:
    image = bytearray(part["size"] or 0)
    for op in part["ops"]:
        if op["type"] in (ZERO, DISCARD):
            continue
        blob = decompress(op["type"], src.read(base + data_start + op["offset"], op["length"]))
        pos = 0
        for start, count in op["extents"]:
            n = count * block
            end = start * block + n
            if len(image) < end:
                image.extend(bytes(end - len(image)))
            image[start * block:end] = blob[pos:pos + n].ljust(n, b"\0")
            pos += n
    return bytes(image)


# --- vendor_boot v3/v4: the concatenated base DTBs ----------------------------------------

def fdt_prop(dtb: bytes, wanted: str) -> bytes | None:
    """Value of a property of the root node."""
    off_struct, off_strings = struct.unpack_from(">II", dtb, 8)
    pos, depth = off_struct, 0
    while pos < len(dtb):
        tok = struct.unpack_from(">I", dtb, pos)[0]
        pos += 4
        if tok == 1:  # BEGIN_NODE
            end = dtb.index(b"\0", pos)
            pos = (end + 4) & ~3
            depth += 1
        elif tok == 2:
            depth -= 1
            if depth == 0:
                return None
        elif tok == 3:
            ln, nameoff = struct.unpack_from(">II", dtb, pos)
            pos += 8
            name = dtb[off_strings + nameoff:dtb.index(b"\0", off_strings + nameoff)].decode()
            val = dtb[pos:pos + ln]
            pos = (pos + ln + 3) & ~3
            if depth == 1 and name == wanted:
                return val
        elif tok == 9:
            return None
    return None


def cape_dtb(vendor_boot: bytes) -> tuple[bytes, list]:
    if vendor_boot[:8] != b"VNDRBOOT":
        raise SystemExit("vendor_boot.img has no VNDRBOOT header")
    # vendor_boot_img_hdr_v3/v4: magic[8], header_version, page_size, kernel_addr, ramdisk_addr,
    # vendor_ramdisk_size, cmdline[2048], tags_addr, name[16], header_size, dtb_size, dtb_addr.
    version, page, _, _, ramdisk_size = struct.unpack_from("<IIIII", vendor_boot, 8)
    header_size, dtb_size = struct.unpack_from("<II", vendor_boot, 28 + 2048 + 4 + 16)
    dtb_off = -(-header_size // page) * page + -(-ramdisk_size // page) * page
    blob = vendor_boot[dtb_off:dtb_off + dtb_size]
    found, pos = [], 0
    while pos + 8 <= len(blob):
        if blob[pos:pos + 4] != b"\xd0\x0d\xfe\xed":
            break
        size = struct.unpack_from(">I", blob, pos + 4)[0]
        dtb = blob[pos:pos + size]
        model = (fdt_prop(dtb, "model") or b"").rstrip(b"\0").decode(errors="replace")
        msm = fdt_prop(dtb, "qcom,msm-id") or b""
        found.append({"index": len(found), "model": model, "bytes": size,
                      "msm_id": [hex(v) for v in struct.unpack(f">{len(msm) // 4}I", msm)]})
        found[-1]["data"] = dtb
        pos += size
    cape = [d for d in found if d["model"].endswith("Cape SoC")]
    if len(cape) != 1:
        raise SystemExit(f"expected one 'Cape SoC' DTB, found {[d['model'] for d in found]}")
    return cape[0]["data"], [{k: v for k, v in d.items() if k != "data"} for d in found]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--package", required=True, help="full OTA zip (path or https URL), or payload.bin")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--partition", action="append", help=f"partition to extract (default {DEFAULT_PARTITIONS})")
    args = ap.parse_args()
    wanted = args.partition or DEFAULT_PARTITIONS

    src = Source(args.package)
    base = 0
    if src.read(0, 4) != b"CrAU":
        base, _ = zip_member(src, "payload.bin")
    head = src.read(base, 24)
    magic, version, manifest_len, sig_len = struct.unpack(">4sQQI", head)
    if magic != b"CrAU" or version != 2:
        raise SystemExit("payload.bin is not a version 2 update_engine payload")
    manifest = src.read(base + 24, manifest_len)
    block, parts = parse_manifest(manifest)
    data_start = 24 + manifest_len + sig_len
    missing = [p for p in wanted if p not in parts]
    if missing:
        raise SystemExit(f"not in the payload: {missing}; available: {sorted(parts)}")

    args.out.mkdir(parents=True, exist_ok=True)
    record = {"package": args.package, "partitions": {}}
    for name in wanted:
        image = extract(src, base, data_start, block, parts[name])
        (args.out / f"{name}.img").write_bytes(image)
        record["partitions"][name] = {"bytes": len(image), "sha256": hashlib.sha256(image).hexdigest()}
        print(f"{name}.img: {len(image)} bytes")
    if "vendor_boot" in wanted:
        dtb, table = cape_dtb((args.out / "vendor_boot.img").read_bytes())
        (args.out / "liuqin-cape.dtb").write_bytes(dtb)
        record["vendor_boot_dtbs"] = table
        record["liuqin-cape.dtb"] = {"bytes": len(dtb), "sha256": hashlib.sha256(dtb).hexdigest()}
        print(f"liuqin-cape.dtb: {len(dtb)} bytes from {len(table)} base DTBs")
    (args.out / "stock-manifest.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
