#!/usr/bin/env python3
"""Generate Binaries/liuqin from the stock liuqin uefi.elf, shaped like Binaries/pong.

The Xiaomi Pad 6 Pro (liuqin) and the Nothing Phone (2) (pong) are both SM8475 boards of
the same Qualcomm BSP generation. liuqinPkg lists its vendor modules with the paths the
Project Silicium Device-Binaries tree uses for pong, Binaries/$(BINARIES_DEVICE)/...; this
tool fills Binaries/liuqin with liuqin's own bytes at those same paths, so switching
BINARIES_DEVICE from pong to liuqin in liuqin.dsc changes no other line.

Every pong INF names its module by FILE_GUID (the FFS GUID of the stock file) and BASE_NAME
(the stock UI name). A liuqin module is matched by FILE_GUID first and by UI name second.
Each FREEFORM file of liuqinPkg/Include/RAW.inc is matched by its FFS GUID.

Vendor bytes are not committed: Binaries/ is a submodule and Binaries/liuqin stays local.

  python3 scripts/import-liuqin-binaries.py --uefi-elf /path/to/uefi.elf
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
import lzma
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FV_SIGNATURE = b"_FVH"
SECTION_COMPRESSION = 0x01
SECTION_GUID_DEFINED = 0x02
SECTION_PE32 = 0x10
SECTION_TE = 0x12
SECTION_DEPEX = 0x13
SECTION_UI = 0x15
SECTION_FV_IMAGE = 0x17
SECTION_RAW = 0x19
FFS_PAD = 0xF0
LZMA_GUID = "EE4E5898-3914-4259-9D6E-DC7BD79403CF"
# Qualcomm's guided section for gzip; the SM8475 uefi.elf of liuqin wraps both of its
# nested firmware volumes in it (payload starts 1f 8b).
GZIP_GUID = "1D301FE9-BE79-4353-91C2-D23BC959AE0C"


def guid_str(raw: bytes) -> str:
    a, b, c = struct.unpack_from("<IHH", raw)
    d = raw[8:16]
    return f"{a:08X}-{b:04X}-{c:04X}-{d[:2].hex().upper()}-{d[2:].hex().upper()}"


def lzma_decompress(data: bytes) -> bytes:
    # EDK II LZMA: 5-byte properties, 8-byte little-endian size, raw stream.
    props, size = data[:5], struct.unpack_from("<Q", data, 5)[0]
    filt = lzma._decode_filter_properties(lzma.FILTER_LZMA1, props)
    out = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[filt]).decompress(data[13:])
    return out[:size] if size != 0xFFFFFFFFFFFFFFFF else out


class Module:
    def __init__(self, guid: str, ffs_type: int):
        self.guid = guid
        self.ffs_type = ffs_type
        self.ui = None
        self.pe32 = None
        self.depex = None
        self.raw = None


def sections(data: bytes, mod: Module, modules: dict) -> None:
    off = 0
    while off + 4 <= len(data):
        size = int.from_bytes(data[off:off + 3], "little")
        stype = data[off + 3]
        hdr = 4
        if size == 0xFFFFFF:
            size = struct.unpack_from("<I", data, off + 4)[0]
            hdr = 8
        if size < hdr or off + size > len(data):
            break
        body = data[off + hdr:off + size]
        if stype == SECTION_PE32 or stype == SECTION_TE:
            mod.pe32 = body
        elif stype == SECTION_DEPEX:
            mod.depex = body
        elif stype == SECTION_UI:
            mod.ui = body.decode("utf-16-le").rstrip("\0")
        elif stype == SECTION_RAW:
            mod.raw = body
        elif stype == SECTION_FV_IMAGE:
            volumes(body, modules)
        elif stype == SECTION_GUID_DEFINED:
            g = guid_str(body[:16])
            data_off = struct.unpack_from("<H", body, 16)[0] - hdr
            payload = body[data_off:]
            if g == LZMA_GUID:
                sections(lzma_decompress(payload), mod, modules)
            elif g == GZIP_GUID:
                sections(zlib.decompress(payload, 31), mod, modules)
            else:
                sections(payload, mod, modules)
        elif stype == SECTION_COMPRESSION:
            ctype = body[4]
            if ctype == 0:
                sections(body[5:], mod, modules)
        off += (size + 3) & ~3


def volumes(blob: bytes, modules: dict) -> None:
    pos = 0
    while True:
        i = blob.find(FV_SIGNATURE, pos)
        if i < 0:
            return
        start = i - 40
        pos = i + 4
        if start < 0:
            continue
        fv_len = struct.unpack_from("<Q", blob, start + 32)[0]
        hdr_len = struct.unpack_from("<H", blob, start + 48)[0]
        if fv_len < hdr_len or start + fv_len > len(blob):
            continue
        fv = blob[start:start + fv_len]
        ext = struct.unpack_from("<H", fv, 52)[0]
        off = hdr_len
        if ext:
            off = ext + struct.unpack_from("<I", fv, ext + 16)[0]
        off = (off + 7) & ~7
        while off + 24 <= len(fv):
            if fv[off:off + 24] == b"\xff" * 24:
                break
            guid = guid_str(fv[off:off + 16])
            ftype = fv[off + 18]
            attrs = fv[off + 19]
            size = int.from_bytes(fv[off + 20:off + 23], "little")
            hdr = 24
            if attrs & 0x01:  # FFS_ATTRIB_LARGE_FILE
                size = struct.unpack_from("<Q", fv, off + 24)[0]
                hdr = 32
            if size < hdr or off + size > len(fv):
                break
            if ftype != FFS_PAD:
                mod = Module(guid, ftype)
                body = fv[off + hdr:off + size]
                if ftype == 0x01:  # EFI_FV_FILETYPE_RAW
                    mod.raw = body
                else:
                    sections(body, mod, modules)
                modules.setdefault(guid, mod)
            off = (off + size + 7) & ~7
        pos = start + fv_len


def parse_inf(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    get = lambda key: (re.search(rf"^\s*{key}\s*=\s*(\S+)", text, re.M) or [None, None])[1]
    bins = re.findall(r"^\s*(PE32|TE|DXE_DEPEX|PEI_DEPEX|RAW)\|([^|\s]+)", text, re.M)
    return {"text": text, "guid": (get("FILE_GUID") or "").upper(), "name": get("BASE_NAME"), "bins": bins}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--uefi-elf", required=True, type=Path, help="stock uefi.elf (uefi_a partition) of liuqin")
    ap.add_argument("--template", type=Path, default=ROOT / "Binaries" / "pong", help="pong Device-Binaries tree")
    ap.add_argument("--out", type=Path, default=ROOT / "Binaries" / "liuqin")
    ap.add_argument("--raw-inc", type=Path, default=ROOT / "Platforms/Xiaomi/liuqinPkg/Include/RAW.inc")
    args = ap.parse_args()

    if not (args.template / "QcomPkg").is_dir():
        print(f"template {args.template} has no QcomPkg: run git submodule update --init Binaries", file=sys.stderr)
        return 2
    modules: dict[str, Module] = {}
    volumes(args.uefi_elf.read_bytes(), modules)
    by_ui = {m.ui: m for m in modules.values() if m.ui}
    print(f"liuqin: {len(modules)} FFS files, {sum(1 for m in modules.values() if m.pe32)} images, "
          f"{sum(1 for m in modules.values() if m.raw)} raw")

    manifest = {"uefi_elf_sha256": hashlib.sha256(args.uefi_elf.read_bytes()).hexdigest(), "modules": [], "raw": [], "missing": []}
    for inf in sorted(args.template.rglob("*.inf")):
        info = parse_inf(inf)
        mod = modules.get(info["guid"]) or by_ui.get(info["name"])
        rel = inf.relative_to(args.template)
        if mod is None or mod.pe32 is None:
            manifest["missing"].append({"inf": str(rel), "guid": info["guid"], "name": info["name"]})
            continue
        dest = args.out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        text = info["text"]
        for kind, name in info["bins"]:
            if kind in ("PE32", "TE"):
                plain = name.replace(".patched.efi", ".efi")
                text = text.replace(f"|{name}|", f"|{plain}|")
                (dest.parent / plain).write_bytes(mod.pe32)
            elif kind.endswith("DEPEX"):
                if mod.depex is not None:
                    (dest.parent / name).write_bytes(mod.depex)
                else:
                    text = re.sub(rf"^\s*{kind}\|{re.escape(name)}[^\n]*\n", "", text, flags=re.M)
        if mod.guid != info["guid"]:
            text = re.sub(r"(FILE_GUID\s*=\s*)\S+", rf"\g<1>{mod.guid}", text)
        dest.write_text(text, encoding="utf-8", newline="\n")
        manifest["modules"].append({"inf": str(rel), "guid": mod.guid, "ui": mod.ui,
                                    "sha256": hashlib.sha256(mod.pe32).hexdigest(),
                                    "matched_by": "guid" if mod.guid == info["guid"] else "name"})

    raw_inc = args.raw_inc.read_text(encoding="utf-8")
    for guid, path in re.findall(r"FILE FREEFORM = (\S+) \{.*?SECTION RAW = Binaries/\$\(BINARIES_DEVICE\)/(\S+)", raw_inc, re.S):
        mod = modules.get(guid.upper())
        if mod is None or mod.raw is None:
            manifest["missing"].append({"raw": path, "guid": guid})
            continue
        dest = args.out / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(mod.raw)
        manifest["raw"].append({"file": path, "guid": guid, "sha256": hashlib.sha256(mod.raw).hexdigest()})

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(manifest['modules'])} modules and {len(manifest['raw'])} raw files to {args.out}")
    for miss in manifest["missing"]:
        print(f"  missing: {miss}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
