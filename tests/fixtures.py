"""Builds real test files: valid/broken GLB, PNG, MP4, and nested archives."""
import gzip, io, json, struct, tarfile, zipfile, zlib, bz2, lzma
from pathlib import Path


def make_glb(names=("Tree",), tris=12, truncate=0) -> bytes:
    nodes = [{"name": n, "mesh": i} for i, n in enumerate(names)]
    meshes = [{"name": n + "_mesh", "primitives": [{"attributes": {"POSITION": 0}, "indices": 1}]} for n in names]
    binary = struct.pack("<9f", 0, 0, 0, 1, 0, 0, 0, 1, 0) + struct.pack("<3H", 0, 1, 2) + b"\0\0"
    j = {"asset": {"version": "2.0"}, "scene": 0, "scenes": [{"nodes": list(range(len(nodes)))}], "nodes": nodes, "meshes": meshes,
         "materials": [{"name": "Bark"}], "buffers": [{"byteLength": len(binary)}],
         "bufferViews": [{"buffer": 0, "byteOffset": 0, "byteLength": 36}, {"buffer": 0, "byteOffset": 36, "byteLength": 6}],
         "accessors": [{"bufferView": 0, "componentType": 5126, "count": 3, "type": "VEC3"},
                       {"bufferView": 1, "componentType": 5123, "count": 3, "type": "SCALAR"}]}
    js = json.dumps(j).encode(); js += b" " * ((4 - len(js) % 4) % 4)
    body = struct.pack("<I4s", len(js), b"JSON") + js + struct.pack("<I4s", len(binary), b"BIN\0") + binary
    data = b"glTF" + struct.pack("<II", 2, 12 + len(body)) + body
    return data[:-truncate] if truncate else data


def make_png(w=4, h=4) -> bytes:
    def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    raw = b"".join(b"\0" + b"\x10\x20\x30" * w for _ in range(h))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def make_mp4(truncate_moov=False) -> bytes:
    ftyp = struct.pack(">I4s", 24, b"ftyp") + b"isom\0\0\2\0isomiso2"
    mvhd = struct.pack(">I4sB3xIIII", 28 + 4, b"mvhd", 0, 0, 0, 1000, 5000) + b"\0" * 80
    moov = struct.pack(">I4s", 8 + len(mvhd), b"moov") + mvhd
    mdat = struct.pack(">I4s", 8 + 100, b"mdat") + b"\0" * 100
    d = ftyp + mdat + moov
    return d[:-30] if truncate_moov else d


def zip_bytes(items: dict, compress=zipfile.ZIP_DEFLATED) -> bytes:
    bo = io.BytesIO()
    with zipfile.ZipFile(bo, "w", compress) as z:
        for n, d in items.items(): z.writestr(n, d)
    return bo.getvalue()


def tar_bytes(items: dict, mode="w") -> bytes:
    bo = io.BytesIO()
    with tarfile.open(fileobj=bo, mode=mode) as t:
        for n, d in items.items():
            ti = tarfile.TarInfo(n); ti.size = len(d); t.addfile(ti, io.BytesIO(d))
    return bo.getvalue()
