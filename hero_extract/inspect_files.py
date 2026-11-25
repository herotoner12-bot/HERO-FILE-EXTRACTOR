"""Structural inspection of files. Checks real structure (chunks, CRCs, box sizes, JSON),
but does NOT decode pixels/audio/video frames. Every result states what was checked."""
from __future__ import annotations

import json
import os
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass, field

from .sniff import ext_of, detect_media

MAX_JSON_BYTES = 256 * 1024 * 1024


@dataclass
class Result:
    status: str = "unchecked"          # ok | suspicious | corrupt | unchecked
    detected: str | None = None        # real type by header
    issues: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    names: list = field(default_factory=list)   # internal names (nodes/meshes/materials/objects)

    def bad(self, msg):
        self.issues.append(msg); self.status = "corrupt"

    def warn(self, msg):
        self.issues.append(msg)
        if self.status != "corrupt": self.status = "suspicious"


def _read(path, n, off=0):
    with open(path, "rb") as f:
        f.seek(off); return f.read(n)


# ---------- images ----------
def _png(path, size, r: Result):
    with open(path, "rb") as f:
        if f.read(8) != b"\x89PNG\r\n\x1a\n": return r.bad("ترويسة PNG خاطئة")
        first = True; seen_end = False
        while True:
            hdr = f.read(8)
            if not hdr: break
            if len(hdr) < 8: return r.bad("PNG مبتور")
            ln, typ = struct.unpack(">I4s", hdr)
            if first:
                if typ != b"IHDR" or ln != 13: return r.bad("PNG بلا IHDR صحيح")
                data = f.read(13); crc = f.read(4)
                if len(data) < 13 or len(crc) < 4: return r.bad("PNG مبتور")
                if zlib.crc32(typ + data) != struct.unpack(">I", crc)[0]: return r.bad("CRC خاطئ في IHDR")
                r.meta["width"], r.meta["height"] = struct.unpack(">II", data[:8]); first = False; continue
            crc_calc = zlib.crc32(typ); remaining = ln
            while remaining:
                chunk = f.read(min(remaining, 1 << 20))
                if not chunk: return r.bad("PNG مبتور داخل مقطع " + typ.decode("latin1"))
                crc_calc = zlib.crc32(chunk, crc_calc); remaining -= len(chunk)
            crc = f.read(4)
            if len(crc) < 4: return r.bad("PNG مبتور")
            if crc_calc != struct.unpack(">I", crc)[0]: return r.bad("CRC خاطئ في مقطع " + typ.decode("latin1"))
            if typ == b"IEND": seen_end = True; break
        if not seen_end: r.bad("PNG بلا IEND (مبتور)")
        elif f.read(1): r.warn("بيانات زائدة بعد IEND")


def _jpeg(path, size, r: Result):
    with open(path, "rb") as f:
        if f.read(2) != b"\xff\xd8": return r.bad("ترويسة JPEG خاطئة")
        data = f.read(1 << 20)
    i = 0; got = False
    while i + 4 <= len(data):
        if data[i] != 0xFF: i += 1; continue
        m = data[i + 1]
        if m in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            r.meta["height"], r.meta["width"] = struct.unpack(">HH", data[i + 5:i + 9]); got = True; break
        if m == 0xDA: break
        if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7 or m == 0xFF: i += 2 if m != 0xFF else 1; continue
        i += 2 + struct.unpack(">H", data[i + 2:i + 4])[0]
    if not got: r.warn("لم يُعثر على أبعاد JPEG")
    tail = _read(path, 4096, max(0, size - 4096)).rstrip(b"\x00")
    if not tail.endswith(b"\xff\xd9"): r.bad("JPEG بلا علامة النهاية EOI (مبتور)")


def _gif(path, size, r: Result):
    h = _read(path, 10)
    if h[:3] != b"GIF": return r.bad("ترويسة GIF خاطئة")
    r.meta["width"], r.meta["height"] = struct.unpack("<HH", h[6:10])
    if _read(path, 1, size - 1) != b"\x3b": r.bad("GIF بلا علامة النهاية (مبتور)")


def _webp(path, size, r: Result):
    h = _read(path, 30)
    if h[:4] != b"RIFF" or h[8:12] != b"WEBP": return r.bad("ترويسة WEBP خاطئة")
    declared = struct.unpack("<I", h[4:8])[0] + 8
    if declared > size: r.bad(f"WEBP مبتور (المعلن {declared} > الفعلي {size})")
    elif declared < size: r.warn("بيانات زائدة بعد نهاية WEBP")
    if h[12:16] == b"VP8X": r.meta["width"] = int.from_bytes(h[24:27], "little") + 1; r.meta["height"] = int.from_bytes(h[27:30], "little") + 1


def _bmp(path, size, r: Result):
    h = _read(path, 26)
    if h[:2] != b"BM": return r.bad("ترويسة BMP خاطئة")
    declared = struct.unpack("<I", h[2:6])[0]
    if declared > size: r.bad("BMP مبتور")
    r.meta["width"], r.meta["height"] = struct.unpack("<ii", h[18:26])


# ---------- ISO BMFF (mp4/mov/m4a/3gp) ----------
def _bmff(path, size, r: Result):
    pos = 0; boxes = []
    with open(path, "rb") as f:
        while pos < size:
            f.seek(pos); h = f.read(16)
            if len(h) < 8: r.bad("نهاية مبتورة في بنية MP4"); break
            ln, typ = struct.unpack(">I4s", h[:8]); hdr = 8
            if ln == 1: ln = struct.unpack(">Q", h[8:16])[0]; hdr = 16
            elif ln == 0: ln = size - pos
            if ln < hdr: r.bad("حجم صندوق غير صالح في MP4"); break
            boxes.append(typ.decode("latin1"))
            if pos + ln > size:
                r.bad(f"صندوق {typ.decode('latin1')} يتجاوز نهاية الملف (الملف مبتور)"); break
            if typ == b"moov":
                f.seek(pos + hdr); inner = f.read(min(ln - hdr, 1 << 16))
                k = inner.find(b"mvhd")
                if k >= 0:
                    v = inner[k + 4]
                    try:
                        if v == 0: ts, du = struct.unpack(">II", inner[k + 16:k + 24])
                        else: ts, du = struct.unpack(">IQ", inner[k + 24:k + 36])
                        if ts: r.meta["duration_s"] = round(du / ts, 2)
                    except struct.error: pass
            pos += ln
    r.meta["boxes"] = boxes[:12]
    if "ftyp" not in boxes: r.warn("لا يوجد صندوق ftyp")
    if "moov" not in boxes and r.status != "corrupt": r.bad("لا يوجد صندوق moov (الفيديو/الصوت غير قابل للتشغيل غالباً)")
    if "mdat" not in boxes and r.status != "corrupt": r.warn("لا يوجد mdat")


def _riff(path, size, r: Result, kind):
    h = _read(path, 12)
    if h[:4] != b"RIFF" or h[8:12] != kind: return r.bad("ترويسة RIFF خاطئة")
    declared = struct.unpack("<I", h[4:8])[0] + 8
    if declared > size: r.bad(f"الملف مبتور (المعلن {declared} > الفعلي {size})")
    if kind == b"WAVE":
        with open(path, "rb") as f:
            f.seek(12); fmt = None; data_len = None
            while f.tell() + 8 <= size:
                ch = f.read(8); cid, cl = struct.unpack("<4sI", ch)
                if cid == b"fmt ":
                    d = f.read(min(cl, 16)); ch_, sr, br = struct.unpack("<HII", d[2:12]); fmt = (ch_, sr, br); f.seek(cl - len(d), 1)
                elif cid == b"data":
                    data_len = cl; break
                else: f.seek(cl + (cl & 1), 1)
        if not fmt: r.bad("WAV بلا fmt")
        else:
            r.meta.update(channels=fmt[0], sample_rate=fmt[1])
            if data_len is None: r.bad("WAV بلا data")
            elif fmt[2]:
                r.meta["duration_s"] = round(min(data_len, size) / fmt[2], 2)


def _flac(path, size, r: Result):
    h = _read(path, 42)
    if h[:4] != b"fLaC": return r.bad("ترويسة FLAC خاطئة")
    v = int.from_bytes(h[18:26], "big"); sr = v >> 44; total = v & ((1 << 36) - 1)
    if sr: r.meta["sample_rate"] = sr
    if sr and total: r.meta["duration_s"] = round(total / sr, 2)


def _ogg(path, size, r: Result):
    if _read(path, 4) != b"OggS": return r.bad("ترويسة OGG خاطئة")
    tail = _read(path, 65536, max(0, size - 65536)); k = tail.rfind(b"OggS")
    if k < 0 or len(tail) < k + 6 or not (tail[k + 5] & 0x04): r.warn("لم تُوجد صفحة النهاية في OGG (قد يكون مبتوراً)")


def _mp3(path, size, r: Result):
    h = _read(path, 10); off = 0
    if h[:3] == b"ID3": off = 10 + ((h[6] & 0x7F) << 21 | (h[7] & 0x7F) << 14 | (h[8] & 0x7F) << 7 | (h[9] & 0x7F))
    f = _read(path, 4096, off); i = f.find(b"\xff")
    ok = False
    while i >= 0 and i + 1 < len(f):
        if f[i + 1] & 0xE0 == 0xE0: ok = True; break
        i = f.find(b"\xff", i + 1)
    if not ok: r.bad("لا توجد إطارات MP3 صالحة")


# ---------- documents ----------
def _pdf(path, size, r: Result):
    if _read(path, 5)[:4] != b"%PDF": return r.bad("ترويسة PDF خاطئة")
    tail = _read(path, 2048, max(0, size - 2048))
    if b"%%EOF" not in tail: r.bad("PDF بلا %%EOF (مبتور)")
    if b"startxref" not in tail: r.warn("PDF بلا startxref")


def _zipdoc(path, size, r: Result, expect=None):
    try:
        with zipfile.ZipFile(path) as z:
            bad = z.testzip()
            if bad: r.bad(f"عنصر تالف داخل الملف: {bad}")
            names = z.namelist()
            if expect and not any(n == expect or n.startswith(expect) for n in names):
                r.warn(f"لا يحتوي على {expect}")
            r.meta["entries"] = len(names)
    except zipfile.BadZipFile as e:
        r.bad(f"ZIP تالف: {e}")
    except Exception as e:
        r.warn(f"تعذر فحص الحاوية: {e}")


def _json(path, size, r: Result):
    if size > MAX_JSON_BYTES: return
    try:
        with open(path, "rb") as f: json.loads(f.read().decode("utf-8-sig"))
    except Exception as e: r.bad(f"JSON غير صالح: {e}")


# ---------- 3D ----------
def _glb_json_stats(j: dict, bin_len: int | None, r: Result):
    names = []
    for key in ("scenes", "nodes", "meshes", "materials", "animations", "skins", "images"):
        for item in j.get(key, []):
            if isinstance(item, dict) and item.get("name"): names.append(str(item["name"]))
    r.names = names[:500]
    r.meta.update(nodes=len(j.get("nodes", [])), meshes=len(j.get("meshes", [])), materials=len(j.get("materials", [])),
                  animations=len(j.get("animations", [])), textures=len(j.get("textures", [])))
    if j.get("extensionsUsed"): r.meta["extensions"] = j["extensionsUsed"][:15]
    acc = j.get("accessors", []); tris = 0; verts = 0
    for m in j.get("meshes", []):
        for p in m.get("primitives", []):
            mode = p.get("mode", 4)
            if "POSITION" in p.get("attributes", {}) and p["attributes"]["POSITION"] < len(acc):
                verts += acc[p["attributes"]["POSITION"]].get("count", 0)
            if mode == 4:
                if "indices" in p and p["indices"] < len(acc): tris += acc[p["indices"]].get("count", 0) // 3
                elif "POSITION" in p.get("attributes", {}) and p["attributes"]["POSITION"] < len(acc):
                    tris += acc[p["attributes"]["POSITION"]].get("count", 0) // 3
    r.meta.update(vertices=verts, triangles=tris)
    if bin_len is not None:
        bvs = j.get("bufferViews", [])
        for i, bv in enumerate(bvs):
            if bv.get("buffer", 0) == 0 and bv.get("byteOffset", 0) + bv.get("byteLength", 0) > bin_len:
                r.bad(f"bufferView {i} يتجاوز حجم BIN (البيانات مبتورة)"); break


def _glb(path, size, r: Result):
    with open(path, "rb") as f:
        h = f.read(12)
        if len(h) < 12 or h[:4] != b"glTF": return r.bad("ترويسة GLB خاطئة")
        ver, total = struct.unpack("<II", h[4:12]); r.meta["version"] = ver
        if ver != 2: r.warn(f"إصدار glTF {ver} غير 2")
        if total > size: r.bad(f"GLB مبتور (المعلن {total} > الفعلي {size})")
        elif total < size: r.warn("بيانات زائدة بعد نهاية GLB")
        pos = 12; j = None; bin_len = None
        while pos + 8 <= min(total, size):
            f.seek(pos); ch = f.read(8); cl, ct = struct.unpack("<I4s", ch)
            if pos + 8 + cl > size: r.bad("مقطع GLB يتجاوز نهاية الملف"); break
            if ct == b"JSON":
                if cl > MAX_JSON_BYTES: r.warn("JSON ضخم لم يُفحص"); break
                try: j = json.loads(f.read(cl).decode("utf-8").rstrip("\x00 "))
                except Exception as e: r.bad(f"JSON داخل GLB غير صالح: {e}"); break
            elif ct == b"BIN\x00": bin_len = cl
            pos += 8 + cl + ((4 - cl % 4) % 4)
        if j is None and r.status != "corrupt": r.bad("GLB بلا مقطع JSON")
        if j is not None and r.status != "corrupt": _glb_json_stats(j, bin_len, r)


def _gltf(path, size, r: Result):
    if size > MAX_JSON_BYTES: return r.warn("glTF ضخم لم يُفحص")
    try:
        with open(path, "rb") as f: j = json.loads(f.read().decode("utf-8-sig"))
    except Exception as e: return r.bad(f"glTF JSON غير صالح: {e}")
    if "asset" not in j: r.warn("glTF بلا حقل asset")
    ext = [x["uri"] for k in ("buffers", "images") for x in j.get(k, []) if isinstance(x, dict) and "uri" in x and not x["uri"].startswith("data:")]
    if ext: r.meta["external_files"] = ext[:20]; r.warn(f"glTF يعتمد على {len(ext)} ملف خارجي (يجب أن تكون بجانبه)")
    _glb_json_stats(j, None, r)


def _obj(path, size, r: Result):
    if size > 512 * 1024 * 1024: return r.warn("OBJ ضخم لم يُفحص")
    v = f = 0; names = []; mtl = []
    with open(path, "rb") as fh:
        for line in fh:
            if line[:2] == b"v ": v += 1
            elif line[:2] == b"f ": f += 1
            elif line[:2] in (b"o ", b"g ") and len(names) < 300: names.append(line[2:].decode("utf-8", "replace").strip())
            elif line[:7] == b"mtllib ": mtl.append(line[7:].decode("utf-8", "replace").strip())
    r.meta.update(vertices=v, faces=f)
    if mtl: r.meta["mtllib"] = mtl[:5]
    r.names = names
    if v == 0 or f == 0: r.bad("OBJ بلا رؤوس أو أوجه")


def _stl(path, size, r: Result):
    h = _read(path, 84)
    if len(h) >= 84:
        n = struct.unpack("<I", h[80:84])[0]
        if 84 + 50 * n == size: r.meta["triangles"] = n; return
    head = _read(path, 512)
    if head[:5].lower() == b"solid":
        tail = _read(path, 512, max(0, size - 512)).lower()
        if b"endsolid" in tail: return
        return r.bad("STL نصي بلا endsolid (مبتور)")
    r.bad("STL ثنائي بحجم لا يطابق عدد المثلثات (مبتور/تالف)")


def _ply(path, size, r: Result):
    head = _read(path, 4096).decode("latin1")
    if not head.startswith("ply"): return r.bad("ترويسة PLY خاطئة")
    if "end_header" not in head: return r.bad("PLY بلا end_header")
    for m in re.finditer(r"element (\w+) (\d+)", head): r.meta[m.group(1)] = int(m.group(2))


def _fbx(path, size, r: Result):
    h = _read(path, 27)
    if h[:18] == b"Kaydara FBX Binary":
        r.meta["version"] = struct.unpack("<I", h[23:27])[0]
    elif h[:5] != b"; FBX": r.bad("ترويسة FBX خاطئة")


def _blend(path, size, r: Result):
    h = _read(path, 12)
    if h[:7] == b"BLENDER": r.meta["version"] = h[9:12].decode("latin1"); return
    if h[:2] == b"\x1f\x8b" or h[:4] == b"\x28\xb5\x2f\xfd": r.warn("ملف blend مضغوط، لم يُفحص داخله"); return
    r.bad("ترويسة BLEND خاطئة")


def _dae(path, size, r: Result):
    if size > 256 * 1024 * 1024: return r.warn("DAE ضخم لم يُفحص")
    import xml.etree.ElementTree as ET
    names = []
    try:
        for _, el in ET.iterparse(path):
            tag = el.tag.rsplit("}", 1)[-1]
            if tag in ("geometry", "node", "material", "visual_scene") and el.get("name") and len(names) < 300: names.append(el.get("name"))
            el.clear()
        r.names = names
    except ET.ParseError as e: r.bad(f"XML غير صالح: {e}")


def _3ds(path, size, r: Result):
    if _read(path, 2) != b"MM": r.bad("ترويسة 3DS خاطئة")


SCANNERS = {
    "png": _png, "jpg": _jpeg, "jpeg": _jpeg, "gif": _gif, "webp": _webp, "bmp": _bmp,
    "mp4": _bmff, "m4v": _bmff, "mov": _bmff, "3gp": _bmff, "m4a": _bmff,
    "avi": lambda p, s, r: _riff(p, s, r, b"AVI "), "wav": lambda p, s, r: _riff(p, s, r, b"WAVE"),
    "flac": _flac, "ogg": _ogg, "oga": _ogg, "opus": _ogg, "mp3": _mp3,
    "mkv": lambda p, s, r: None if _read(p, 4) == b"\x1a\x45\xdf\xa3" else r.bad("ترويسة EBML خاطئة"),
    "webm": lambda p, s, r: None if _read(p, 4) == b"\x1a\x45\xdf\xa3" else r.bad("ترويسة EBML خاطئة"),
    "pdf": _pdf, "json": _json,
    "docx": lambda p, s, r: _zipdoc(p, s, r, "word/"), "xlsx": lambda p, s, r: _zipdoc(p, s, r, "xl/"),
    "pptx": lambda p, s, r: _zipdoc(p, s, r, "ppt/"), "odt": lambda p, s, r: _zipdoc(p, s, r, "mimetype"),
    "ods": lambda p, s, r: _zipdoc(p, s, r, "mimetype"), "odp": lambda p, s, r: _zipdoc(p, s, r, "mimetype"),
    "epub": lambda p, s, r: _zipdoc(p, s, r, "mimetype"), "usdz": _zipdoc, "3mf": _zipdoc,
    "glb": _glb, "vrm": _glb, "gltf": _gltf, "obj": _obj, "stl": _stl, "ply": _ply, "fbx": _fbx, "blend": _blend,
    "dae": _dae, "3ds": _3ds,
    "doc": lambda p, s, r: None if _read(p, 8) == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" else r.bad("ترويسة OLE خاطئة"),
}
SCANNERS["xls"] = SCANNERS["ppt"] = SCANNERS["doc"]

# extensions whose real type may legitimately differ from the header-detected one
_EQUIV = {"jpeg": "jpg", "vrm": "glb", "m4a": "mp4", "mov": "mp4", "m4v": "mp4", "3gp": "mp4", "webm": "mkv", "oga": "ogg", "opus": "ogg",
          "xls": "ole", "ppt": "ole", "doc": "ole"}


def inspect(path: str, name: str) -> Result:
    r = Result()
    try:
        size = os.path.getsize(path)
        e = ext_of(name)
        head = _read(path, 64)
        r.detected = detect_media(head)
        fn = SCANNERS.get(e)
        if size == 0:
            r.warn("الملف فارغ"); return r
        if fn is None:
            r.status = "unchecked"
            return r
        r.status = "ok"
        fn(path, size, r)
        want = _EQUIV.get(e, e)
        if r.detected and e in SCANNERS and want != r.detected and not (want in ("docx", "xlsx", "pptx") and r.detected is None):
            if e not in ("json", "obj", "gltf", "stl", "dae", "pdf") or r.detected:
                r.warn(f"الامتداد .{e} لكن الترويسة تدل على {r.detected}")
        return r
    except Exception as ex:  # a scanner bug must never stop an extraction run
        r.status = "unchecked"; r.issues.append(f"تعذر الفحص: {ex.__class__.__name__}: {ex}")
        return r
