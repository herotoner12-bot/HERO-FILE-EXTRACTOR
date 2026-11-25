"""Archive readers. Two shapes:
  * stream backends (zip, tar, gz/bz2/xz): yield (Member, open_fn) one at a time, nothing is staged on disk;
  * batch backends (7z, rar): list() first, then extract(names, dest) for just the wanted members.
Archives are only ever opened for reading."""
from __future__ import annotations

import bz2
import gzip
import lzma
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .sniff import detect_archive


class ArchiveError(Exception):
    """Archive (or member) is damaged / truncated."""

class Unsupported(ArchiveError):
    """Format or compression method cannot be handled."""

class Encrypted(ArchiveError):
    """Needs a password."""


@dataclass
class Member:
    name: str
    size: int = 0
    is_dir: bool = False
    is_link: bool = False
    encrypted: bool = False


def _fix_zip_name(info: zipfile.ZipInfo) -> str:
    n = info.filename
    if info.flag_bits & 0x800:
        return n
    try:  # legacy zips store non-ASCII names in cp437 although they are really UTF-8
        return n.encode("cp437").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return n


# ------------------------------------------------------------------ stream backends
class ZipBackend:
    stream = True

    def __init__(self, path):
        self.path = path

    def iter_entries(self):
        try:
            z = zipfile.ZipFile(self.path)
        except zipfile.BadZipFile as e:
            # central directory missing (typical for interrupted downloads): salvage by scanning local headers
            yield from self._salvage(str(e))
            return
        except NotImplementedError as e:
            raise Unsupported(str(e))
        with z:
            for info in z.infolist():
                is_link = ((info.external_attr >> 16) & 0o170000) == 0o120000
                m = Member(_fix_zip_name(info), info.file_size, info.is_dir(), is_link, bool(info.flag_bits & 1))
                def opener(i=info):
                    try:
                        return z.open(i)
                    except NotImplementedError as e:
                        raise Unsupported(f"طريقة ضغط غير مدعومة: {e}")
                    except (zipfile.BadZipFile, EOFError) as e:
                        raise ArchiveError(str(e))
                yield m, opener


    def _salvage(self, why):
        """Recover files from a damaged zip by walking local file headers. Entries that are cut off raise
        ArchiveError when read, so they are reported as corrupt while earlier complete ones still come out."""
        import struct, zlib
        found = 0
        f = open(self.path, "rb")
        try:
            pos = 0
            size = os.path.getsize(self.path)
            while pos + 30 <= size:
                f.seek(pos)
                h = f.read(30)
                if h[:4] != b"PK\x03\x04":
                    break
                (_, flags, method, _, _, crc, csize, usize, nlen, xlen) = struct.unpack("<HHHHHIIIHH", h[4:30])
                name_b = f.read(nlen)
                name = name_b.decode("utf-8" if flags & 0x800 else "cp437", "replace")
                data_start = pos + 30 + nlen + xlen
                if flags & 1:
                    yield Member(name, usize, False, False, True), None
                    break  # cannot know where the next entry starts without sizes
                if flags & 8 and not csize:
                    if method != 8:
                        break
                    consumed = {}
                    def opener(start=data_start, nm=name, box=consumed):
                        return _DeflateSpan(self.path, start, None, box)
                    yield Member(name, 0), opener
                    if "end" not in consumed:
                        raise ArchiveError(f"ZIP مبتور: {why}")
                    pos = consumed["end"]
                    # skip optional data-descriptor signature + 12/20 bytes
                    f.seek(pos); sig = f.read(4)
                    pos += 16 if sig == b"PK\x07\x08" else 12
                    found += 1
                    continue
                if data_start + csize > size:
                    def bad_opener(): raise ArchiveError("العنصر مبتور (انقطع الملف قبل اكتماله)")
                    yield Member(name, usize), bad_opener
                    break
                if not name.endswith("/"):
                    yield Member(name, usize), (lambda s_=data_start, c_=csize, m_=method, cr=crc: _DeflateSpan(self.path, s_, c_, {}, m_, cr))
                found += 1
                pos = data_start + csize
        finally:
            f.close()
        if not found:
            raise ArchiveError(f"ZIP تالف أو مبتور ولا يمكن إنقاذ شيء منه: {why}")


class _DeflateSpan:
    """File-like reader over one zip entry's raw bytes (stored/deflate), verifying CRC when known."""

    def __init__(self, path, start, csize, box, method=8, crc=None):
        import zlib
        self.f = open(path, "rb"); self.f.seek(start)
        self.left, self.method, self.crc, self.box, self.start = csize, method, crc, box, start
        self.d = zlib.decompressobj(-15) if method == 8 else None
        self.run = 0; self.done = False; self.size = 0
        if method not in (0, 8):
            self.f.close(); raise Unsupported(f"طريقة ضغط {method} غير مدعومة في وضع الإنقاذ")

    def read(self, n=-1):
        import zlib
        if self.done:
            return b""
        raw = self.f.read(1 << 20 if self.left is None else min(1 << 20, self.left))
        if self.left is not None:
            self.left -= len(raw)
        if not raw and not (self.d and self.d.eof):
            raise ArchiveError("العنصر مبتور")
        try:
            out = self.d.decompress(raw) if self.d else raw
        except zlib.error as e:
            raise ArchiveError(f"بيانات ضغط تالفة: {e}")
        self.run = zlib.crc32(out, self.run); self.size += len(out)
        if self.d is not None and self.d.eof:
            self.box["end"] = self.start + (self.f.tell() - self.start) - len(self.d.unused_data)
            self.done = True
        elif self.left == 0:
            self.done = True
        if self.done and self.crc is not None and self.run != self.crc:
            raise ArchiveError("فشل التحقق من CRC")
        return out

    def close(self):
        self.f.close()


class TarBackend:
    stream = True

    def __init__(self, path):
        self.path = path

    def iter_entries(self):
        try:
            tf = tarfile.open(self.path, mode="r|*")
        except tarfile.ReadError as e:
            raise ArchiveError(f"TAR تالف: {e}")
        with tf:
            try:
                for ti in tf:
                    if ti.isdir():
                        yield Member(ti.name, 0, True), None; continue
                    if not ti.isreg():
                        yield Member(ti.name, 0, False, True), None; continue
                    yield Member(ti.name, ti.size), (lambda t=ti: tf.extractfile(t))
            except (tarfile.ReadError, EOFError, OSError, lzma.LZMAError) as e:
                raise ArchiveError(f"TAR مبتور أو تالف: {e}")


class SingleBackend:
    """.gz / .bz2 / .xz holding one file."""
    stream = True
    _open = {"gz": gzip.open, "bz2": bz2.open, "xz": lzma.open}

    def __init__(self, path, fmt, display_name):
        self.path, self.fmt = path, fmt
        base = os.path.basename(display_name)
        for suf in (".gz", ".bz2", ".xz"):
            if base.lower().endswith(suf):
                base = base[: -len(suf)]; break
        self.inner = base or "data"

    def iter_entries(self):
        opener = lambda: self._open[self.fmt](self.path, "rb")
        yield Member(self.inner, 0), opener


def is_tar_inside(path, fmt) -> bool:
    try:
        with SingleBackend._open[fmt](path, "rb") as f:
            return f.read(512)[257:262] == b"ustar"
    except Exception:
        return False


# ------------------------------------------------------------------ batch backends
def _env():
    e = dict(os.environ); e["LC_ALL"] = "C.UTF-8"; return e


class SevenZipBackend:
    stream = False

    def __init__(self, path):
        self.path = path

    def list(self):
        try:
            import py7zr
            with py7zr.SevenZipFile(self.path, "r") as z:
                if z.needs_password():
                    raise Encrypted("أرشيف 7z محمي بكلمة مرور")
                return [Member(i.filename, i.uncompressed or 0, i.is_directory, i.is_symlink) for i in z.list()]
        except Encrypted:
            raise
        except Exception as e:
            cli = self._cli_list()
            if cli is not None:
                return cli
            if "password" in str(e).lower() or "encrypt" in str(e).lower():
                raise Encrypted(str(e))
            raise ArchiveError(f"تعذر قراءة 7z: {e.__class__.__name__}: {e}")

    def _cli(self):
        return shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")

    def _cli_list(self):
        exe = self._cli()
        if not exe:
            return None
        p = subprocess.run([exe, "l", "-slt", "-p", "-y", self.path], capture_output=True, env=_env())
        if p.returncode != 0:
            return None
        out, cur, res = p.stdout.decode("utf-8", "replace"), {}, []
        for line in out.splitlines() + [""]:
            if "=" in line:
                k, v = line.split(" = ", 1) if " = " in line else (line.split("=", 1)[0].strip(), "")
                cur[k.strip()] = v.strip()
            elif cur:
                if "Path" in cur and "Folder" in cur:
                    res.append(Member(cur["Path"], int(cur.get("Size") or 0), cur["Folder"] == "+", False, cur.get("Encrypted") == "+"))
                cur = {}
        return res

    def extract(self, names, dest):
        try:
            import py7zr
            with py7zr.SevenZipFile(self.path, "r") as z:
                z.extract(path=dest, targets=list(names))
            return
        except Exception as e:
            exe = self._cli()
            if not exe:
                raise ArchiveError(f"تعذر فك 7z: {e}")
        lst = Path(dest, ".names.txt"); lst.write_text("\n".join(names), encoding="utf-8")
        p = subprocess.run([exe, "x", "-y", f"-o{dest}", "-p", self.path, f"@{lst}"], capture_output=True, env=_env())
        lst.unlink(missing_ok=True)
        if p.returncode not in (0, 1):
            raise ArchiveError("فشل فك 7z: " + p.stdout.decode("utf-8", "replace")[-300:])


class RarBackend:
    stream = False

    def __init__(self, path):
        self.path = path
        self._staged = None

    def list(self):
        if shutil.which("unrar"):
            p = subprocess.run(["unrar", "lt", "-p-", self.path], capture_output=True, env=_env(), stdin=subprocess.DEVNULL)
            out = p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
            if "encrypted headers" in out or ("Checksum error in the encrypted file" in out):
                raise Encrypted("أسماء الملفات داخل RAR مشفّرة بكلمة مرور")
            members, cur = [], {}
            for line in out.splitlines() + [""]:
                s = line.strip()
                if ":" in s and line.startswith(" ") and s.split(":", 1)[0] in ("Name", "Type", "Size", "Flags"):
                    k, v = s.split(":", 1); cur[k] = v.strip()
                elif not s and "Name" in cur:
                    t = cur.get("Type", "File")
                    members.append(Member(cur["Name"], int(cur.get("Size") or 0), t == "Directory",
                                          "link" in t.lower(), "encrypted" in cur.get("Flags", "")))
                    cur = {}
            if not members and p.returncode != 0:
                raise ArchiveError("تعذر قراءة RAR: " + out.strip()[-300:])
            return members
        return self._stage_all()[0]

    def _stage_all(self):
        if self._staged:
            return self._staged
        tmp = tempfile.mkdtemp(prefix="hfe_rarfb_")
        errs = []
        for tool, cmd in (("unar", ["unar", "-q", "-o", tmp, "-D", self.path]), ("bsdtar", ["bsdtar", "-xf", self.path, "-C", tmp]),
                          ("7z", ["7z", "x", "-y", f"-o{tmp}", self.path])):
            if not shutil.which(cmd[0]):
                continue
            p = subprocess.run(cmd, capture_output=True, env=_env(), stdin=subprocess.DEVNULL)
            files = [f for f in Path(tmp).rglob("*") if f.is_file()]
            if p.returncode == 0 and files:
                members = [Member(str(f.relative_to(tmp)).replace(os.sep, "/"), f.stat().st_size) for f in files]
                self._staged = (members, tmp); return self._staged
            errs.append(tool)
            for f in list(Path(tmp).iterdir()):
                shutil.rmtree(f, ignore_errors=True) if f.is_dir() else f.unlink(missing_ok=True)
        shutil.rmtree(tmp, ignore_errors=True)
        raise Unsupported("لا توجد أداة لفك RAR (ثبّت unrar). جُرّبت: " + (", ".join(errs) or "لا شيء"))

    def extract(self, names, dest):
        if shutil.which("unrar"):
            lst = Path(dest, ".names.txt"); lst.write_text("\n".join(names), encoding="utf-8")
            p = subprocess.run(["unrar", "x", "-idq", "-o+", "-p-", self.path, str(dest) + "/", f"@{lst}"],
                               capture_output=True, env=_env(), stdin=subprocess.DEVNULL)
            lst.unlink(missing_ok=True)
            err = p.stderr.decode("utf-8", "replace") + p.stdout.decode("utf-8", "replace")
            if p.returncode == 11 or "Incorrect password" in err:
                raise Encrypted("RAR محمي بكلمة مرور")
            if p.returncode not in (0, 1) and not any(Path(dest, n).exists() for n in names):
                raise ArchiveError(f"فشل فك RAR (رمز {p.returncode}): {err.strip()[-300:]}")
            return
        members, tmp = self._stage_all()
        for n in names:
            src = Path(tmp, n)
            if src.exists():
                tgt = Path(dest, n); tgt.parent.mkdir(parents=True, exist_ok=True); shutil.move(str(src), str(tgt))

    def cleanup(self):
        if self._staged:
            shutil.rmtree(self._staged[1], ignore_errors=True)


def open_backend(path: str, fmt: str, display_name: str):
    if fmt == "zip": return ZipBackend(path)
    if fmt == "tar": return TarBackend(path)
    if fmt in ("gz", "bz2", "xz"):
        return TarBackend(path) if is_tar_inside(path, fmt) else SingleBackend(path, fmt, display_name)
    if fmt == "7z": return SevenZipBackend(path)
    if fmt in ("rar", "rar5"): return RarBackend(path)
    raise Unsupported(f"صيغة غير مدعومة: {fmt}")
