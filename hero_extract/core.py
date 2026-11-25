from __future__ import annotations

import csv
import hashlib
import os
import shutil
import sys
import tempfile
import time
import zlib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import backends as B
from .filters import Filters
from .inspect_files import inspect, Result
from .sniff import (ARCHIVE, CATEGORY_FOLDER, OPAQUE_CONTAINERS, IMAGE, VIDEO, AUDIO, MODEL3D, DOCUMENT,
                    category_of, detect_archive, ext_of)

SEP = " ▸ "
KNOWN_NON_ARCHIVE = IMAGE | VIDEO | AUDIO | MODEL3D | DOCUMENT
CONTENT_NAME_EXTS = {"glb", "gltf", "obj", "dae", "vrm"}
GB = 1024 ** 3


class LimitReached(Exception):
    pass


@dataclass
class Options:
    out_dir: Path
    filters: Filters = field(default_factory=Filters)
    layout: str = "smart"           # smart | category | source | flat
    list_only: bool = False
    max_depth: int = 10
    max_total_bytes: int = 50 * GB   # total bytes ever written to temp + output
    max_member_bytes: int = 20 * GB
    max_entries: int = 2_000_000
    unpack_containers: bool = False
    quarantine: bool = True
    keep_duplicates: bool = False
    work_dir: Path | None = None
    hash_limit_bytes: int = 1 * GB
    min_free_bytes: int = 512 * 1024 * 1024
    batch_bytes: int = 4 * GB
    verbose: bool = False


def safe_rel(raw: str) -> str | None:
    parts = []
    for p in raw.replace("\\", "/").split("/"):
        p = "".join(ch if ord(ch) >= 32 and ch not in '<>:"|?*' else "_" for ch in p).strip().rstrip(".")
        if p in ("", ".", ".."):
            continue
        if len(p.encode("utf-8")) > 150:
            stem, dot, ext = p.rpartition(".")
            p = (stem[:100] + "~" + dot + ext[:10]) if dot else p[:110]
        parts.append(p)
    return "/".join(parts) or None


def sha256_file(path, limit=None) -> str | None:
    if limit is not None and os.path.getsize(path) > limit:
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Extractor:
    def __init__(self, opts: Options):
        self.o = opts
        self.f = opts.filters
        self.work = Path(tempfile.mkdtemp(prefix="hfe_", dir=opts.work_dir))
        self.written = 0
        self.entries = 0
        self.t0 = time.time(); self._last_log = 0.0
        self.archives = []     # dicts: chain, format, status, note
        self.problems = []     # dicts: kind, chain, message
        self.manifest = []     # dicts for extracted/placed files
        self.counts = dict(archives_opened=0, members_seen=0, extracted=0, skipped_filter=0, duplicates=0,
                           corrupt_members=0, corrupt_files=0, suspicious_files=0, unsupported=0, encrypted=0, links_skipped=0)
        self.hash_index: dict[str, str] = {}   # sha256 -> out relative path
        self.aborted: str | None = None
        self.inputs_check = []
        self._tmp_n = 0
        opts.out_dir.mkdir(parents=True, exist_ok=True)
        self.inv_file = open(opts.out_dir / "inventory.csv", "w", newline="", encoding="utf-8-sig")
        self.inv = csv.writer(self.inv_file)
        self.inv.writerow(["path", "size", "category", "ext", "action", "note"])

    # ------------------------------------------------------------ utilities
    def log(self, msg, force=False):
        now = time.time()
        if force or self.o.verbose or now - self._last_log > 5:
            self._last_log = now
            print(f"[{now - self.t0:7.1f}s] {msg}", file=sys.stderr, flush=True)

    def problem(self, kind, chain, msg):
        self.problems.append(dict(kind=kind, path=SEP.join(chain), message=msg))
        self.log(f"{kind}: {SEP.join(chain)} — {msg}", force=True)

    def inventory(self, chain, size, name, action, note=""):
        self.inv.writerow([SEP.join(chain), size, category_of(name), ext_of(name), action, note])

    def tmp_path(self, hint="f") -> Path:
        self._tmp_n += 1
        return self.work / f"{self._tmp_n:06d}_{hint[:20].replace('/', '_')}"

    def check_space(self, need: int):
        free = shutil.disk_usage(self.work).free
        if need + self.o.min_free_bytes > free:
            raise OSError(f"مساحة القرص غير كافية (المطلوب ~{need // 1048576}MB، المتاح {free // 1048576}MB)")

    def account(self, n: int):
        self.written += n
        if self.written > self.o.max_total_bytes:
            raise LimitReached(f"بلغت حد الحجم الإجمالي ({self.o.max_total_bytes // GB}GB). عدّل --max-gb إن لزم")

    # ------------------------------------------------------------ top level
    def run(self, inputs: list[Path]):
        files = []
        out_resolved = self.o.out_dir.resolve()
        for p in inputs:
            if p.is_dir():
                for r, dirs, fs in os.walk(p):
                    dirs.sort()
                    if Path(r).resolve() == out_resolved or out_resolved in Path(r).resolve().parents:
                        dirs[:] = []; continue
                    dirs[:] = [d for d in dirs if d != ".git"]
                    for fn in sorted(fs):
                        files.append((Path(r) / fn, str(Path(r, fn).relative_to(p.parent)).replace(os.sep, "/")))
            elif p.is_file():
                files.append((p, p.name))
            else:
                self.problem("input_missing", [str(p)], "المسار غير موجود")
        for path, disp in files:
            st = path.stat()
            self.inputs_check.append(dict(path=disp, size=st.st_size, mtime_ns=st.st_mtime_ns,
                                          sha256=sha256_file(path, self.o.hash_limit_bytes), real=path))
        for rec in self.inputs_check:
            if self.aborted:
                break
            self.log(f"فحص: {rec['path']} ({rec['size'] / 1048576:.1f} MB)", force=True)
            try:
                self.process_file(rec["real"], rec["path"], [rec["path"]], 0, movable=False)
            except LimitReached as e:
                self.aborted = str(e); self.problem("limit", [rec["path"]], self.aborted)
            except Exception as e:  # never let one input stop the run
                self.problem("internal_error", [rec["path"]], f"{e.__class__.__name__}: {e}")
        self.finish()

    def finish(self):
        for rec in self.inputs_check:
            p = rec["real"]; ok = True; why = ""
            try:
                st = p.stat()
                if st.st_size != rec["size"] or st.st_mtime_ns != rec["mtime_ns"]:
                    ok = False; why = "تغيّر الحجم أو وقت التعديل"
                elif rec["sha256"] and sha256_file(p, self.o.hash_limit_bytes) != rec["sha256"]:
                    ok = False; why = "تغيّرت البصمة"
            except FileNotFoundError:
                ok = False; why = "الملف لم يعد موجوداً"
            rec["unchanged"] = ok; rec["verify_note"] = why
            rec["verified_by"] = "sha256+size+mtime" if rec["sha256"] else "size+mtime فقط (الملف كبير)"
        self.inv_file.close()
        shutil.rmtree(self.work, ignore_errors=True)

    # ------------------------------------------------------------ file dispatch
    def process_file(self, path: Path, name: str, chain: list, depth: int, movable: bool):
        with open(path, "rb") as f:
            head = f.read(600)
        fmt = detect_archive(head)
        ext = ext_of(name)
        if fmt and (ext not in OPAQUE_CONTAINERS or self.o.unpack_containers):
            if depth >= self.o.max_depth:
                self.problem("depth", chain, f"تجاوز أقصى عمق تداخل ({self.o.max_depth})، لم يُفك")
                self.inventory(chain, path.stat().st_size, name, "not_unpacked", "max depth")
                return
            self.process_archive(path, fmt, name, chain, depth)
        else:
            self.handle_leaf(path, name, chain, movable)

    def process_archive(self, path: Path, fmt: str, name: str, chain: list, depth: int):
        info = dict(path=SEP.join(chain), format=fmt, status="ok", note="")
        self.archives.append(info)
        try:
            backend = B.open_backend(str(path), fmt, name)
            self.counts["archives_opened"] += 1
            if backend.stream:
                self._stream_archive(backend, chain, depth)
            else:
                self._batch_archive(backend, chain, depth)
        except LimitReached:
            raise
        except B.Encrypted as e:
            info["status"] = "encrypted"; info["note"] = str(e); self.counts["encrypted"] += 1
            self.problem("encrypted", chain, str(e)); self.inventory(chain, 0, name, "encrypted", str(e))
        except B.Unsupported as e:
            info["status"] = "unsupported"; info["note"] = str(e); self.counts["unsupported"] += 1
            self.problem("unsupported", chain, str(e)); self.inventory(chain, 0, name, "unsupported", str(e))
        except (B.ArchiveError, OSError, EOFError, zlib.error, zipfile.BadZipFile) as e:
            info["status"] = "corrupt"; info["note"] = str(e); self.counts["corrupt_members"] += 1
            self.problem("corrupt_archive", chain, str(e)); self.inventory(chain, 0, name, "corrupt", str(e))
            self._keep_unreadable(path, name, chain)

    def _keep_unreadable(self, path, name, chain):
        """An archive we could not (fully) read is preserved so nothing is lost."""
        if self.o.list_only or not str(path).startswith(str(self.work)):
            return
        try:
            dest = self._unique_dest(Path("_unreadable_archives") / (safe_rel(name.rsplit("/", 1)[-1]) or "archive"))
            (self.o.out_dir / dest).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, self.o.out_dir / dest)
        except OSError as e:
            self.problem("copy_failed", chain, str(e))

    # ------------------------------------------------------------ stream archives
    def _want_level(self, name: str) -> int:
        """2 = wanted by the filters, 1 = unknown extension (peek the header: might be a hidden archive), 0 = skip."""
        if not self.f.any_active:
            return 2
        e = ext_of(name)
        if self.f.type_ok(name) and not self.f.excluded(name):
            return 2
        if e in ARCHIVE:
            return 2
        if e not in KNOWN_NON_ARCHIVE:
            return 1
        return 0

    def _wanted(self, name: str) -> bool:
        return self._want_level(name) > 0

    def _stream_archive(self, backend, chain, depth):
        for m, opener in backend.iter_entries():
            self.entries += 1
            if self.entries > self.o.max_entries:
                raise LimitReached("بلغت الحد الأقصى لعدد العناصر")
            if m.is_dir:
                continue
            rel = safe_rel(m.name)
            mchain = chain + [m.name]
            if rel is None:
                self.problem("unsafe_name", mchain, "اسم غير صالح"); continue
            self.counts["members_seen"] += 1
            if m.is_link or opener is None:
                self.counts["links_skipped"] += 1; self.inventory(mchain, 0, m.name, "skipped", "رابط/ملف خاص"); continue
            if m.encrypted:
                self.counts["encrypted"] += 1; self.problem("encrypted", mchain, "العنصر مشفّر بكلمة مرور")
                self.inventory(mchain, m.size, m.name, "encrypted"); continue
            try:
                level = self._want_level(m.name)
                if level == 0:
                    self.counts["skipped_filter"] += 1; self.inventory(mchain, m.size, m.name, "skipped_filter"); continue
                if m.size > self.o.max_member_bytes:
                    self.problem("too_large", mchain, "أكبر من --max-member-gb"); continue
                src = opener()
                try:
                    head = b""
                    if level == 1:   # unknown extension: only keep it if its header says it is an archive
                        head = src.read(600)
                        if detect_archive(head) is None:
                            self.counts["skipped_filter"] += 1; self.inventory(mchain, m.size, m.name, "skipped_filter", "type"); continue
                    self.check_space(min(m.size, self.o.max_member_bytes))
                    tmp = self.tmp_path(rel.rsplit("/", 1)[-1])
                    try:
                        self._copy_stream(src, tmp, head)
                        self.process_file(tmp, rel, mchain, depth + 1, movable=True)
                    finally:
                        tmp.unlink(missing_ok=True)
                finally:
                    try: src.close()
                    except Exception: pass
            except LimitReached:
                raise
            except B.Unsupported as e:
                self.counts["unsupported"] += 1; self.problem("unsupported", mchain, str(e)); self.inventory(mchain, m.size, m.name, "unsupported", str(e))
            except (B.ArchiveError, zlib.error, EOFError, zipfile.BadZipFile) as e:
                self.counts["corrupt_members"] += 1; self.problem("corrupt_member", mchain, f"بيانات تالفة أو مبتورة: {e}")
                self.inventory(mchain, m.size, m.name, "corrupt", str(e))
            except OSError as e:
                if "مساحة" in str(e) or getattr(e, "errno", 0) == 28:
                    self.problem("no_space", mchain, str(e)); self.inventory(mchain, m.size, m.name, "failed", "no space")
                else:
                    self.counts["corrupt_members"] += 1; self.problem("corrupt_member", mchain, f"خطأ قراءة: {e}")
                    self.inventory(mchain, m.size, m.name, "corrupt", str(e))

    def _copy_stream(self, src, tmp: Path, head: bytes = b""):
        n = len(head)
        try:
            with open(tmp, "wb") as out:
                if head:
                    self.account(len(head)); out.write(head)
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    n += len(chunk)
                    if n > self.o.max_member_bytes:
                        raise B.ArchiveError("العنصر أكبر من الحد المسموح (قد يكون قنبلة ضغط)")
                    self.account(len(chunk))
                    out.write(chunk)
        except BaseException:
            tmp.unlink(missing_ok=True); raise

    # ------------------------------------------------------------ batch archives
    def _batch_archive(self, backend, chain, depth):
        members = backend.list()
        selected = []
        for m in members:
            if m.is_dir:
                continue
            self.entries += 1
            if self.entries > self.o.max_entries:
                raise LimitReached("بلغت الحد الأقصى لعدد العناصر")
            self.counts["members_seen"] += 1
            mchain = chain + [m.name]
            if safe_rel(m.name) is None:
                self.problem("unsafe_name", mchain, "اسم غير صالح"); continue
            if m.is_link:
                self.counts["links_skipped"] += 1; self.inventory(mchain, 0, m.name, "skipped", "رابط"); continue
            if m.encrypted:
                self.counts["encrypted"] += 1; self.problem("encrypted", mchain, "العنصر مشفّر بكلمة مرور")
                self.inventory(mchain, m.size, m.name, "encrypted"); continue
            if not self._wanted(m.name):
                self.counts["skipped_filter"] += 1; self.inventory(mchain, m.size, m.name, "skipped_filter"); continue
            if m.size > self.o.max_member_bytes:
                self.problem("too_large", mchain, "أكبر من --max-member-gb"); continue
            selected.append(m)
        try:
            batch, size = [], 0
            for m in selected + [None]:
                if m is not None:
                    batch.append(m); size += m.size
                    if size < self.o.batch_bytes:
                        continue
                if batch:
                    self._run_batch(backend, batch, chain, depth)
                batch, size = [], 0
        finally:
            if hasattr(backend, "cleanup"):
                backend.cleanup()

    def _run_batch(self, backend, batch, chain, depth):
        dest = Path(tempfile.mkdtemp(prefix="b_", dir=self.work))
        try:
            try:
                self.check_space(sum(m.size for m in batch))
                backend.extract([m.name for m in batch], str(dest))
            except B.Encrypted:
                raise
            except OSError as e:
                self.problem("no_space", chain, str(e)); return
            for m in batch:
                mchain = chain + [m.name]
                p = dest / m.name
                if not p.is_file():
                    cand = dest / (safe_rel(m.name) or "")
                    p = cand if cand.is_file() else p
                if not p.is_file():
                    self.counts["corrupt_members"] += 1; self.problem("corrupt_member", mchain, "لم يُنتج الفك هذا العنصر (تالف أو غير مدعوم)")
                    self.inventory(mchain, m.size, m.name, "failed"); continue
                self.account(p.stat().st_size)
                try:
                    self.process_file(p, safe_rel(m.name) or m.name, mchain, depth + 1, movable=True)
                finally:
                    p.unlink(missing_ok=True)
        finally:
            shutil.rmtree(dest, ignore_errors=True)

    # ------------------------------------------------------------ leaf files
    def handle_leaf(self, path: Path, name: str, chain: list, movable: bool):
        size = path.stat().st_size
        ext = ext_of(name); cat = category_of(name)
        text = SEP.join(chain)
        if self.f.excluded(text):
            self.counts["skipped_filter"] += 1; self.inventory(chain, size, name, "skipped_filter", "exclude"); return
        if not self.f.type_ok(name):
            self.counts["skipped_filter"] += 1; self.inventory(chain, size, name, "skipped_filter", "type"); return
        label = None
        res: Result | None = None
        if self.f.keywords:
            label = self.f.keyword_label(text)
            if label is None and self.f.match_content and ext in CONTENT_NAME_EXTS:
                res = inspect(str(path), name)
                label = self.f.keyword_label(" ".join(res.names)) if res.names else None
            if label is None:
                self.counts["skipped_filter"] += 1; self.inventory(chain, size, name, "skipped_filter", "keyword"); return
        if res is None:
            res = inspect(str(path), name)
        digest = sha256_file(path)
        status = res.status
        if status == "corrupt":
            self.counts["corrupt_files"] += 1
        elif status == "suspicious":
            self.counts["suspicious_files"] += 1
        row = dict(chain=text, name=name.rsplit("/", 1)[-1], size=size, category=cat, ext=ext, keyword=label or "",
                   status=status, issues="; ".join(res.issues), detected=res.detected or "", sha256=digest,
                   meta=res.meta, internal_names=res.names[:30], output="")
        if digest in self.hash_index and not self.o.keep_duplicates:
            self.counts["duplicates"] += 1
            row["output"] = self.hash_index[digest]; row["duplicate"] = True
            self.manifest.append(row); self.inventory(chain, size, name, "duplicate", row["output"]); return
        if self.o.list_only:
            self.inventory(chain, size, name, "would_extract", status); self.manifest.append(row); self.counts["extracted"] += 1; return
        rel = self._dest_rel(name, cat, ext, label, chain)
        if status == "corrupt" and self.o.quarantine:
            rel = Path("_needs_review") / rel
        rel = self._unique_dest(rel)
        target = self.o.out_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if movable:
            try: os.replace(path, target)
            except OSError: shutil.move(str(path), target)
        else:
            self.account(size); shutil.copy2(path, target)
        self.hash_index[digest] = str(rel).replace(os.sep, "/")
        row["output"] = str(rel).replace(os.sep, "/")
        self.counts["extracted"] += 1
        self.manifest.append(row); self.inventory(chain, size, name, "extracted", status)
        self.log(f"✔ {row['output']}")

    def _dest_rel(self, name, cat, ext, label, chain) -> Path:
        base = safe_rel(name.rsplit("/", 1)[-1]) or "file"
        lay = self.o.layout
        if lay == "flat":
            return Path(base)
        if lay == "source":
            parts = [safe_rel(c) or "x" for c in chain[:-1]] + [safe_rel(name) or base]
            return Path(*[p.replace("/", os.sep) for p in parts])
        folder = CATEGORY_FOLDER[cat]
        sub = ext or "noext"
        if lay == "smart" and label:
            return Path(label) / sub / base
        return Path(folder) / sub / base

    def _unique_dest(self, rel: Path) -> Path:
        rel = Path(rel)
        if not (self.o.out_dir / rel).exists():
            return rel
        stem, suf = rel.stem, rel.suffix
        i = 2
        while (self.o.out_dir / rel.with_name(f"{stem}__{i}{suf}")).exists():
            i += 1
        return rel.with_name(f"{stem}__{i}{suf}")
