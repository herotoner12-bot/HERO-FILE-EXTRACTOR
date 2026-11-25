from __future__ import annotations

import csv
import json
import time
from pathlib import Path

from .core import Extractor, SEP

STATUS_AR = {"ok": "سليم", "suspicious": "مشتبه", "corrupt": "تالف", "unchecked": "لم يُفحص"}


def write_reports(ex: Extractor, argv_text: str) -> dict:
    out = ex.o.out_dir
    c = ex.counts
    data = {
        "tool": "HERO FILE EXTRACTOR", "command": argv_text,
        "duration_s": round(time.time() - ex.t0, 1), "list_only": ex.o.list_only,
        "aborted": ex.aborted, "counts": c, "bytes_written_total": ex.written,
        "inputs": [{k: v for k, v in r.items() if k != "real"} for r in ex.inputs_check],
        "originals_unchanged": all(r.get("unchanged", False) for r in ex.inputs_check),
        "archives": ex.archives, "problems": ex.problems, "files": ex.manifest,
    }
    (out / "report.json").write_text(json.dumps(data, ensure_ascii=False, indent=1, default=str), encoding="utf-8")

    with open(out / "manifest.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["output", "status", "category", "ext", "keyword", "size", "sha256", "issues", "source_chain"])
        for r in ex.manifest:
            w.writerow([r["output"], r["status"], r["category"], r["ext"], r["keyword"], r["size"], r["sha256"], r["issues"], r["chain"]])

    L = []
    ok = data["originals_unchanged"]
    L += ["# تقرير HERO FILE EXTRACTOR", ""]
    L += [f"- الأمر: `{argv_text}`", f"- المدة: {data['duration_s']} ثانية" + ("  — **وضع الفحص فقط (لم يُنسخ شيء)**" if ex.o.list_only else "")]
    if ex.aborted:
        L += [f"- ⚠ **توقفت العملية مبكراً:** {ex.aborted}"]
    L += ["", "## الملخص", "",
          f"| البند | العدد |", "|---|---|",
          f"| أرشيفات فُتحت | {c['archives_opened']} |",
          f"| عناصر اطُّلع عليها داخل الأرشيفات | {c['members_seen']} |",
          f"| ملفات {'ستُستخرج' if ex.o.list_only else 'مستخرجة'} | {c['extracted']} |",
          f"| مكررة (محتوى متطابق) | {c['duplicates']} |",
          f"| تم تخطيها بسبب الفلاتر | {c['skipped_filter']} |",
          f"| ملفات تالفة (فحص البنية) | {c['corrupt_files']} |",
          f"| ملفات مشتبه بها | {c['suspicious_files']} |",
          f"| أرشيفات/عناصر تالفة أو مبتورة | {c['corrupt_members']} |",
          f"| غير مدعومة | {c['unsupported']} |",
          f"| مشفّرة بكلمة مرور | {c['encrypted']} |",
          f"| روابط/ملفات خاصة متخطاة | {c['links_skipped']} |", ""]
    L += ["## الملفات الأصلية", ""]
    for r in data["inputs"]:
        mark = "✅ لم تتغير" if r.get("unchanged") else f"❌ {r.get('verify_note')}"
        L.append(f"- `{r['path']}` — {r['size']:,} بايت — {mark} (التحقق: {r.get('verified_by')})")
    L.append("")
    if ex.problems:
        L += ["## المشاكل والأخطاء", ""]
        for p in ex.problems[:300]:
            L.append(f"- **{p['kind']}** — `{p['path']}` — {p['message']}")
        if len(ex.problems) > 300:
            L.append(f"- … و{len(ex.problems) - 300} أخرى في report.json")
        L.append("")
    bad = [r for r in ex.manifest if r["status"] in ("corrupt", "suspicious")]
    if bad:
        L += ["## ملفات مستخرجة لكن بها ملاحظات", ""]
        for r in bad[:300]:
            L.append(f"- [{STATUS_AR[r['status']]}] `{r['output'] or r['name']}` — {r['issues']}")
        L.append("")
    L += ["## الملفات المستخرجة", ""]
    by = {}
    for r in ex.manifest:
        if r.get("duplicate"):
            continue
        top = (r["output"] or r["name"]).split("/")[0]
        by.setdefault(top, []).append(r)
    for top, rows in sorted(by.items()):
        L.append(f"### {top} ({len(rows)})")
        for r in rows[:200]:
            extra = ""
            m = r["meta"]
            if "triangles" in m: extra = f" — {m['triangles']:,} مثلث"
            elif "width" in m: extra = f" — {m['width']}×{m.get('height')}"
            elif "duration_s" in m: extra = f" — {m['duration_s']}ث"
            L.append(f"- `{r['output'] or r['name']}` ({r['size']:,} بايت){extra} ← {r['chain']}")
        if len(rows) > 200:
            L.append(f"- … و{len(rows) - 200} أخرى في manifest.csv")
        L.append("")
    L += ["---", "فحص السلامة يتحقق من **بنية** الملف (ترويسات، أحجام، CRC، JSON داخل GLB، صناديق MP4…) ولا يفك ترميز الصور أو الفيديو أو الصوت بالكامل. "
          "«سليم» لا يعني «ممتاز بصرياً»، و«تالف» تعني خللاً بنيوياً مؤكداً."]
    (out / "REPORT.md").write_text("\n".join(L), encoding="utf-8")
    return data
