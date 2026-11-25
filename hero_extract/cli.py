from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .core import Extractor, Options, GB
from .filters import Filters, parse_categories, parse_exts, parse_keywords
from .report import write_reports


def build_parser():
    p = argparse.ArgumentParser(prog="hero_extract", description="HERO FILE EXTRACTOR — فك الأرشيفات المتداخلة وفحص محتواها")
    p.add_argument("inputs", nargs="+", help="ملفات أو مجلدات (تُقرأ فقط ولا تُعدَّل)")
    p.add_argument("-o", "--out", required=True, help="مجلد النتائج (يُنشأ)")
    p.add_argument("--type", help="امتدادات مطلوبة، مثل: glb,gltf")
    p.add_argument("--category", help="فئات: images,video,audio,models3d,documents,archives")
    p.add_argument("--match", help="كلمات مفتاحية: 'trees=tree|pine|palm,houses=house|cottage' (التسمية قبل = اسم المجلد)")
    p.add_argument("--exclude", help="كلمات تُستبعد، مفصولة بفواصل")
    p.add_argument("--no-content-match", action="store_true", help="لا تبحث عن الكلمات داخل أسماء عقد/مجسمات GLB وOBJ")
    p.add_argument("--substring", action="store_true", help="مطابقة نصية خام بدل مطابقة الكلمات الكاملة")
    p.add_argument("--layout", choices=["smart", "category", "source", "flat"], default="smart")
    p.add_argument("--list-only", action="store_true", help="فحص وتقرير فقط، دون نسخ أي ملف إلى مجلد النتائج")
    p.add_argument("--max-depth", type=int, default=10)
    p.add_argument("--max-gb", type=float, default=50, help="الحد الأقصى لإجمالي ما يُكتب (مؤقت + نتائج)")
    p.add_argument("--max-member-gb", type=float, default=20)
    p.add_argument("--unpack-containers", action="store_true", help="فك docx/xlsx/apk/jar… أيضاً")
    p.add_argument("--no-quarantine", action="store_true", help="لا تعزل الملفات التالفة في _needs_review")
    p.add_argument("--keep-duplicates", action="store_true")
    p.add_argument("--work-dir", help="مجلد مؤقت (افتراضي: مؤقت النظام)")
    p.add_argument("--hash-limit-mb", type=int, default=1024, help="أكبر ملف أصلي يُحسب sha256 له للتحقق من عدم تعديله")
    p.add_argument("--fail-on-error", action="store_true", help="رمز خروج 1 إن وُجدت مشاكل")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=__version__)
    return p


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    a = build_parser().parse_args(argv)
    filt = Filters(exts=parse_exts(a.type), categories=parse_categories(a.category), keywords=parse_keywords(a.match),
                   exclude=[t.strip() for t in (a.exclude or "").split(",") if t.strip()],
                   match_content=not a.no_content_match, substring=a.substring)
    opts = Options(out_dir=Path(a.out), filters=filt, layout=a.layout, list_only=a.list_only, max_depth=a.max_depth,
                   max_total_bytes=int(a.max_gb * GB), max_member_bytes=int(a.max_member_gb * GB),
                   unpack_containers=a.unpack_containers, quarantine=not a.no_quarantine, keep_duplicates=a.keep_duplicates,
                   work_dir=Path(a.work_dir) if a.work_dir else None, hash_limit_bytes=a.hash_limit_mb * 1024 * 1024, verbose=a.verbose)
    ex = Extractor(opts)
    ex.run([Path(p) for p in a.inputs])
    data = write_reports(ex, "hero_extract " + " ".join(argv))
    c = data["counts"]
    print(f"\nانتهى: مستخرج={c['extracted']} تالف={c['corrupt_files'] + c['corrupt_members']} غير مدعوم={c['unsupported']} "
          f"مشفّر={c['encrypted']} | الأصول لم تتغير={data['originals_unchanged']} | التقرير: {opts.out_dir / 'REPORT.md'}")
    return 1 if (a.fail_on_error and data["problems"]) or not data["originals_unchanged"] else 0
