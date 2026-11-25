import hashlib, json, os, shutil, subprocess, sys, bz2, gzip, lzma, zipfile
from pathlib import Path
import pytest
import py7zr

sys.path.insert(0, str(Path(__file__).parent))
from fixtures import make_glb, make_png, make_mp4, zip_bytes, tar_bytes

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(__file__).parent / "data"


def run(tmp_path, inputs, *args, expect_rc=0):
    out = tmp_path / "out"
    cmd = [sys.executable, "-m", "hero_extract", *map(str, inputs), "-o", str(out), *args]
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    assert p.returncode == expect_rc, p.stdout + p.stderr
    return out, json.loads((out / "report.json").read_text(encoding="utf-8")), p


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


@pytest.fixture
def pack(tmp_path):
    deep_tgz = tar_bytes({"Character_Knight.glb": make_glb(["Knight"]), "unlabeled.glb": make_glb(["OakTree_Big"])}, mode="w:gz")
    seven = tmp_path / "inner.7z"
    (tmp_path / "s").mkdir()
    (tmp_path / "s/Rock_A.glb").write_bytes(make_glb(["Rock"]))
    (tmp_path / "s/deep.tar.gz").write_bytes(deep_tgz)
    with py7zr.SevenZipFile(seven, "w") as z:
        z.write(tmp_path / "s/Rock_A.glb", "rocks/Rock_A.glb")
        z.write(tmp_path / "s/deep.tar.gz", "deep.tar.gz")
    full = zip_bytes({
        "models/Pine_Tree.glb": make_glb(["Pine"]),
        "models/street_lamp.glb": make_glb(["Lamp"]),
        "models/house_01.glb": make_glb(["House"]),
        "models/broken_rock.glb": make_glb(["Rock"], truncate=20),
        "models/copy_of_house.glb": make_glb(["House"]),
        "art/hero.png": make_png(), "art/clip.mp4": make_mp4(), "art/cut.mp4": make_mp4(truncate_moov=True),
        "inner.7z": seven.read_bytes(),
        "report.docx": zip_bytes({"[Content_Types].xml": "<x/>", "word/document.xml": "<d/>"}),
        "notes.txt": b"hello",
        "../../evil.txt": b"x",
    })
    p = tmp_path / "in" / "pack.zip"; p.parent.mkdir(); p.write_bytes(full)
    return p


def test_full_extract_nested_and_originals_untouched(tmp_path, pack):
    before = sha(pack)
    out, rep, _ = run(tmp_path, [pack])
    assert sha(pack) == before and rep["originals_unchanged"] is True
    outs = {r["output"] for r in rep["files"]}
    assert "models_3d/glb/Rock_A.glb" in outs                  # zip > 7z
    assert "models_3d/glb/Character_Knight.glb" in outs        # zip > 7z > tar.gz
    assert "documents/docx/report.docx" in outs                # container not unpacked
    assert (out / "images/png/hero.png").is_file()
    assert not any("evil" in str(p) and out not in p.parents for p in tmp_path.rglob("evil.txt"))
    assert not (tmp_path / "evil.txt").exists() and not (tmp_path.parent / "evil.txt").exists()
    assert rep["counts"]["duplicates"] == 1                      # copy_of_house.glb


def test_corrupt_files_flagged_and_quarantined(tmp_path, pack):
    out, rep, _ = run(tmp_path, [pack])
    bad = {r["name"]: r for r in rep["files"] if r["status"] == "corrupt"}
    assert "broken_rock.glb" in bad and bad["broken_rock.glb"]["output"].startswith("_needs_review/")
    assert "cut.mp4" in bad
    good = {r["name"]: r for r in rep["files"] if r["status"] == "ok"}
    assert "hero.png" in good and "clip.mp4" in good and "Pine_Tree.glb" in good
    glb = good["Pine_Tree.glb"]["meta"]
    assert glb["triangles"] == 1 and glb["meshes"] == 1


def test_type_and_keyword_filters_incl_content_match(tmp_path, pack):
    out, rep, _ = run(tmp_path, [pack], "--type", "glb", "--match", "trees=tree|oak,houses=house")
    outs = sorted(r["output"] for r in rep["files"])
    assert "trees/glb/Pine_Tree.glb" in outs
    assert "trees/glb/unlabeled.glb" in outs                    # matched by internal node name OakTree_Big
    assert "houses/glb/house_01.glb" in outs
    assert not any("street_lamp" in o or "hero.png" in o for o in outs)   # 'street' must not match 'tree'


def test_no_content_match_flag(tmp_path, pack):
    out, rep, _ = run(tmp_path, [pack], "--type", "glb", "--match", "trees=tree|oak", "--no-content-match")
    assert not any(r["name"] == "unlabeled.glb" for r in rep["files"])


def test_list_only_writes_nothing_but_reports(tmp_path, pack):
    out, rep, _ = run(tmp_path, [pack], "--list-only")
    assert rep["list_only"] and rep["counts"]["extracted"] >= 5
    assert not (out / "models_3d").exists()
    assert (out / "REPORT.md").is_file() and (out / "inventory.csv").is_file()


def test_truncated_zip_does_not_crash(tmp_path):
    full = zip_bytes({"a.bin": os.urandom(300000), "b.bin": os.urandom(300000)}, compress=zipfile.ZIP_STORED)
    p = tmp_path / "in" / "t.zip"; p.parent.mkdir(); p.write_bytes(full[: len(full) // 2])
    out, rep, _ = run(tmp_path, [p])
    # central directory is gone, but the complete first entry is salvaged and the cut-off one is reported
    assert any(r["name"] == "a.bin" and r["status"] in ("ok", "unchecked") for r in rep["files"])
    assert rep["counts"]["corrupt_members"] >= 1
    assert sha(p) == rep["inputs"][0]["sha256"]


def test_nested_unreadable_archive_is_kept(tmp_path):
    outer = zip_bytes({"junk.zip": b"PK\x03\x04" + os.urandom(50), "ok.txt": b"hi"})
    p = tmp_path / "in" / "o.zip"; p.parent.mkdir(); p.write_bytes(outer)
    out, rep, _ = run(tmp_path, [p])
    assert (out / "_unreadable_archives/junk.zip").is_file()
    assert any(r["name"] == "ok.txt" for r in rep["files"])


def test_corrupt_member_crc(tmp_path):
    data = bytearray(zip_bytes({"ok.txt": b"fine", "bad.bin": b"A" * 1000}, compress=zipfile.ZIP_STORED))
    i = data.find(b"A" * 1000); data[i + 500] ^= 0xFF
    p = tmp_path / "in" / "c.zip"; p.parent.mkdir(); p.write_bytes(bytes(data))
    out, rep, _ = run(tmp_path, [p])
    assert rep["counts"]["corrupt_members"] == 1
    assert any(r["name"] == "ok.txt" for r in rep["files"])


@pytest.mark.parametrize("name,payload", [
    ("a.gz", lambda d: gzip.compress(d)), ("a.bz2", lambda d: bz2.compress(d)), ("a.xz", lambda d: lzma.compress(d))])
def test_single_compressors(tmp_path, name, payload):
    p = tmp_path / "in" / name; p.parent.mkdir(); p.write_bytes(payload(make_glb(["Tree"])))
    out, rep, _ = run(tmp_path, [p])
    assert rep["files"][0]["status"] == "ok" and rep["files"][0]["ext"] == "" or rep["counts"]["extracted"] == 1


@pytest.mark.parametrize("mode,suffix", [("w:gz", "tar.gz"), ("w:bz2", "tar.bz2"), ("w:xz", "tar.xz"), ("w", "tar")])
def test_tar_family(tmp_path, mode, suffix):
    p = tmp_path / "in" / f"x.{suffix}"; p.parent.mkdir(); p.write_bytes(tar_bytes({"d/Tree.glb": make_glb(["Tree"])}, mode=mode))
    out, rep, _ = run(tmp_path, [p])
    assert (out / "models_3d/glb/Tree.glb").is_file()


def test_encrypted_zip_reported(tmp_path):
    if not shutil.which("7z"): pytest.skip("7z CLI missing")
    src = tmp_path / "s.txt"; src.write_text("secret")
    p = tmp_path / "in" / "e.zip"; p.parent.mkdir()
    subprocess.run(["7z", "a", "-tzip", "-pPASS", str(p), str(src)], check=True, capture_output=True)
    out, rep, _ = run(tmp_path, [p])
    assert rep["counts"]["encrypted"] >= 1 and rep["counts"]["extracted"] == 0


needs_unrar = pytest.mark.skipif(not shutil.which("unrar"), reason="unrar not installed")


@needs_unrar
def test_rar5_and_rar4_real_files(tmp_path):
    for f in ("rar5-solid.rar", "rar3-solid.rar"):
        out, rep, _ = run(tmp_path / f.replace(".rar", ""), [DATA / f]) if False else (None, None, None)
    for f in ("rar5-solid.rar", "rar3-solid.rar", "rar3-subdirs.rar"):
        d = tmp_path / f; d.mkdir()
        out, rep, _ = run(d, [DATA / f])
        assert rep["counts"]["extracted"] >= 1 and rep["counts"]["corrupt_members"] == 0, f
        assert all(r["status"] != "corrupt" for r in rep["files"])
    d = tmp_path / "sub2"; d.mkdir()
    out, rep, _ = run(d, [DATA / "rar3-subdirs.rar"], "--layout", "source")
    assert any(str(p).endswith("üȵĩöḋè/file.txt") or "üȵĩöḋè" in str(p) for p in out.rglob("*.txt"))


@needs_unrar
def test_rar_password_reported(tmp_path):
    out, rep, _ = run(tmp_path, [DATA / "rar5-psw.rar"])
    assert rep["counts"]["encrypted"] >= 1
