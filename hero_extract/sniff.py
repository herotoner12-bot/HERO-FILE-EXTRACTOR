"""Magic-byte detection and extension -> category tables."""
from __future__ import annotations

IMAGE = {"png", "jpg", "jpeg", "gif", "webp", "bmp", "tga", "tif", "tiff", "svg", "ico", "dds", "hdr", "exr"}
VIDEO = {"mp4", "m4v", "mov", "mkv", "webm", "avi", "3gp", "wmv", "flv"}
AUDIO = {"mp3", "wav", "ogg", "oga", "opus", "flac", "m4a", "aac", "wma", "mid", "midi"}
MODEL3D = {"glb", "gltf", "obj", "stl", "fbx", "ply", "dae", "blend", "3ds", "3mf", "usdz", "usd", "usda", "usdc", "vrm", "x3d", "off", "abc"}
DOCUMENT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "txt", "md", "csv", "tsv",
            "json", "xml", "html", "htm", "epub", "yml", "yaml", "ini", "log"}
ARCHIVE = {"zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "tbz", "tbz2", "xz", "txz", "cbz", "cbr",
           "mcpack", "mcaddon", "mcworld", "mctemplate", "unitypackage"}

# ZIP-based formats that are *documents/apps*, never unpacked as nested archives unless asked.
OPAQUE_CONTAINERS = {"docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "apk", "aab", "jar", "war", "xpi", "vsix", "usdz", "3mf", "vrm"}

CATEGORY_NAMES = {
    "images": IMAGE, "video": VIDEO, "audio": AUDIO, "models3d": MODEL3D,
    "documents": DOCUMENT, "archives": ARCHIVE,
}
# folder names used in the output tree
CATEGORY_FOLDER = {
    "images": "images", "video": "video", "audio": "audio", "models3d": "models_3d",
    "documents": "documents", "archives": "archives", "other": "other",
}


def ext_of(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


def category_of(name: str) -> str:
    e = ext_of(name)
    for cat, exts in CATEGORY_NAMES.items():
        if e in exts:
            return cat
    return "other"


def detect_archive(head: bytes) -> str | None:
    """Return archive format from the first >=560 bytes, or None."""
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[:8] == b"Rar!\x1a\x07\x01\x00":
        return "rar5"
    if head[:7] == b"Rar!\x1a\x07\x00":
        return "rar"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:2] == b"\x1f\x8b":
        return "gz"
    if head[:3] == b"BZh":
        return "bz2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    return None


def detect_media(head: bytes) -> str | None:
    """Best-effort real type of a non-archive file from its header (used for mismatch warnings)."""
    h = head
    if h[:8] == b"\x89PNG\r\n\x1a\n": return "png"
    if h[:3] == b"\xff\xd8\xff": return "jpg"
    if h[:4] == b"GIF8": return "gif"
    if h[:4] == b"RIFF" and h[8:12] == b"WEBP": return "webp"
    if h[:4] == b"RIFF" and h[8:12] == b"WAVE": return "wav"
    if h[:4] == b"RIFF" and h[8:12] == b"AVI ": return "avi"
    if h[:2] == b"BM": return "bmp"
    if h[:4] == b"glTF": return "glb"
    if h[:4] == b"%PDF": return "pdf"
    if h[:4] == b"OggS": return "ogg"
    if h[:4] == b"fLaC": return "flac"
    if h[:4] == b"\x1a\x45\xdf\xa3": return "mkv"
    if h[4:8] == b"ftyp": return "mp4"
    if h[:3] == b"ID3" or h[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"): return "mp3"
    if h[:7] == b"BLENDER": return "blend"
    if h[:18] == b"Kaydara FBX Binary": return "fbx"
    if h[:3] == b"ply": return "ply"
    if h[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": return "ole"
    return None
