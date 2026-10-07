"""
SHERLOCK MEDIA FORENSICS
Metadata / EXIF / PDF forensic inspection.
This module does not claim that metadata alone can prove AI generation.
"""

import hashlib
import mimetypes
import os
from datetime import datetime

from PIL import Image, ExifTags

try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None

try:
    import fitz  # PyMuPDF
except Exception:
    fitz = None


AI_SOFTWARE_HINTS = {
    "midjourney", "dall-e", "dall·e", "stable diffusion",
    "comfyui", "automatic1111", "adobe firefly", "firefly",
    "leonardo ai", "ideogram", "bing image creator"
}

EDITING_SOFTWARE_HINTS = {
    "adobe photoshop", "photoshop", "lightroom", "gimp",
    "affinity photo", "canva", "pixlr", "paint.net"
}


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _json_safe(value):
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", "replace")
        except Exception:
            return f"<{len(value)} bytes>"
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    try:
        return str(value)
    except Exception:
        return repr(value)


def _gps_to_decimal(gps):
    def convert(v):
        if isinstance(v, (tuple, list)) and len(v) == 3:
            def part(x):
                if isinstance(x, tuple) and len(x) == 2 and x[1]:
                    return float(x[0]) / float(x[1])
                return float(x)
            return part(v[0]) + part(v[1]) / 60 + part(v[2]) / 3600
        return None

    lat = convert(gps.get(2))
    lon = convert(gps.get(4))
    if lat is None or lon is None:
        return None

    lat_ref = gps.get(1)
    lon_ref = gps.get(3)
    if isinstance(lat_ref, bytes):
        lat_ref = lat_ref.decode("utf-8", "ignore")
    if isinstance(lon_ref, bytes):
        lon_ref = lon_ref.decode("utf-8", "ignore")

    if str(lat_ref).upper() == "S":
        lat = -lat
    if str(lon_ref).upper() == "W":
        lon = -lon

    return {"latitude": round(lat, 6), "longitude": round(lon, 6)}


def _assess_metadata(values):
    joined = " ".join(
        str(v).lower() for v in values if v not in (None, "")
    )

    ai_hits = sorted(
        hint for hint in AI_SOFTWARE_HINTS
        if hint in joined
    )
    edit_hits = sorted(
        hint for hint in EDITING_SOFTWARE_HINTS
        if hint in joined
    )

    if ai_hits:
        return {
            "label": "POTENTIAL AI / AI-ASSISTED CONTENT",
            "level": "SIGNAL",
            "confidence": "LOW",
            "reason": "Metadata contains a software/generator name associated with AI image creation. Metadata can be modified or removed, so this is not proof of AI generation."
        }

    if edit_hits:
        return {
            "label": "POTENTIAL EDITING / PROCESSING",
            "level": "SIGNAL",
            "confidence": "LOW",
            "reason": "Metadata contains an image-editing or design application name. This indicates processing may have occurred, but it does not prove AI editing."
        }

    return {
        "label": "INCONCLUSIVE",
        "level": "NONE",
        "confidence": "N/A",
        "reason": "Metadata alone cannot reliably determine whether an image or document was created or edited by AI."
    }


def analyze_image(path):
    size = os.path.getsize(path)
    sha256 = _sha256(path)

    with Image.open(path) as image:
        exif = image.getexif()
        tags = {}

        for key, value in exif.items():
            name = ExifTags.TAGS.get(key, str(key))
            tags[name] = _json_safe(value)

        gps = {}
        try:
            gps_raw = exif.get_ifd(ExifTags.IFD.GPSInfo) if exif else {}
            for key, value in gps_raw.items():
                gps[ExifTags.GPSTAGS.get(key, str(key))] = _json_safe(value)
        except Exception:
            gps = {}

        metadata_values = list(tags.values()) + list(gps.values())

        return {
            "file_type": "IMAGE",
            "mime_type": mimetypes.guess_type(path)[0] or "application/octet-stream",
            "file_name": os.path.basename(path),
            "file_size_bytes": size,
            "file_size_human": _human_size(size),
            "sha256": sha256,
            "format": image.format,
            "mode": image.mode,
            "width": image.width,
            "height": image.height,
            "aspect_ratio": round(image.width / image.height, 4) if image.height else None,
            "has_exif": bool(tags),
            "exif": tags,
            "gps": gps,
            "gps_decimal": _gps_to_decimal(gps) if gps else None,
            "forensic_assessment": _assess_metadata(metadata_values),
            "notes": [
                "Missing EXIF metadata does not mean an image is AI-generated.",
                "EXIF can be stripped by screenshots, messaging platforms, social media, export tools, or privacy software.",
                "Metadata is supporting forensic evidence, not proof of authenticity."
            ]
        }


def analyze_pdf(path):
    size = os.path.getsize(path)
    sha256 = _sha256(path)

    metadata = {}
    page_count = None
    pdf_version = None
    encrypted = None
    embedded_image_count = None
    font_count = None

    if PdfReader is not None:
        reader = PdfReader(path)
        page_count = len(reader.pages)
        encrypted = bool(reader.is_encrypted)
        raw_meta = reader.metadata or {}
        metadata = {
            str(k).lstrip("/"): _json_safe(v)
            for k, v in raw_meta.items()
        }

        try:
            pdf_version = reader.pdf_header
        except Exception:
            pdf_version = None

    if fitz is not None:
        doc = fitz.open(path)
        embedded_image_count = sum(
            len(page.get_images(full=True))
            for page in doc
        )
        fonts = set()
        for page in doc:
            try:
                for font in page.get_fonts(full=True):
                    fonts.add(font[3])
            except Exception:
                pass
        font_count = len(fonts)
        if page_count is None:
            page_count = doc.page_count
        doc.close()

    assessment = _assess_metadata(metadata.values())

    return {
        "file_type": "PDF",
        "mime_type": "application/pdf",
        "file_name": os.path.basename(path),
        "file_size_bytes": size,
        "file_size_human": _human_size(size),
        "sha256": sha256,
        "page_count": page_count,
        "pdf_version": pdf_version,
        "encrypted": encrypted,
        "creator": metadata.get("Creator"),
        "producer": metadata.get("Producer"),
        "author": metadata.get("Author"),
        "subject": metadata.get("Subject"),
        "title": metadata.get("Title"),
        "creation_date": metadata.get("CreationDate"),
        "modification_date": metadata.get("ModDate"),
        "metadata": metadata,
        "embedded_image_count": embedded_image_count,
        "font_count": font_count,
        "forensic_assessment": assessment,
        "notes": [
            "PDF metadata can be edited or removed and should not be treated as proof of authorship.",
            "Creator/Producer fields can reveal the software pipeline used to generate or process a PDF.",
            "A metadata-only assessment cannot prove that document content was generated by AI."
        ]
    }


def _human_size(size):
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}"
        value /= 1024


def analyze_file(path):
    name = os.path.basename(path).lower()
    mime = mimetypes.guess_type(name)[0] or ""

    if mime.startswith("image/") or name.endswith((".png", ".jpg", ".jpeg", ".webp", ".tif", ".tiff", ".bmp")):
        return analyze_image(path)

    if mime == "application/pdf" or name.endswith(".pdf"):
        return analyze_pdf(path)

    raise ValueError("Unsupported file type. Upload an image or PDF.")
