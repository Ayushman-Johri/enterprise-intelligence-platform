"""File validation, sandboxed text extraction and chunking."""
import csv
import hashlib
import io
import multiprocessing as mp
import os
import re
from dataclasses import dataclass
from typing import Optional

from ..config import Config
from . import pdf_worker


ACTIVE_PDF = re.compile(rb"/(JavaScript|JS|Launch)(?=[\s/<(\[])")


class ValidationError(Exception):
    """User-facing error (message is safe to show)."""


@dataclass
class Segment:
    text: str
    page: Optional[int] = None


def file_ext(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def validate_upload(filename: str, data: bytes) -> str:
    ext = file_ext(filename)
    if ext not in Config.ALLOWED_EXTENSIONS:
        raise ValidationError(f"Unsupported file type '.{ext}'. Allowed: PDF, TXT, MD, CSV")
    if not data:
        raise ValidationError("File is empty")
    if len(data) > Config.MAX_UPLOAD_MB * 1024 * 1024:
        raise ValidationError(f"File exceeds {Config.MAX_UPLOAD_MB} MB limit")
    if ext == "pdf":
        if not data.startswith(b"%PDF"):
            raise ValidationError("File has .pdf extension but is not a valid PDF")
        if Config.REJECT_ACTIVE_PDF and ACTIVE_PDF.search(data):
            # Nothing is ever executed here, but PDFs with active content are rejected as a policy.
            raise ValidationError("PDF contains active content (JavaScript / Launch action) and was rejected")
    else:
        if b"\x00" in data[:8192]:
            raise ValidationError("Text file appears to be binary")
        if data[:2] in (b"MZ", b"PK") or data[:4] == b"\x7fELF":
            raise ValidationError("File content is an executable/archive, not text")
    return ext


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_filename(name: str) -> str:
    name = os.path.basename((name or "file").replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).lstrip(".")
    return name[:150] or "file"


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _extract_pdf(data: bytes) -> list:
    args = (data, Config.MAX_PDF_PAGES, Config.MAX_EXTRACT_CHARS)
    if not Config.PDF_SANDBOX:
        return pdf_worker.extract_pdf(*args)
    # Isolated child process: a malicious/broken PDF can't hang or exhaust the web server.
    ctx = mp.get_context("spawn")
    pool = ctx.Pool(1)
    try:
        return pool.apply_async(pdf_worker.extract_pdf, args + (1536,)).get(timeout=Config.EXTRACT_TIMEOUT_SEC)
    except mp.TimeoutError:
        raise ValidationError(f"PDF parsing exceeded {Config.EXTRACT_TIMEOUT_SEC}s and was stopped")
    finally:
        pool.terminate()
        pool.join()


def extract_segments(path: str, ext: str) -> list:
    with open(path, "rb") as f:
        data = f.read()
    if ext == "pdf":
        try:
            pages = _extract_pdf(data)
        except pdf_worker.PdfLimitError as e:
            raise ValidationError(str(e))
        except ValidationError:
            raise
        except MemoryError:
            raise ValidationError("PDF needs too much memory to parse")
        except Exception:
            raise ValidationError("PDF could not be parsed (corrupt or unsupported)")
        segs = [Segment(clean_text(t), i) for i, t in pages]
        segs = [s for s in segs if s.text]
        if not segs:
            raise ValidationError("No extractable text in PDF (scanned image PDFs need OCR)")
        return segs
    text = _decode(data)
    if len(text) > Config.MAX_EXTRACT_CHARS:
        raise ValidationError(f"Text exceeds {Config.MAX_EXTRACT_CHARS:,} characters")
    if ext == "csv":
        return [Segment(t) for t in csv_to_records(text)]
    return [Segment(clean_text(text))]


def csv_to_records(text: str, rows_per_block: int = 15) -> list:
    """CSV rows -> 'header: value' records so each chunk is self-describing."""
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return []
    header, body = rows[0], rows[1:]
    blocks, cur = [], []
    for r in body:
        rec = "; ".join(f"{h.strip()}: {v.strip()}" for h, v in zip(header, r) if str(v).strip())
        if rec:
            cur.append(rec)
        if len(cur) >= rows_per_block:
            blocks.append("\n".join(cur)); cur = []
    if cur:
        blocks.append("\n".join(cur))
    return blocks or [", ".join(header)]


def clean_text(text: str) -> str:
    text = text.replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def chunk_text(text: str, size: int = None, overlap: int = None) -> list:
    size = size or Config.CHUNK_SIZE
    overlap = overlap or Config.CHUNK_OVERLAP
    text = (text or "").strip()
    if not text:
        return []
    if len(text) <= size:
        return [text]
    units = []
    for para in re.split(r"\n\s*\n", text):
        para = para.strip()
        if not para:
            continue
        if len(para) <= size:
            units.append(para)
        else:
            for s in re.split(r"(?<=[.!?])\s+", para):
                while len(s) > size:
                    units.append(s[:size]); s = s[size - overlap:]
                if s:
                    units.append(s)
    chunks, cur = [], ""
    for u in units:
        if len(cur) + len(u) + 1 <= size:
            cur = f"{cur}\n{u}".strip()
        else:
            if cur:
                chunks.append(cur)
            tail = cur[-overlap:] if overlap and cur else ""
            cur = f"{tail} {u}".strip() if tail else u
    if cur:
        chunks.append(cur)
    return chunks


def chunk_segments(segments: list) -> list:
    out = [Segment(c, seg.page) for seg in segments for c in chunk_text(seg.text)]
    if len(out) > Config.MAX_CHUNKS_PER_DOC:
        raise ValidationError(f"Document produces {len(out)} chunks; limit is {Config.MAX_CHUNKS_PER_DOC}")
    return out
