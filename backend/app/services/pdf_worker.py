"""
PDF text extraction that can run in an isolated child process (hard timeout + memory cap).
Keep this module dependency-light: it is imported by the spawned child.
"""
import io


class PdfLimitError(Exception):
    pass


def _limit_memory(mb: int):
    try:
        import resource  # Linux/macOS only
        resource.setrlimit(resource.RLIMIT_AS, (mb * 1024 * 1024, mb * 1024 * 1024))
    except Exception:
        pass


def extract_pdf(data: bytes, max_pages: int, max_chars: int, mem_mb: int = 0) -> list:
    """Return [(page_no, text)]. Raises PdfLimitError for policy violations."""
    if mem_mb:
        _limit_memory(mem_mb)
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        try:
            if not reader.decrypt(""):
                raise PdfLimitError("Password-protected PDFs are not supported")
        except Exception:
            raise PdfLimitError("Password-protected PDFs are not supported")
    n = len(reader.pages)
    if n > max_pages:
        raise PdfLimitError(f"PDF has {n} pages; limit is {max_pages}")
    out, total = [], 0
    for i, page in enumerate(reader.pages, start=1):
        txt = page.extract_text() or ""
        total += len(txt)
        if total > max_chars:
            raise PdfLimitError(f"PDF text exceeds {max_chars:,} characters")
        out.append((i, txt))
    return out
