"""Asynchronous document processing with duplicate-job prevention and injection scanning."""
import logging
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor

from .. import db
from ..config import Config
from . import documents, embeddings, llm, security

log = logging.getLogger("eip.jobs")
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="docjob")
_active = set()
_active_lock = threading.Lock()


def enqueue(document_id: int) -> dict:
    with _active_lock:
        if document_id in _active:
            return {"queued": False, "reason": "job already running for this document"}
        running = db.query("SELECT id FROM jobs WHERE document_id=? AND status IN ('queued','processing')",
                           (document_id,), one=True)
        if running:
            return {"queued": False, "reason": "job already queued", "job_id": running["id"]}
        _active.add(document_id)
    job_id = db.execute("INSERT INTO jobs (document_id, status) VALUES (?, 'queued')", (document_id,))
    db.execute("UPDATE documents SET status='queued', error=NULL WHERE id=?", (document_id,))
    _executor.submit(_run, job_id, document_id)
    return {"queued": True, "job_id": job_id}


def _run(job_id: int, document_id: int):
    try:
        process_document(job_id, document_id)
    finally:
        with _active_lock:
            _active.discard(document_id)


def recover_stale_jobs():
    db.execute("UPDATE jobs SET status='failed', error='interrupted by restart' WHERE status IN ('queued','processing')")
    db.execute("UPDATE documents SET status='failed', error='interrupted by restart - click Reprocess' "
               "WHERE status IN ('queued','processing')")


def scan_chunk(text: str, user_id: int, guard_budget: list) -> list:
    """Regex/normalization scan first; ML classifier (if enabled) for chunks the regex considers clean."""
    reasons = security.detect_injection(text)
    if not reasons and guard_budget[0] > 0:
        guard_budget[0] -= 1
        score = llm.classify_injection(text, user_id)
        if score is not None and score >= Config.PROMPT_GUARD_THRESHOLD:
            reasons = [f"prompt_guard:{score:.2f}"]
    return reasons


def process_document(job_id: int, document_id: int):
    doc = db.query("SELECT * FROM documents WHERE id=?", (document_id,), one=True)
    if not doc:
        return
    db.execute("UPDATE jobs SET status='processing', attempts=attempts+1 WHERE id=?", (job_id,))
    db.execute("UPDATE documents SET status='processing' WHERE id=?", (document_id,))
    try:
        chunks = documents.chunk_segments(documents.extract_segments(doc["file_path"], doc["file_type"]))
        if not chunks:
            raise documents.ValidationError("Document produced no text chunks")
        vectors = embeddings.embed([c.text for c in chunks])
        budget = [Config.PROMPT_GUARD_MAX_CHUNKS if Config.PROMPT_GUARD_ENABLED else 0]
        flags = 0
        scanned = [scan_chunk(c.text, doc["user_id"], budget) for c in chunks]
        with db.get_conn() as conn:
            conn.execute("DELETE FROM chunks WHERE document_id=?", (document_id,))
            for i, (c, v, reasons) in enumerate(zip(chunks, vectors, scanned)):
                flags += 1 if reasons else 0
                conn.execute("INSERT INTO chunks (document_id, user_id, chunk_index, text, page, embedding, suspicious, "
                             "injection_reasons) VALUES (?,?,?,?,?,?,?,?)",
                             (document_id, doc["user_id"], i, c.text, c.page, embeddings.to_blob(v),
                              1 if reasons else 0, ",".join(reasons)))
            conn.execute("UPDATE documents SET status='ready', num_chunks=?, num_chars=?, injection_flags=?, "
                         "processed_at=datetime('now'), error=NULL WHERE id=?",
                         (len(chunks), sum(len(c.text) for c in chunks), flags, document_id))
            conn.execute("UPDATE jobs SET status='done', finished_at=datetime('now') WHERE id=?", (job_id,))
        db.log_activity(doc["user_id"], "document.processed",
                        {"document_id": document_id, "chunks": len(chunks), "injection_flags": flags,
                         "embeddings": embeddings.backend_name()})
        if flags:
            db.log_activity(doc["user_id"], "security.injection_detected",
                            {"document_id": document_id, "flagged_chunks": flags,
                             "reasons": sorted({r for rs in scanned for r in rs})}, "warning")
    except documents.ValidationError as e:
        _fail(doc, job_id, document_id, str(e))
    except Exception:
        ref = secrets.token_hex(4)
        log.exception("Processing failed for document %s (ref %s)", document_id, ref)
        _fail(doc, job_id, document_id, f"Processing failed (ref {ref})")


def _fail(doc, job_id, document_id, msg):
    db.execute("UPDATE documents SET status='failed', error=? WHERE id=?", (msg[:300], document_id))
    db.execute("UPDATE jobs SET status='failed', error=?, finished_at=datetime('now') WHERE id=?", (msg[:300], job_id))
    db.log_activity(doc["user_id"], "document.failed", {"document_id": document_id, "error": msg}, "error")
