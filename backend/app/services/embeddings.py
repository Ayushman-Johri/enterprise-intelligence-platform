"""
Embeddings run locally (Groq has no embeddings endpoint).
- fastembed (default): BAAI/bge-small-en-v1.5, 384-dim, ONNX runtime.
- hashing (fallback):  feature-hashing of word uni/bi-grams, 512-dim; no download, weaker semantics.
"""
import hashlib
import logging
import re
import threading

import numpy as np

from ..config import Config

log = logging.getLogger("eip.embed")
_model = None
_lock = threading.Lock()
_backend_in_use = None
_TOKEN_RE = re.compile(r"[a-z0-9]+")
HASH_DIM = 512


def _hash_embed(texts: list) -> np.ndarray:
    out = np.zeros((len(texts), HASH_DIM), dtype=np.float32)
    for i, t in enumerate(texts):
        toks = _TOKEN_RE.findall(t.lower())
        for f in toks + [f"{a}_{b}" for a, b in zip(toks, toks[1:])]:
            h = int(hashlib.md5(f.encode()).hexdigest(), 16)
            out[i, h % HASH_DIM] += 1.0 if (h >> 64) & 1 else -1.0
    norms = np.linalg.norm(out, axis=1, keepdims=True)
    norms[norms == 0] = 1
    return out / norms


def _load():
    global _model, _backend_in_use
    if _backend_in_use:
        return
    with _lock:
        if _backend_in_use:
            return
        if Config.EMBEDDING_BACKEND == "fastembed":
            try:
                from fastembed import TextEmbedding
                _model = TextEmbedding(model_name=Config.EMBEDDING_MODEL, cache_dir=Config.EMBEDDING_CACHE_DIR)
                _backend_in_use = "fastembed"
                log.info("Embeddings: fastembed %s", Config.EMBEDDING_MODEL)
                return
            except Exception as e:
                log.warning("fastembed unavailable (%s) -> using hashing embeddings", type(e).__name__)
        _backend_in_use = "hashing"


def backend_name() -> str:
    _load()
    return "hashing" if _backend_in_use == "hashing" else f"fastembed:{Config.EMBEDDING_MODEL}"


def embed(texts: list, is_query: bool = False) -> np.ndarray:
    _load()
    if not texts:
        return np.zeros((0, HASH_DIM), dtype=np.float32)
    if _backend_in_use == "fastembed":
        gen = _model.query_embed(texts) if is_query else _model.embed(texts, batch_size=32)
        arr = np.array(list(gen), dtype=np.float32)
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        norms[norms == 0] = 1
        return arr / norms
    return _hash_embed(texts)


def to_blob(vec: np.ndarray) -> bytes:
    return vec.astype(np.float32).tobytes()


def from_blob(blob: bytes) -> np.ndarray:
    return np.frombuffer(blob, dtype=np.float32)
