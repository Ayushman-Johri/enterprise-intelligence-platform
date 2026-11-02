"""
Hybrid retrieval = dense vectors + BM25 keywords, fused with Reciprocal Rank Fusion,
plus LLM query rewriting and metadata filtering. Always scoped to one user.
"""
import math
import re
from collections import Counter
from dataclasses import dataclass, asdict
from typing import Optional

import numpy as np

from .. import db
from ..config import Config
from . import embeddings, llm

_TOK = re.compile(r"[a-z0-9]+")
STOP = set("a an the of to in on for and or is are was were be been with by at from as that this it its "
           "what which who whom how why when where do does did can could should would our we you your i "
           "me my they their there these those about into than then them any all".split())


def tokenize(text: str) -> list:
    return [t for t in _TOK.findall((text or "").lower()) if t not in STOP and len(t) > 1]


class BM25:
    def __init__(self, docs: list, k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.docs = [tokenize(d) for d in docs]
        self.N = len(self.docs)
        self.avgdl = (sum(len(d) for d in self.docs) / self.N) if self.N else 0
        df = Counter()
        for d in self.docs:
            df.update(set(d))
        self.idf = {t: math.log(1 + (self.N - n + 0.5) / (n + 0.5)) for t, n in df.items()}
        self.tf = [Counter(d) for d in self.docs]

    def scores(self, query: str) -> np.ndarray:
        q = tokenize(query)
        out = np.zeros(self.N, dtype=np.float32)
        for i, tf in enumerate(self.tf):
            dl = len(self.docs[i]) or 1
            out[i] = sum(self.idf.get(t, 0) * tf[t] * (self.k1 + 1) /
                         (tf[t] + self.k1 * (1 - self.b + self.b * dl / (self.avgdl or 1)))
                         for t in q if t in tf)
        return out


def rrf(rank_lists: list, k: int = 60) -> dict:
    scores = {}
    for ranks in rank_lists:
        for pos, idx in enumerate(ranks):
            scores[idx] = scores.get(idx, 0.0) + 1.0 / (k + pos + 1)
    return scores


@dataclass
class Hit:
    chunk_id: int
    document_id: int
    filename: str
    page: Optional[int]
    text: str
    vector_score: float
    bm25_score: float
    fused_score: float
    suspicious: bool
    injection_reasons: str = ""

    def to_source(self, n: int) -> dict:
        d = asdict(self)
        d["source_id"] = f"S{n}"
        d["snippet"] = self.text[:300]
        del d["text"]
        return d


def load_chunks(user_id: int, doc_ids: Optional[list] = None, file_type: Optional[str] = None) -> list:
    sql = """SELECT c.id, c.document_id, c.text, c.page, c.embedding, c.suspicious, c.injection_reasons, d.filename
             FROM chunks c JOIN documents d ON d.id = c.document_id
             WHERE c.user_id = ? AND d.user_id = ? AND d.status = 'ready'"""
    params = [user_id, user_id]
    if doc_ids:
        sql += f" AND c.document_id IN ({','.join('?' * len(doc_ids))})"
        params += [int(x) for x in doc_ids]
    if file_type:
        sql += " AND d.file_type = ?"
        params.append(file_type)
    if Config.INJECTION_ACTION == "exclude":
        sql += " AND c.suspicious = 0"
    return db.query(sql, tuple(params))


def search(user_id: int, query: str, top_k: int = None, doc_ids: Optional[list] = None,
           file_type: Optional[str] = None) -> list:
    top_k = top_k or Config.TOP_K
    rows = load_chunks(user_id, doc_ids, file_type)
    if not rows:
        return []
    qv = embeddings.embed([query], is_query=True)[0]
    rows = [r for r in rows if len(r["embedding"]) == qv.shape[0] * 4]
    if not rows:
        raise RuntimeError("Documents were embedded with a different embedding backend - click 'Reprocess' on them")
    mat = np.vstack([embeddings.from_blob(r["embedding"]) for r in rows])
    vec_scores = mat @ qv
    bm = BM25([r["text"] for r in rows]).scores(query)
    pool = min(len(rows), max(top_k * 4, 20))
    vec_rank = list(np.argsort(-vec_scores)[:pool])
    bm_rank = [i for i in np.argsort(-bm)[:pool] if bm[i] > 0]
    fused = rrf([vec_rank, bm_rank])
    order = sorted(fused, key=lambda i: -fused[i])[:top_k]
    return [Hit(rows[i]["id"], rows[i]["document_id"], rows[i]["filename"], rows[i]["page"], rows[i]["text"],
                float(vec_scores[i]), float(bm[i]), float(fused[i]), bool(rows[i]["suspicious"]),
                rows[i].get("injection_reasons") or "") for i in order]


def relevance_ok(hits: list) -> bool:
    if not hits:
        return False
    threshold = Config.MIN_RELEVANCE if embeddings.backend_name() != "hashing" else Config.MIN_RELEVANCE * 0.6
    return max(h.vector_score for h in hits) >= threshold or max(h.bm25_score for h in hits) >= 3.0


def rewrite_query(question: str, history_text: str, user_id=None) -> tuple:
    if not Config.ENABLE_QUERY_REWRITE:
        return question, None
    msgs = [
        {"role": "system", "content": (
            "You rewrite user questions for a document search engine. Resolve pronouns and references "
            "using the conversation context. Return JSON: {\"standalone_question\": str, \"keywords\": str}. "
            "keywords = important terms, identifiers, synonyms separated by spaces.")},
        {"role": "user", "content": f"Conversation context:\n{history_text or '(none)'}\n\nQuestion: {question}"},
    ]
    try:
        data, res = llm.chat_json(msgs, user_id=user_id, purpose="query_rewrite", max_tokens=800,
                                  use_cache=True, temperature=0)
        q = (data.get("standalone_question") or question).strip()
        return f"{q} {(data.get('keywords') or '').strip()}".strip()[:1000], res.usage()
    except Exception:
        return question, None
