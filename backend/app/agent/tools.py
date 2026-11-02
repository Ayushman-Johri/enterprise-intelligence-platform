"""
Agent tools: JSON schema (sent to the LLM), validator, executor.
Least privilege: tools can only READ the calling user's own documents. There is no tool that executes code,
reads files from disk, queries arbitrary SQL, accesses user accounts, or makes network requests.
"""
import json

from .. import db
from ..services import llm, retrieval, security


class ToolError(Exception):
    pass


TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": "list_documents",
        "description": "List the user's processed documents (id, filename, type, chunks). Use to find document ids.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {
        "name": "search_knowledge_base",
        "description": "Hybrid semantic+keyword search over the user's documents. Returns evidence passages with source ids, document ids and filenames.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string", "description": "Search query"},
            "top_k": {"type": "integer", "description": "Number of passages (1-10)"},
            "document_ids": {"type": "array", "items": {"type": "integer"}, "description": "Optional filter"}},
            "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "analyze_document",
        "description": "Deep-analyze ONE document for a given focus. Returns structured findings with evidence. Use document_id from search results or list_documents.",
        "parameters": {"type": "object", "properties": {
            "document_id": {"type": "integer"},
            "focus": {"type": "string", "description": "What to analyze"}},
            "required": ["document_id", "focus"]}}},
    {"type": "function", "function": {
        "name": "generate_report",
        "description": "Generate a structured report (executive summary, findings, evidence, recommendations) from findings gathered by previous tools.",
        "parameters": {"type": "object", "properties": {
            "title": {"type": "string"},
            "findings": {"type": "string", "description": "Findings and evidence collected from previous tool outputs"},
            "audience": {"type": "string", "description": "e.g. engineering, management"}},
            "required": ["title", "findings"]}}},
]
ALLOWED_TOOLS = {t["function"]["name"] for t in TOOL_SCHEMAS}


def validate_args(name: str, args: dict) -> dict:
    if name not in ALLOWED_TOOLS:
        raise ToolError(f"unknown tool '{name}'")
    if not isinstance(args, dict):
        raise ToolError("arguments must be a JSON object")
    if name == "list_documents":
        return {}
    if name == "search_knowledge_base":
        q = str(args.get("query", "")).strip()
        if len(q) < 2:
            raise ToolError("'query' is required (min 2 chars)")
        try:
            top_k = max(1, min(10, int(args.get("top_k") or 6)))
        except (TypeError, ValueError):
            top_k = 6
        ids = args.get("document_ids") or None
        if ids is not None:
            try:
                ids = [int(i) for i in ids][:20]
            except (TypeError, ValueError):
                raise ToolError("'document_ids' must be a list of integers")
        return {"query": q[:500], "top_k": top_k, "document_ids": ids}
    if name == "analyze_document":
        try:
            did = int(args.get("document_id"))
        except (TypeError, ValueError):
            raise ToolError("'document_id' must be an integer")
        focus = str(args.get("focus", "")).strip()
        if not focus:
            raise ToolError("'focus' is required")
        return {"document_id": did, "focus": focus[:300]}
    findings = str(args.get("findings", "")).strip()
    if len(findings) < 20:
        raise ToolError("'findings' must contain the evidence gathered by earlier tools")
    return {"title": (str(args.get("title", "")).strip() or "Analysis Report")[:150],
            "findings": findings[:12000], "audience": str(args.get("audience") or "management")[:50]}


def t_list_documents(user_id: int) -> dict:
    return {"documents": db.query("SELECT id, filename, file_type, num_chunks, status FROM documents "
                                  "WHERE user_id=? ORDER BY id DESC LIMIT 50", (user_id,))}


def t_search(user_id: int, query: str, top_k: int, document_ids=None) -> dict:
    hits = retrieval.search(user_id, query, top_k=top_k, doc_ids=document_ids)
    return {"relevant": retrieval.relevance_ok(hits),
            "results": [{"source_id": f"S{i+1}", "document_id": h.document_id, "filename": h.filename,
                         "page": h.page, "score": round(h.fused_score, 4), "suspicious": h.suspicious,
                         "text": security.wrap_untrusted(f"S{i+1}", h.filename, h.text[:1200], h.suspicious)}
                        for i, h in enumerate(hits)]}


def t_analyze(user_id: int, document_id: int, focus: str, usage_sink: list) -> dict:
    doc = db.query("SELECT id, filename FROM documents WHERE id=? AND user_id=? AND status='ready'",
                   (document_id, user_id), one=True)
    if not doc:
        raise ToolError(f"document {document_id} not found or not ready")
    hits = retrieval.search(user_id, focus, top_k=8, doc_ids=[document_id])
    ctx = "\n\n".join(security.wrap_untrusted(f"C{h.chunk_id}", doc["filename"], h.text, h.suspicious) for h in hits)
    data, res = llm.chat_json([
        {"role": "system", "content": "You analyze one document. " + security.UNTRUSTED_POLICY +
         ' Return ONLY a JSON object: {"summary": str, "findings": [{"finding": str, "evidence": str, "chunk": str}], '
         '"gaps_or_conflicts": [str]}. Only use the provided text.'},
        {"role": "user", "content": f"Document: {doc['filename']}\nFocus: {focus}\n\n{ctx}"},
    ], user_id=user_id, purpose="agent_analyze", max_tokens=2500, temperature=0)
    usage_sink.append({"step": "analyze_document", **res.usage()})
    data["document"], data["document_id"] = doc["filename"], document_id
    return data


def t_report(user_id: int, title: str, findings: str, audience: str, usage_sink: list) -> dict:
    def _v(d):
        for k in ("executive_summary", "findings", "recommendations"):
            if k not in d:
                raise ValueError(f"missing '{k}'")
    data, res = llm.chat_json([
        {"role": "system", "content": "You write structured enterprise reports strictly from the provided findings. "
         "Do not invent facts. Plain text in fields (no HTML, no markdown tables, no links). " + security.UNTRUSTED_POLICY +
         ' Return ONLY a JSON object: {"title": str, "executive_summary": str, "findings": [{"title": str, "detail": str, '
         '"evidence": str}], "recommendations": [{"action": str, "priority": "high|medium|low", "rationale": str}], '
         '"risks_and_gaps": [str]}'},
        {"role": "user", "content": f"Title: {title}\nAudience: {audience}\n\nFINDINGS:\n{findings}"},
    ], validator=_v, user_id=user_id, purpose="agent_report", max_tokens=3500, temperature=0.1)
    usage_sink.append({"step": "generate_report", **res.usage()})
    return data


def execute(name: str, args: dict, user_id: int, usage_sink: list) -> dict:
    if name == "list_documents":
        return t_list_documents(user_id)
    if name == "search_knowledge_base":
        return t_search(user_id, **args)
    if name == "analyze_document":
        return t_analyze(user_id, usage_sink=usage_sink, **args)
    if name == "generate_report":
        return t_report(user_id, usage_sink=usage_sink, **args)
    raise ToolError(f"unknown tool '{name}'")


def to_tool_message(result) -> str:
    return json.dumps(result, default=str)[:12000]
