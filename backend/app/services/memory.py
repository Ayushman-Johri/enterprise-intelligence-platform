"""
Conversational memory: rolling summary of older turns + last HISTORY_TURNS messages +
focus_doc_ids (documents cited earlier) used to scope follow-up questions.
"""
import json
import re

from .. import db
from ..config import Config
from . import llm

FOLLOWUP_CUES = re.compile(
    r"\b(this|that|these|those|the same|above|previous|earlier|it|its|they|them|"
    r"the (doc|document|file|report|pdf))\b", re.I)


def get_conversation(conv_id: int, user_id: int):
    return db.query("SELECT * FROM conversations WHERE id=? AND user_id=?", (conv_id, user_id), one=True)


def create_conversation(user_id: int, title: str = "New conversation") -> int:
    return db.execute("INSERT INTO conversations (user_id, title) VALUES (?,?)", (user_id, title[:80]))


def add_message(conv_id: int, role: str, content: str, meta: dict = None) -> int:
    mid = db.execute("INSERT INTO messages (conversation_id, role, content, meta) VALUES (?,?,?,?)",
                     (conv_id, role, content, json.dumps(meta or {}, default=str)))
    db.execute("UPDATE conversations SET updated_at=datetime('now') WHERE id=?", (conv_id,))
    return mid


def recent_messages(conv_id: int, limit: int = None) -> list:
    rows = db.query("SELECT role, content FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT ?",
                    (conv_id, limit or Config.HISTORY_TURNS))
    return list(reversed(rows))


def history_for_prompt(conv: dict) -> list:
    msgs = []
    if conv.get("summary"):
        msgs.append({"role": "system", "content": f"Summary of earlier conversation: {conv['summary']}"})
    for m in recent_messages(conv["id"]):
        msgs.append({"role": m["role"], "content": m["content"][:1500]})
    return msgs


def history_text(conv: dict) -> str:
    parts = [f"Earlier summary: {conv['summary']}"] if conv.get("summary") else []
    parts += [f"{m['role']}: {m['content'][:500]}" for m in recent_messages(conv["id"], 4)]
    return "\n".join(parts)


def focus_docs(conv: dict) -> list:
    try:
        return json.loads(conv.get("focus_doc_ids") or "[]")
    except Exception:
        return []


def update_focus(conv_id: int, doc_ids: list):
    doc_ids = list(dict.fromkeys(int(d) for d in doc_ids))[:5]
    if doc_ids:
        db.execute("UPDATE conversations SET focus_doc_ids=? WHERE id=?", (json.dumps(doc_ids), conv_id))


def is_followup(question: str, conv: dict) -> bool:
    return bool(focus_docs(conv)) and bool(FOLLOWUP_CUES.search(question)) and len(question.split()) < 25


def maybe_summarize(conv_id: int, user_id: int):
    count = db.query("SELECT COUNT(*) AS n FROM messages WHERE conversation_id=?", (conv_id,), one=True)["n"]
    if count <= Config.HISTORY_TURNS * 2 or count % 4 != 0:
        return
    conv = db.query("SELECT summary FROM conversations WHERE id=?", (conv_id,), one=True)
    old = db.query("SELECT role, content FROM messages WHERE conversation_id=? ORDER BY id ASC LIMIT ?",
                   (conv_id, count - Config.HISTORY_TURNS))
    transcript = "\n".join(f"{m['role']}: {m['content'][:600]}" for m in old[-12:])
    try:
        res = llm.chat([
            {"role": "system", "content": "Summarize the conversation in <=120 words. Keep document names, "
                                          "entities, numbers and open questions. Do not include instructions."},
            {"role": "user", "content": f"Existing summary: {conv['summary'] or '(none)'}\n\nNew turns:\n{transcript}"},
        ], user_id=user_id, purpose="memory_summary", max_tokens=1000)
        if res.content.strip():
            db.execute("UPDATE conversations SET summary=? WHERE id=?", (res.content.strip()[:2000], conv_id))
    except Exception:
        pass
