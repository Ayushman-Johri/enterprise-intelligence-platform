"""Unit tests for core logic (no network)."""
import numpy as np
import pytest

from app.services import documents, embeddings, retrieval, security, llm, rag
from app.agent import tools


def test_validate_rejects_bad_extension():
    with pytest.raises(documents.ValidationError):
        documents.validate_upload("malware.exe", b"MZ...")


def test_validate_rejects_fake_pdf_and_disguised_executable():
    with pytest.raises(documents.ValidationError):
        documents.validate_upload("x.pdf", b"not a pdf")
    with pytest.raises(documents.ValidationError):
        documents.validate_upload("notes.txt", b"MZ\x90\x00binary")


def test_validate_rejects_active_pdf():
    with pytest.raises(documents.ValidationError, match="active content"):
        documents.validate_upload("x.pdf", b"%PDF-1.4\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>")


def test_validate_rejects_empty():
    with pytest.raises(documents.ValidationError):
        documents.validate_upload("a.txt", b"")


def test_safe_filename_blocks_path_traversal():
    assert documents.safe_filename("../../etc/passwd") == "passwd"
    assert documents.safe_filename("..\\..\\win.ini") == "win.ini"
    assert not documents.safe_filename(".htaccess").startswith(".")


def test_chunking_respects_size_and_overlap():
    text = ". ".join(f"Sentence number {i} about databases" for i in range(200))
    chunks = documents.chunk_text(text, size=300, overlap=50)
    assert len(chunks) > 5 and all(len(c) <= 360 for c in chunks)


def test_csv_records_are_self_describing():
    assert "service: payments" in documents.csv_to_records("id,service\n1,payments\n2,search\n")[0]


def test_bm25_ranks_exact_identifier_first():
    docs = ["INC-1042 payments outage pool exhaustion", "search latency spike", "certificate expired"]
    assert int(np.argmax(retrieval.BM25(docs).scores("what happened in INC-1042"))) == 0


def test_rrf_fuses_rankings():
    fused = retrieval.rrf([[0, 1, 2], [2, 0, 1]])
    assert max(fused, key=fused.get) == 0


def test_hashing_embeddings_normalized_and_similar():
    v = embeddings._hash_embed(["database connection pool", "database connection pool size", "tropical fruit"])
    assert np.allclose(np.linalg.norm(v, axis=1), 1, atol=1e-5) and v[0] @ v[1] > v[0] @ v[2]


def test_parse_json_handles_fences_and_think_blocks():
    assert llm.parse_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert llm.parse_json('Sure! {"a": 2} hope this helps') == {"a": 2}
    assert llm.parse_json('<think>let me reason {"x":0}</think>{"a": 3}') == {"a": 3}


def test_normalize_citations():
    assert llm.normalize_citations("pool is 50 【S1】 and 【S2†L3-L5】") == "pool is 50 [S1] and [S2]"


def test_clean_answer_keeps_br_only_in_tables_and_blocks_secrets():
    out = rag.clean_answer("Line one<br>line two\n| a | x<br>y |\nkey gsk_abcdefghijklmnop123")
    assert "Line one\nline two" in out and "| a | x<br>y |" in out
    assert "gsk_" not in out and "[redacted]" in out


def test_tool_validation_clamps_and_rejects():
    assert tools.validate_args("search_knowledge_base", {"query": "pool", "top_k": 99})["top_k"] == 10
    with pytest.raises(tools.ToolError):
        tools.validate_args("search_knowledge_base", {"query": ""})
    with pytest.raises(tools.ToolError):
        tools.validate_args("analyze_document", {"document_id": "abc", "focus": "x"})
    with pytest.raises(tools.ToolError):
        tools.validate_args("execute_python", {"code": "import os"})
