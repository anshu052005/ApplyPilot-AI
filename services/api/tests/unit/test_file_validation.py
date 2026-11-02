import io
import zipfile

import pytest

from app.modules.files import validation
from app.modules.files.validation import safe_display_name, sniff_document_kind


def make_docx(parts: dict[str, bytes] | None = None) -> bytes:
    buffer = io.BytesIO()
    contents = parts if parts is not None else {
        "[Content_Types].xml": b"<Types/>",
        "word/document.xml": b"<document/>",
    }
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in contents.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_pdf_is_recognised_by_content():
    assert sniff_document_kind(b"%PDF-1.7\n...") == "pdf"


def test_docx_is_recognised_by_content():
    assert sniff_document_kind(make_docx()) == "docx"


def test_plain_text_is_rejected_even_with_a_pdf_name():
    assert sniff_document_kind(b"just some text") is None


def test_html_is_rejected():
    assert sniff_document_kind(b"<html><script>alert(1)</script></html>") is None


def test_zip_without_word_parts_is_not_a_docx():
    assert sniff_document_kind(make_docx({"hello.txt": b"hi"})) is None


def test_corrupt_zip_is_rejected():
    assert sniff_document_kind(b"PK\x03\x04" + b"\x00" * 50) is None


def test_docx_with_oversized_uncompressed_content_is_rejected(monkeypatch):
    monkeypatch.setattr(validation, "MAX_DOCX_UNCOMPRESSED_BYTES", 100)
    assert sniff_document_kind(make_docx({"[Content_Types].xml": b"x" * 500, "word/document.xml": b"y"})) is None


def test_empty_bytes_are_rejected():
    assert sniff_document_kind(b"") is None


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("../../etc/passwd", "passwd"),
        ("..\\..\\windows\\system.ini", "system.ini"),
        ("resume\x00.pdf", "resume.pdf"),
        ("", "document"),
        (None, "document"),
        ("   ", "document"),
    ],
)
def test_display_name_cannot_carry_path_or_control_characters(raw, expected):
    assert safe_display_name(raw) == expected


def test_display_name_is_length_limited():
    assert len(safe_display_name("a" * 1000 + ".pdf")) == 255
