"""Upload validation for candidate documents.

Checks, in order: size, content sniffing (magic bytes), and agreement between the sniffed type and the declared
MIME type. The browser's declared type and filename are never trusted on their own.
"""

import io
import re
import zipfile

MAX_FILE_BYTES = 10 * 1024 * 1024
# Upper bound on the uncompressed size of a DOCX archive, to stop zip bombs.
MAX_DOCX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024

MIME_BY_KIND = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
EXTENSION_BY_KIND = {"pdf": "pdf", "docx": "docx"}

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def sniff_document_kind(data: bytes) -> str | None:
    """Returns "pdf", "docx", or None. Looks at the content, not the name or declared type."""
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"PK\x03\x04") and _looks_like_docx(data):
        return "docx"
    return None


def _looks_like_docx(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
            if not {"[Content_Types].xml", "word/document.xml"} <= names:
                return False
            total = sum(info.file_size for info in archive.infolist())
            return total <= MAX_DOCX_UNCOMPRESSED_BYTES
    except (zipfile.BadZipFile, RuntimeError, ValueError, OSError):
        return False


def safe_display_name(filename: str | None) -> str:
    """Keeps a readable name for display only. It is never used to build a storage path."""
    base = (filename or "document").replace("\\", "/").rsplit("/", 1)[-1]
    base = _CONTROL_CHARS.sub("", base).strip()
    return (base or "document")[:255]
