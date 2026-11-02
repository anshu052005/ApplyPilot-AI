import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class CurrentUser:
    """The verified identity of the caller. Built only from a verified Supabase JWT."""

    id: uuid.UUID
    email: str | None
