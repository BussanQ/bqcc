"""Structured storage helpers for resumable chat sessions."""
import re
from pathlib import Path
from uuid import uuid4


DEFAULT_SESSION_DIR = Path("memory") / "sessions"


class SessionStore:
    def __init__(self, base_dir: Path | str = DEFAULT_SESSION_DIR):
        self.base_dir = Path(base_dir)

    def create_session_id(self, requested_id: str | None = None) -> str:
        raw_value = requested_id.strip() if isinstance(requested_id, str) and requested_id.strip() else uuid4().hex[:12]
        safe_value = re.sub(r"[^A-Za-z0-9._-]+", "-", raw_value).strip("-._")
        return safe_value or uuid4().hex[:12]

    def get_session_path(self, session_id: str) -> Path:
        safe_id = self.create_session_id(session_id)
        return self.base_dir / f"{safe_id}.json"

    def exists(self, session_id: str) -> bool:
        return self.get_session_path(session_id).exists()

    def load(self, session, session_id: str) -> bool:
        path = self.get_session_path(session_id)
        if not path.exists():
            return False
        session.load_json(path)
        return True

    def save(self, session) -> Path:
        session_id = self.create_session_id(getattr(session, "id", None))
        session.id = session_id
        path = self.get_session_path(session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(session.to_json(), encoding="utf-8")
        return path
