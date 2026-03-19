"""Helpers for cleaning assistant output before display or persistence."""
import re
from typing import Any


THINK_BLOCK_RE = re.compile(r"<think>[\s\S]*?</think>", re.IGNORECASE)
USER_INPUT_PREFIX_RE = re.compile(r"^\[input\]:\s*\n?", re.IGNORECASE)


def sanitize_assistant_output(value: Any, fallback: str = "(no result)") -> str:
    """Remove visible reasoning blocks and normalize whitespace in assistant output."""
    text = "" if value is None else str(value)
    text = THINK_BLOCK_RE.sub("", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text or fallback


def sanitize_user_content(value: Any) -> str:
    """Normalize stored user content for chat history."""
    text = "" if value is None else str(value)
    text = USER_INPUT_PREFIX_RE.sub("", text).strip()
    return text


def sanitize_chat_history(messages) -> list[dict[str, str]]:
    """Return a cleaned chat history list that is safe to persist."""
    cleaned: list[dict[str, str]] = []
    for message in messages:
        if isinstance(message, dict):
            role = str(message.get("role", "assistant"))
            content = message.get("content", "")
        else:
            role = str(getattr(message, "role", "assistant"))
            content = getattr(message, "content", "")

        if role == "assistant":
            normalized = sanitize_assistant_output(content, fallback="")
        elif role == "user":
            normalized = sanitize_user_content(content)
        else:
            normalized = "" if content is None else str(content).strip()

        cleaned.append({"role": role, "content": normalized})
    return cleaned
