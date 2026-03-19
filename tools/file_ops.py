import os
import glob as glob_module
import subprocess
from pathlib import Path


def read_file(path: str, offset: int = 0, limit: int = 0) -> str:
    """Read file content with line numbers."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        start = offset
        end = start + limit if limit > 0 else len(lines)
        numbered = [f"{i+1:4d} {line}" for i, line in enumerate(lines[start:end], start)]
        return "".join(numbered) if numbered else "(empty file)"
    except Exception as e:
        return f"Error: {e}"


def write_file(path: str, content: str) -> str:
    """Write content to file, creating parent dirs if needed."""
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"Successfully wrote to {path}"
    except Exception as e:
        return f"Error: {e}"


def edit_file(path: str, old_string: str, new_string: str) -> str:
    """Replace exactly one occurrence of old_string with new_string in file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        count = content.count(old_string)
        if count == 0:
            return "Error: old_string not found in file"
        if count > 1:
            return f"Error: old_string appears {count} times, must appear exactly once"
        new_content = content.replace(old_string, new_string, 1)
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_content)
        return f"Successfully edited {path}"
    except Exception as e:
        return f"Error: {e}"
