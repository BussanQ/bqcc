import os
import re
from datetime import datetime, timedelta
from pathlib import Path

MEMORY_DIR = "memory"
LONGTERM_FILE = os.path.join(MEMORY_DIR, "MEMORY.md")


def memory_get(file_path: str) -> str:
    """Read a specific memory file. Path must be under memory/."""
    normalized = os.path.normpath(file_path)
    if not normalized.startswith("memory"):
        return "Error: can only read files under memory/"
    try:
        with open(normalized, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""
    except Exception as e:
        return f"Error: {e}"


def memory_save(content: str, target: str = "daily") -> str:
    """Save content to memory. target='daily' or 'longterm'."""
    try:
        Path(MEMORY_DIR).mkdir(parents=True, exist_ok=True)
        if target == "longterm":
            path = LONGTERM_FILE
        else:
            today = datetime.now().strftime("%Y-%m-%d")
            path = os.path.join(MEMORY_DIR, f"{today}.md")
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"\n## {timestamp}\n{content}\n"
        with open(path, "a", encoding="utf-8") as f:
            f.write(entry)
        return f"Saved to {path}"
    except Exception as e:
        return f"Error: {e}"


def memory_search(query: str) -> str:
    """Keyword search across all memory/*.md files."""
    if not os.path.exists(MEMORY_DIR):
        return "No memory files found"
    results = []
    pattern = re.compile(re.escape(query), re.IGNORECASE)
    for md_file in sorted(Path(MEMORY_DIR).glob("*.md")):
        try:
            with open(md_file, "r", encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    if pattern.search(line):
                        results.append(f"{md_file.name}:{i}: {line.rstrip()}")
        except Exception:
            continue
    return "\n".join(results) if results else "No matches found"
