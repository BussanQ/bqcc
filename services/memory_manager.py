"""Memory manager — daily logs, long-term memory, search, and context loading."""
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

MEMORY_DIR = "memory"
LONGTERM_FILE = os.path.join(MEMORY_DIR, "MEMORY.md")
MAX_LONGTERM_LINES = 100
MAX_DAILY_LINES = 50


class MemoryManager:
    def __init__(self, memory_dir: str = MEMORY_DIR):
        self.memory_dir = memory_dir
        self.longterm_file = os.path.join(memory_dir, "MEMORY.md")

    async def load_context(self) -> str:
        """Load today + yesterday daily logs and tail of MEMORY.md for prompt injection."""
        parts = []

        # Long-term memory
        lt = self._read_tail(self.longterm_file, MAX_LONGTERM_LINES)
        if lt:
            parts.append(f"## Long-term Memory\n{lt}")

        # Today's daily log
        today = datetime.now().strftime("%Y-%m-%d")
        today_file = os.path.join(self.memory_dir, f"{today}.md")
        today_content = self._read_tail(today_file, MAX_DAILY_LINES)
        if today_content:
            parts.append(f"## Today ({today})\n{today_content}")

        # Yesterday's daily log
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        yesterday_file = os.path.join(self.memory_dir, f"{yesterday}.md")
        yesterday_content = self._read_tail(yesterday_file, MAX_DAILY_LINES)
        if yesterday_content:
            parts.append(f"## Yesterday ({yesterday})\n{yesterday_content}")

        return "\n\n".join(parts) if parts else ""

    async def save_daily(self, task: str, result: str):
        """Append task/result to today's daily log."""
        Path(self.memory_dir).mkdir(parents=True, exist_ok=True)
        today = datetime.now().strftime("%Y-%m-%d")
        path = os.path.join(self.memory_dir, f"{today}.md")
        timestamp = datetime.now().strftime("%H:%M:%S")
        # Truncate result if too long
        result_summary = result[:500] if len(result) > 500 else result
        entry = f"\n## {timestamp}\n**Task:** {task}\n**Result:** {result_summary}\n"
        with open(path, "a", encoding="utf-8") as f:
            f.write(entry)

    async def save_longterm(self, insight: str):
        """Append a durable insight to MEMORY.md."""
        Path(self.memory_dir).mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        entry = f"\n- [{timestamp}] {insight}\n"
        with open(self.longterm_file, "a", encoding="utf-8") as f:
            f.write(entry)

    async def search(self, query: str) -> list[str]:
        """Keyword search across all memory/*.md files."""
        if not os.path.exists(self.memory_dir):
            return []
        results = []
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        for md_file in sorted(Path(self.memory_dir).glob("*.md")):
            try:
                with open(md_file, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f, 1):
                        if pattern.search(line):
                            results.append(f"{md_file.name}:{i}: {line.rstrip()}")
            except Exception:
                continue
        return results

    def _read_tail(self, path: str, max_lines: int) -> str:
        """Read the last max_lines from a file."""
        if not os.path.exists(path):
            return ""
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            tail = lines[-max_lines:] if len(lines) > max_lines else lines
            return "".join(tail).strip()
        except Exception:
            return ""
