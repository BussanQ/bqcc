import os
import glob as glob_module
import subprocess


def glob_search(pattern: str) -> str:
    """Find files matching glob pattern, sorted by modification time."""
    try:
        files = glob_module.glob(pattern, recursive=True)
        files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        return "\n".join(files) if files else "No files found"
    except Exception as e:
        return f"Error: {e}"


def grep_search(pattern: str, path: str = ".") -> str:
    """Search files for regex pattern using grep."""
    try:
        result = subprocess.run(
            ["grep", "-rn", pattern, path],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout if result.stdout else "No matches found"
    except Exception as e:
        return f"Error: {e}"
