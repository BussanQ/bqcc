"""Tool registration for Agently agent."""
import os
import json
from pathlib import Path
from tools.file_ops import read_file, write_file, edit_file
from tools.search_ops import glob_search, grep_search
from tools.shell_ops import bash
from tools.memory_ops import memory_get, memory_save, memory_search


def register_tools(agent):
    """Register all tools on the given Agently agent. Returns list of tool functions."""

    @agent.tool_func
    def read(path: str, offset: int = 0, limit: int = 0) -> str:
        """Read file content with line numbers. offset/limit are optional."""
        return read_file(path, offset, limit)

    @agent.tool_func
    def write(path: str, content: str) -> str:
        """Write content to file, creating parent dirs if needed."""
        return write_file(path, content)

    @agent.tool_func
    def edit(path: str, old_string: str, new_string: str) -> str:
        """Replace exactly one occurrence of old_string with new_string."""
        return edit_file(path, old_string, new_string)

    @agent.tool_func
    def glob(pattern: str) -> str:
        """Find files matching glob pattern (supports **), sorted by mtime."""
        return glob_search(pattern)

    @agent.tool_func
    def grep(pattern: str, path: str = ".") -> str:
        """Search files for regex pattern."""
        return grep_search(pattern, path)

    @agent.tool_func
    def shell(command: str) -> str:
        """Run a shell command and return output."""
        return bash(command)

    @agent.tool_func
    def mem_get(file_path: str) -> str:
        """Read a memory file from memory/ directory."""
        return memory_get(file_path)

    @agent.tool_func
    def mem_save(content: str, target: str = "daily") -> str:
        """Save to memory. target='daily' for today's log, 'longterm' for MEMORY.md."""
        return memory_save(content, target)

    @agent.tool_func
    def mem_search(query: str) -> str:
        """Search all memory files for a keyword."""
        return memory_search(query)

    return [read, write, edit, glob, grep, shell, mem_get, mem_save, mem_search]


MCP_CONFIG = ".agent/mcp.json"


def load_mcp_tools():
    """Load MCP tool definitions from .agent/mcp.json if present."""
    if not os.path.exists(MCP_CONFIG):
        return []
    try:
        with open(MCP_CONFIG, "r", encoding="utf-8") as f:
            config = json.load(f)
        tools = []
        for server_name, server_config in config.get("mcpServers", {}).items():
            if server_config.get("disabled", False):
                continue
            for tool in server_config.get("tools", []):
                tools.append(tool)
        return tools
    except Exception:
        return []
