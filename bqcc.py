"""AgentlyBq — Agently-powered CLI agent with workspace prompts, memory, and TriggerFlow."""
import argparse
import asyncio
import io
import os
import re
import sys

import yaml

# Fix Windows console encoding for Unicode output
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Auto-load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv not installed — use system env vars
    env_path = os.path.join(os.path.dirname(__file__) or ".", ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    os.environ.setdefault(_k.strip(), _v.strip())

from agently import Agently

from services.memory_manager import MemoryManager
from services.workspace_loader import inject_workspace, load_rules, load_skills, load_workspace
from tools import register_tools
from workflow.chat_mode import run_chat_mode
from workflow.plan_execute import run_plan_execute


# ---------------------------------------------------------------------------
# Settings loader
# ---------------------------------------------------------------------------

def load_settings(path: str = "SETTINGS.yaml"):
    """Load SETTINGS.yaml and apply to Agently with ${ENV.xxx} resolution."""
    prefix = "plugins.ModelRequester.OpenAICompatible"

    if not os.path.exists(path):
        print(f"[Warn] {path} not found, using env vars directly")
        Agently.set_settings(f"{prefix}.base_url", os.environ.get("OPENAI_BASE_URL", ""))
        Agently.set_settings(f"{prefix}.auth", os.environ.get("OPENAI_API_KEY", ""))
        Agently.set_settings(f"{prefix}.model", os.environ.get("OPENAI_MODEL", "gpt-4o-mini"))
        return

    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    cfg = _resolve_env(cfg)

    # Apply settings recursively using dot-notation paths
    _apply_settings(cfg)


def _resolve_env(value):
    """Recursively resolve ${ENV.xxx} placeholders in config values."""
    if isinstance(value, str):
        return re.sub(
            r"\$\{ENV\.(\w+)\}",
            lambda m: os.environ.get(m.group(1), ""),
            value,
        )
    if isinstance(value, dict):
        return {k: _resolve_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env(v) for v in value]
    return value


def _apply_settings(cfg: dict, prefix: str = ""):
    """Recursively apply a nested dict to Agently.set_settings using dot-notation keys."""
    for key, value in cfg.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            _apply_settings(value, path)
        else:
            Agently.set_settings(path, value)


# ---------------------------------------------------------------------------
# Self-optimization
# ---------------------------------------------------------------------------

async def self_optimize(agent, memory: MemoryManager, task: str, result: str):
    """Ask the model if this interaction produced a durable insight worth remembering."""
    try:
        request = agent.create_request(
            inherit_agent_prompt=True,
            inherit_extension_handlers=False,
        )
        insight = await (
            request
            .input(f"Task: {task}\nResult: {result[:500]}")
            .instruct(
                "Determine if this interaction produced a durable pattern, preference, or fact "
                "worth remembering long-term. If yes, return a concise memory entry. "
                "If not, return an empty string."
            )
            .output({
                "insight": (str, "concise memory entry, or empty string if nothing worth remembering"),
            })
            .async_start()
        )
        if isinstance(insight, dict):
            text = insight.get("insight", "")
        else:
            text = str(insight) if insight else ""
        if text and text.strip():
            await memory.save_longterm(text.strip())
            print(f"[Memory] Saved insight: {text.strip()[:80]}...")
    except Exception as e:
        print(f"[Memory] Self-optimize skipped: {e}")


# ---------------------------------------------------------------------------
# Bootstrap and execution
# ---------------------------------------------------------------------------

async def bootstrap_agent():
    """Create and configure the shared Agently agent runtime."""
    print("[Init] Loading AgentlyBq...")

    load_settings()
    agent = Agently.create_agent()
    model_name = Agently.settings.get("plugins.ModelRequester.OpenAICompatible.model") or "default"
    print(f"[Model] {model_name}")

    workspace = await load_workspace()
    rules = await load_rules()
    skills = await load_skills()
    inject_workspace(agent, workspace, rules, skills)
    loaded = [f for f in ["SOUL.md", "AGENT.md", "USER.md", "TOOLS.md"] if f in workspace]
    if loaded:
        print(f"[Workspace] Loaded: {', '.join(loaded)}")
    if rules:
        print("[Rules] Loaded")
    if skills:
        print(f"[Skills] Loaded {len(skills)} skills")

    memory = MemoryManager()
    context = await memory.load_context()
    if context:
        agent.info(f"[Memory]\n{context}", always=True)
        print("[Memory] Context loaded")

    tool_funcs = register_tools(agent)
    agent.set_tool_loop(enabled=True)
    print(f"[Tools] Registered {len(tool_funcs)} tools: {[f.__name__ for f in tool_funcs]}")
    return agent, tool_funcs, memory


async def run_direct_task(agent, tool_funcs, task: str) -> str:
    """Execute one task in direct tool-using mode."""
    print("\n[Mode] Direct execution")
    result = await agent.input(task).use_tools(tool_funcs).async_start()
    return str(result) if result else "(no result)"


async def run_single_task(agent, tool_funcs, task: str, use_plan: bool = False) -> str:
    """Execute one task in either direct or plan mode."""
    if use_plan:
        print("\n[Mode] Plan-then-execute")
        result = await run_plan_execute(agent, tool_funcs, task)
    else:
        result = await run_direct_task(agent, tool_funcs, task)

    print(f"\n{'=' * 60}")
    print(result)
    print(f"{'=' * 60}")
    return result


async def main(
    task: str | None = None,
    *,
    use_plan: bool = False,
    use_chat: bool = False,
    session_id: str | None = None,
):
    agent, tool_funcs, memory = await bootstrap_agent()

    if use_chat:
        async def on_turn_complete(turn_task: str, turn_result: str):
            await self_optimize(agent, memory, turn_task, turn_result)

        await run_chat_mode(
            agent=agent,
            tool_funcs=tool_funcs,
            default_use_plan=use_plan,
            session_id=session_id,
            on_turn_complete=on_turn_complete,
        )
        return "(chat session ended)"

    if not task:
        return "(no task)"

    result = await run_single_task(agent, tool_funcs, task, use_plan=use_plan)
    await memory.save_daily(task, result)
    await self_optimize(agent, memory, task, result)
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AgentlyBq — Agently-powered CLI Agent")
    parser.add_argument("task", nargs="*", help="Task to execute in one-shot mode")
    parser.add_argument("--plan", action="store_true", help="Enable TriggerFlow plan-then-execute mode")
    parser.add_argument("--chat", action="store_true", help="Start interactive conversation mode")
    parser.add_argument("--session", help="Session ID to resume or create for --chat mode")
    return parser


def parse_args(argv: list[str] | None = None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.session and not args.chat:
        parser.error("--session requires --chat")
    if args.chat and args.task:
        parser.error("--chat does not accept a one-shot task; start the session and type messages interactively")

    return parser, args


if __name__ == "__main__":
    parser, args = parse_args()
    task = " ".join(args.task).strip()

    if not args.chat and not task:
        parser.print_help()
        sys.exit(0)

    asyncio.run(
        main(
            task or None,
            use_plan=args.plan,
            use_chat=args.chat,
            session_id=args.session,
        )
    )
