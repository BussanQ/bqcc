"""Workspace loader — loads AGENT.md, SOUL.md, USER.md, TOOLS.md and .agent/rules into prompt slots."""
import os
import json
from pathlib import Path

WORKSPACE_DIR = "workspace"
RULES_DIR = os.path.join(".agent", "rules")
SKILLS_DIR = os.path.join(".agent", "skills")
WORKSPACE_FILES = ["AGENT.md", "SOUL.md", "USER.md", "TOOLS.md"]


async def load_workspace() -> dict[str, str]:
    """Load all workspace markdown files. Returns {filename: content}."""
    result = {}
    for fname in WORKSPACE_FILES:
        fpath = os.path.join(WORKSPACE_DIR, fname)
        if os.path.exists(fpath):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                if content:
                    result[fname] = content
            except Exception:
                pass
    return result


async def load_rules() -> str:
    """Load all .agent/rules/*.md files and concatenate them."""
    if not os.path.exists(RULES_DIR):
        return ""
    parts = []
    for rule_file in sorted(Path(RULES_DIR).glob("*.md")):
        try:
            with open(rule_file, "r", encoding="utf-8") as f:
                parts.append(f"# {rule_file.stem}\n{f.read()}")
        except Exception:
            continue
    return "\n\n".join(parts)


async def load_skills() -> list[dict]:
    """Load all .agent/skills/*.json skill definitions."""
    if not os.path.exists(SKILLS_DIR):
        return []
    skills = []
    for skill_file in sorted(Path(SKILLS_DIR).glob("*.json")):
        try:
            with open(skill_file, "r", encoding="utf-8") as f:
                skills.append(json.load(f))
        except Exception:
            continue
    return skills


def inject_workspace(agent, workspace: dict[str, str], rules: str = "", skills: list[dict] = None):
    """Inject workspace content into agent prompt slots (always=True for persistence across requests)."""
    if "SOUL.md" in workspace:
        agent.info(f"[Persona]\n{workspace['SOUL.md']}", always=True)
    if "AGENT.md" in workspace:
        agent.instruct(workspace["AGENT.md"], always=True)
    if "USER.md" in workspace:
        agent.info(f"[User Context]\n{workspace['USER.md']}", always=True)
    if "TOOLS.md" in workspace:
        agent.info(f"[Tools Guidance]\n{workspace['TOOLS.md']}", always=True)
    if rules:
        agent.info(f"[Rules]\n{rules}", always=True)
    if skills:
        skill_desc = "\n".join(
            f"- {s.get('name', '?')}: {s.get('description', '')}"
            for s in skills
        )
        agent.info(f"[Available Skills]\n{skill_desc}", always=True)
