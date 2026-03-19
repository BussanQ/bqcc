"""TriggerFlow workflow for plan-then-execute orchestration."""
from agently import TriggerFlow

from services.output_cleaner import sanitize_assistant_output


SUMMARY_STEP_CHAR_LIMIT = 3000


def _create_plain_request(agent):
    """Create a request that inherits workspace prompts but skips tool-loop handlers."""
    return agent.create_request(
        inherit_agent_prompt=True,
        inherit_extension_handlers=False,
    )


def _normalize_step_text(step) -> str:
    """Normalize step text so tool-planning JSON is less likely to break on Windows paths."""
    return str(step).replace("\\", "/").strip()


def _clip_text(text: str, limit: int = SUMMARY_STEP_CHAR_LIMIT) -> str:
    """Trim oversized step outputs before sending them into the final summarizer."""
    text = text.strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit].rstrip()}\n...(truncated)"


def _format_step_trace(step_records) -> str:
    """Format the raw step results for debugging or fallback output."""
    if not step_records:
        return "(no result)"
    return "\n\n---\n\n".join(
        f"**Step {i+1}:** {entry.get('result', '(no output)')}"
        for i, entry in enumerate(step_records)
    )


def _build_summary_context(step_records) -> str:
    """Build a compact plain-text summary context from executed steps."""
    sections: list[str] = []
    for i, entry in enumerate(step_records, 1):
        step_text = _normalize_step_text(entry.get("step", ""))
        result_text = sanitize_assistant_output(entry.get("result", ""), fallback="(no output)")
        sections.append(
            f"Step {i}\n"
            f"Task: {step_text or '(unspecified)'}\n"
            f"Result:\n{_clip_text(result_text)}"
        )
    return "\n\n".join(sections)


async def _summarize_step_results(agent, task: str, step_records) -> str:
    """Turn internal step execution results into a concise user-facing answer."""
    fallback = _format_step_trace(step_records)
    if not step_records:
        return fallback

    request = _create_plain_request(agent)
    result = await (
        request
        .input(
            f"User task:\n{task}\n\n"
            f"Executed step results:\n{_build_summary_context(step_records)}"
        )
        .instruct(
            "Write the final reply to the user based only on the executed step results. "
            "Be concise and direct. Match the user's language. "
            "Do not mention internal planning, step numbers, or tool calls unless they are directly useful. "
            "If the task asked for a summary or explanation, provide it plainly. "
            "If the results are incomplete or inconsistent, say what is confirmed and what is still unclear. "
            "Do not invent facts."
        )
        .async_start()
    )
    return sanitize_assistant_output(result, fallback=fallback)


async def run_plan_execute(agent, tool_funcs, task: str, timeout: int = 300) -> str:
    """Execute one task through the plan-then-execute workflow and return the final text."""
    flow, step_records = create_plan_execute_flow(agent, tool_funcs)
    await flow.async_start(task, timeout=timeout)
    try:
        return await _summarize_step_results(agent, task, step_records)
    except Exception as e:
        print(f"[Plan] Final summarization skipped: {e}")
        return _format_step_trace(step_records)


def create_plan_execute_flow(agent, tool_funcs):
    """Create a TriggerFlow that plans a task into steps and executes each one.

    Args:
        agent: An Agently agent instance with tools already registered.
        tool_funcs: List of tool functions to use with .use_tools().

    Returns:
        A TriggerFlow ready to start with a task string, and a list ref for results.
    """
    flow = TriggerFlow(name="plan-execute")
    step_records = []

    @flow.chunk
    async def plan(data):
        """Break the task into 3-5 concrete steps."""
        task = data.value
        print(f"[Plan] Breaking down: {task}")
        request = _create_plain_request(agent)
        result = await (
            request
            .input(task)
            .instruct(
                "Break this task into 3-5 concrete, actionable steps. "
                "Use workspace-relative file paths with forward slashes only, like workflow/plan_execute.py. "
                "Never include Windows absolute paths or backslashes. "
                "Do not include placeholder values like <line>. "
                "Each step must be independently executable without relying on hidden results from previous steps. "
                "Each step should be small enough to complete in a single tool-planning round."
            )
            .output({
                "steps": ([str], "list of concise step descriptions using relative forward-slash paths"),
            })
            .async_start()
        )
        raw_steps = result.get("steps", [task]) if isinstance(result, dict) else [task]
        steps = [_normalize_step_text(step) for step in raw_steps if str(step).strip()]
        if not steps:
            steps = [_normalize_step_text(task)]
        print(f"[Plan] Created {len(steps)} steps:")
        for i, s in enumerate(steps, 1):
            print(f"  {i}. {s}")
        return steps

    @flow.chunk
    async def execute_step(data):
        """Execute a single step using the agent with tools."""
        step = _normalize_step_text(data.value)
        step_index = len(step_records) + 1
        print(f"\n[Step {step_index}] {step}")

        previous_enabled = bool(agent.settings.get("tool.loop.enabled", True))
        previous_max_rounds = agent.settings.get("tool.loop.max_rounds", 5)
        if not isinstance(previous_max_rounds, int) or previous_max_rounds < 0:
            previous_max_rounds = 5

        try:
            agent.set_tool_loop(enabled=True, max_rounds=2)
            result = await (
                agent
                .input(step)
                .instruct(
                    "Execute this step using the available tools when needed. Take action, don't just describe. "
                    "If you need file or search data, actually call the tool and use its result before answering. "
                    "Return only the grounded result of the step. "
                    "Never output pseudo tool-call markup like [TOOL_CALL], <tool_call>, or <file_read>. "
                    "Use workspace-relative file paths with forward slashes only. "
                    "Do not echo Windows absolute paths or backslashes unless the user explicitly asks for them."
                )
                .use_tools(tool_funcs)
                .async_start()
            )
        finally:
            agent.set_tool_loop(enabled=previous_enabled, max_rounds=previous_max_rounds)

        result_text = sanitize_assistant_output(result, fallback="(no output)")
        step_records.append({"step": step, "result": result_text})
        print(f"[Step {step_index} done]")
        return result_text

    @flow.chunk
    async def collect(data):
        """Collect all step results and set the flow result."""
        final = _format_step_trace(step_records)
        data.set_result(final)
        return final

    # concurrency=1 ensures steps execute sequentially
    flow.to(plan).for_each(concurrency=1).to(execute_step).to(collect)
    return flow, step_records
