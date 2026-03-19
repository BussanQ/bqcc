"""TriggerFlow workflow for plan-then-execute orchestration."""
from agently import TriggerFlow


def _create_plain_request(agent):
    """Create a request that inherits workspace prompts but skips tool-loop handlers."""
    return agent.create_request(
        inherit_agent_prompt=True,
        inherit_extension_handlers=False,
    )


def _normalize_step_text(step) -> str:
    """Normalize step text so tool-planning JSON is less likely to break on Windows paths."""
    return str(step).replace("\\", "/").strip()


async def run_plan_execute(agent, tool_funcs, task: str, timeout: int = 300) -> str:
    """Execute one task through the plan-then-execute workflow and return the final text."""
    flow, step_results = create_plan_execute_flow(agent, tool_funcs)
    result = await flow.async_start(task, timeout=timeout)
    if result is None:
        result = "\n\n".join(step_results) if step_results else "(no result)"
    return str(result) if result else "(no result)"


def create_plan_execute_flow(agent, tool_funcs):
    """Create a TriggerFlow that plans a task into steps and executes each one.

    Args:
        agent: An Agently agent instance with tools already registered.
        tool_funcs: List of tool functions to use with .use_tools().

    Returns:
        A TriggerFlow ready to start with a task string, and a list ref for results.
    """
    flow = TriggerFlow(name="plan-execute")
    step_results = []

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
        step_index = len(step_results) + 1
        print(f"\n[Step {step_index}] {step}")

        previous_enabled = bool(agent.settings.get("tool.loop.enabled", True))
        previous_max_rounds = agent.settings.get("tool.loop.max_rounds", 5)
        if not isinstance(previous_max_rounds, int) or previous_max_rounds < 0:
            previous_max_rounds = 5

        try:
            agent.set_tool_loop(enabled=True, max_rounds=1)
            result = await (
                agent
                .input(step)
                .instruct(
                    "Execute this step using the available tools. Take action, don't just describe. "
                    "Use workspace-relative file paths with forward slashes only. "
                    "Do not echo Windows absolute paths or backslashes unless the user explicitly asks for them."
                )
                .use_tools(tool_funcs)
                .async_start()
            )
        finally:
            agent.set_tool_loop(enabled=previous_enabled, max_rounds=previous_max_rounds)

        result_text = str(result) if result else "(no output)"
        step_results.append(result_text)
        print(f"[Step {step_index} done]")
        return result_text

    @flow.chunk
    async def collect(data):
        """Collect all step results and set the flow result."""
        final = "\n\n---\n\n".join(
            f"**Step {i+1}:** {r}" for i, r in enumerate(step_results)
        )
        data.set_result(final)
        return final

    # concurrency=1 ensures steps execute sequentially
    flow.to(plan).for_each(concurrency=1).to(execute_step).to(collect)
    return flow, step_results
