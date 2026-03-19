"""Interactive chat mode for AgentlyBq."""
from collections.abc import Awaitable, Callable

from services.output_cleaner import sanitize_assistant_output, sanitize_chat_history
from services.session_store import SessionStore
from workflow.plan_execute import run_plan_execute


SESSION_MAX_LENGTH = 12000
HELP_TEXT = """Commands:
  /help      Show this help
  /clear     Clear current chat history
  /plan on   Enable plan mode for each turn
  /plan off  Disable plan mode for each turn
  /exit      Save and exit
  /quit      Save and exit
"""


def _sanitize_active_session(agent):
    """Rewrite stored chat history to remove reasoning noise."""
    if agent.activated_session is None:
        return
    cleaned_history = sanitize_chat_history(agent.activated_session.full_context)
    agent.set_chat_history(cleaned_history)


async def _run_planned_chat_turn(agent, tool_funcs, task: str) -> str:
    """Run one planned turn without polluting session history with internal steps."""
    if agent.activated_session is None:
        return await run_plan_execute(agent, tool_funcs, task)

    session_id = agent.activated_session.id
    agent.deactivate_session()
    try:
        result = await run_plan_execute(agent, tool_funcs, task)
    finally:
        agent.activate_session(session_id=session_id)

    agent.add_chat_history(
        [
            {"role": "user", "content": task},
            {"role": "assistant", "content": result},
        ]
    )
    _sanitize_active_session(agent)
    return result


def _print_session_banner(session_id: str, resumed: bool, default_use_plan: bool):
    state = "resumed" if resumed else "started"
    plan_state = "on" if default_use_plan else "off"
    print("\n[Mode] Chat conversation")
    print(f"[Session] {session_id} ({state})")
    print(f"[Plan] {plan_state}")
    print("[Commands] /help /clear /plan on /plan off /exit /quit")


async def run_chat_mode(
    *,
    agent,
    tool_funcs,
    default_use_plan: bool = False,
    session_id: str | None = None,
    on_turn_complete: Callable[[str, str], Awaitable[None]] | None = None,
):
    """Start an interactive multi-turn chat loop."""
    store = SessionStore()
    final_session_id = store.create_session_id(session_id)

    agent.settings.set("session.input_keys", "input")
    agent.settings.set("session.max_length", SESSION_MAX_LENGTH)
    agent.activate_session(session_id=final_session_id)

    resumed = False
    if agent.activated_session is not None:
        resumed = store.load(agent.activated_session, final_session_id)

    _print_session_banner(final_session_id, resumed, default_use_plan)

    while True:
        try:
            user_input = input("\nYou> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[Chat] Saving session and exiting...")
            break

        if not user_input:
            continue

        lowered = user_input.lower()
        if lowered in {"/exit", "/quit"}:
            print("[Chat] Saving session and exiting...")
            break
        if lowered == "/help":
            print(HELP_TEXT)
            continue
        if lowered == "/clear":
            agent.reset_chat_history()
            if agent.activated_session is not None:
                store.save(agent.activated_session)
            print("[Chat] Cleared session history.")
            continue
        if lowered == "/plan on":
            default_use_plan = True
            print("[Chat] Plan mode enabled.")
            continue
        if lowered == "/plan off":
            default_use_plan = False
            print("[Chat] Plan mode disabled.")
            continue
        if user_input.startswith("/"):
            print("[Chat] Unknown command. Use /help to see available commands.")
            continue

        try:
            if default_use_plan:
                result_text = await _run_planned_chat_turn(agent, tool_funcs, user_input)
            else:
                result = await agent.input(user_input).use_tools(tool_funcs).async_start()
                result_text = sanitize_assistant_output(result)
                _sanitize_active_session(agent)
        except Exception as e:
            result_text = f"Error: {e}"
            if agent.activated_session is not None:
                agent.add_chat_history(
                    [
                        {"role": "user", "content": user_input},
                        {"role": "assistant", "content": result_text},
                    ]
                )
                _sanitize_active_session(agent)

        print(f"\nAssistant> {result_text}")

        if on_turn_complete is not None:
            await on_turn_complete(user_input, result_text)
        if agent.activated_session is not None:
            store.save(agent.activated_session)

    if agent.activated_session is not None:
        path = store.save(agent.activated_session)
        print(f"[Chat] Session saved to {path}")
