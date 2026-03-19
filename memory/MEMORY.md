# Long-term Memory

Durable facts, patterns, and preferences learned from interactions.

- [2026-03-20 01:30] User prefers Chinese language interaction.

- [2026-03-20 01:54] [2026-03-20] Project codebase is named 'AgentlyBq' - an Agently-powered CLI agent framework with 3-layer architecture: workflow (chat_mode, plan_execute), services (memory, session, workspace, output), and tools (file, memory, search, shell). Main entry point is bqcc.py. Supports plan-then-execute mode via TriggerFlow.

- [2026-03-20 02:01] bqcc.py supports two modes: --chat (default interactive) and --plan (TriggerFlow-based plan-execute), with --session for resuming sessions.

- [2026-03-20 02:05] bqcc.py supports both single task mode (`python bqcc.py <task>`) and interactive chat mode (`python bqcc.py --chat`), with --plan flag available for both. MemoryManager handles both long-term memory and daily context.

- [2026-03-20 02:09] bqcc.py 入口点使用 asyncio.run(main(...))，main() 通过 bootstrap_agent() 初始化 Agent，该函数依次执行 load_settings() → Agently.create_agent() → load workspace/rules/skills → MemoryManager() → register_tools()，然后根据 use_chat 参数分流至 run_chat_mode() 或其他模式。
