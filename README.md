# AgentlyBq

AgentlyBq 是一个基于 Agently 的命令行 Agent 原型，集成了 workspace prompt、工具调用、记忆管理和 TriggerFlow 计划执行。

当前项目支持：

- 单次任务执行
- `--plan` 计划后执行模式
- `--chat` 多轮对话模式
- `--session` 会话恢复
- workspace prompt 注入
- 每日日志、长期记忆、会话落盘
- 文件、搜索、Shell、memory 等内置工具

## 功能概览

### 1. 单次任务模式
直接执行一条任务，让 Agent 按当前 prompt 和工具配置完成一次性请求。

### 2. Plan-then-execute 模式
通过 TriggerFlow 先把任务拆成 3–5 个步骤，再逐步执行，并在最后汇总成面向用户的简洁答复。

### 3. 多轮对话模式
进入 REPL 式交互会话，支持：

- 保存/恢复会话
- 在对话中动态开关 plan 模式
- 将对话历史写入 session JSON

### 4. 记忆系统
项目内置两类持久化记忆：

- `memory/YYYY-MM-DD.md`：每日任务与结果摘要
- `memory/MEMORY.md`：长期记忆

### 5. Workspace Prompt
启动时会自动加载以下 prompt 资源并注入 Agent：

- `workspace/SOUL.md`
- `workspace/AGENT.md`
- `workspace/USER.md`
- `workspace/TOOLS.md`
- `.agent/rules/*.md`
- `.agent/skills/*.json`

## 项目结构

```text
AgentlyBq/
├─ bqcc.py                  # CLI 入口
├─ SETTINGS.yaml            # 模型配置（支持 ${ENV.xxx}）
├─ .env.example             # 环境变量示例
├─ workflow/
│  ├─ chat_mode.py          # 多轮对话模式
│  └─ plan_execute.py       # TriggerFlow 计划执行
├─ services/
│  ├─ memory_manager.py     # 每日日志 / 长期记忆
│  ├─ session_store.py      # 会话 JSON 持久化
│  ├─ workspace_loader.py   # workspace / rules / skills 加载
│  └─ output_cleaner.py     # 输出清洗
├─ tools/
│  ├─ file_ops.py           # 文件读写编辑
│  ├─ search_ops.py         # glob / grep
│  ├─ shell_ops.py          # shell 命令
│  └─ memory_ops.py         # memory 读写搜索
├─ workspace/               # 常驻 prompt
└─ memory/                  # 运行期记忆与会话
```

## 安装

先准备一个可用的 Python 环境，再安装项目依赖。当前代码至少依赖：

- Agently
- PyYAML
- python-dotenv（可选，但推荐，用于自动加载 `.env`）

示例：

```bash
pip install agently pyyaml python-dotenv
```

## 配置模型

1. 复制环境变量模板：

```bash
cp .env.example .env
```

2. 编辑 `.env`：

```env
OPENAI_API_KEY=your-api-key-here
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o-mini
```

3. `SETTINGS.yaml` 会通过 `${ENV.xxx}` 读取这些变量，并把模型配置写入：

- `plugins.ModelRequester.OpenAICompatible.base_url`
- `plugins.ModelRequester.OpenAICompatible.auth`
- `plugins.ModelRequester.OpenAICompatible.model`

如果没有安装 `python-dotenv`，程序也会在启动时尝试手动读取根目录下的 `.env`。

## 使用方式

### 单次任务

```bash
python bqcc.py "总结当前项目结构"
```

### 单次任务 + 计划执行

```bash
python bqcc.py --plan "排查 workflow/plan_execute.py 的问题"
```

### 启动多轮对话

```bash
python bqcc.py --chat
```

### 恢复指定会话

```bash
python bqcc.py --chat --session my-session
```

### 对话模式下默认启用计划执行

```bash
python bqcc.py --chat --plan
```

## 对话模式命令

进入 `--chat` 后可用命令：

- `/help`：显示帮助
- `/clear`：清空当前会话历史
- `/plan on`：为后续每轮消息启用 plan 模式
- `/plan off`：关闭 plan 模式
- `/exit`：保存并退出
- `/quit`：保存并退出

## 可用工具

启动后会注册以下工具：

- `read`
- `write`
- `edit`
- `glob`
- `grep`
- `shell`
- `mem_get`
- `mem_save`
- `mem_search`

这些工具由 [tools/](tools/) 下的实现提供，并在 [tools/__init__.py](tools/__init__.py) 中统一注册。

## Memory 与 Session 落盘

### Memory

- 每日记录：`memory/YYYY-MM-DD.md`
- 长期记忆：`memory/MEMORY.md`

### Session

- 会话文件目录：`memory/sessions/`
- 文件名格式：`<session_id>.json`

会话 ID 会经过清洗，非法字符会被替换，以便安全保存到文件系统。

## 输出清洗

项目会在输出和会话保存前做一层清洗，用来：

- 去掉 `<think>...</think>` 这类推理噪声
- 规范化已保存的聊天历史
- 让 `--plan` 的最终输出更适合作为面向用户的答复

## 说明

- Windows 下会在启动时把标准输出/错误切换为 UTF-8 包装，减少中文乱码问题。
- `--plan` 模式会使用 TriggerFlow 顺序执行步骤，而不是把内部步骤直接暴露为最终答复。
- `.gitignore` 当前忽略 `memory/` 下的大多数运行期文件，但保留跟踪 `memory/MEMORY.md`。

## 快速示例

```bash
# 直接执行一个任务
python bqcc.py "读取 bqcc.py 并说明入口流程"

# 用计划执行模式分析问题
python bqcc.py --plan "检查 chat mode 如何保存 session"

# 开启一个可恢复的聊天会话
python bqcc.py --chat --session demo
```

## 后续可扩展方向

- 增加 requirements / pyproject 以固定依赖
- 为常用任务补充 `.agent/skills`
- 接入更多 MCP 工具
- 为 plan 模式增加更细粒度的执行与观察能力
