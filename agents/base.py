"""Base agent class — shared agentic loop for all agents."""

import os
import sys

import anthropic

# Fix Windows terminal encoding
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

DEFAULT_MODEL = "claude-sonnet-4-6"       # routine agents + orchestrator routing
STRONG_MODEL = "claude-opus-5"            # reasoning-heavy categories
STRONG_AGENTS = {"crypto", "reversing", "blockchain", "exploit"}


def get_model(agent_name: str = None) -> str:
    """Resolve the model id for an agent (or the orchestrator when agent_name is None).

    Precedence, most specific first:
      1. RECON_MODEL_<AGENT>   — per-agent override (e.g. RECON_MODEL_CRYPTO)
      2. RECON_MODEL           — global override forcing one model everywhere
      3. per-tier default      — STRONG_AGENTS use RECON_STRONG_MODEL/opus-5;
                                 everything else uses DEFAULT_MODEL/sonnet-4-6
    """
    if agent_name:
        specific = os.getenv(f"RECON_MODEL_{agent_name.upper()}")
        if specific:
            return specific
    global_override = os.getenv("RECON_MODEL")
    if global_override:
        return global_override
    if agent_name in STRONG_AGENTS:
        return os.getenv("RECON_STRONG_MODEL", STRONG_MODEL)
    return DEFAULT_MODEL


class BaseAgent:
    def __init__(
        self,
        name: str,
        system_prompt: str,
        tools: list[dict],
        tool_dispatch: dict[str, callable],
        client: anthropic.Anthropic,
    ):
        self.name = name
        self.system_prompt = system_prompt
        self.tools = tools
        self.tool_dispatch = tool_dispatch
        self.client = client
        self.model = get_model(name)
        self.max_iterations = 40

    def run(self, task: str, state: dict) -> str:
        """Run the agentic loop. Returns the final text response.

        Args:
            task: The task description to send to the agent.
            state: State dict available for subclass use; not consumed by the base class.
        """
        messages = [{"role": "user", "content": task}]

        print(f"\n[{self.name}] Starting — {task[:80]}")

        last_text = ""  # most recent text, kept so partial progress is never lost

        for iteration in range(1, self.max_iterations + 1):
            print(f"[{self.name}] Iteration {iteration}")

            try:
                response = self.client.messages.create(
                    model=self.model,
                    system=self.system_prompt,
                    messages=messages,
                    tools=self.tools if self.tools else anthropic.NOT_GIVEN,
                    max_tokens=4096,
                )
            except Exception as e:
                print(f"[{self.name}] ERROR: API call failed: {e}")
                # Preserve any progress instead of discarding it on a late error.
                return last_text + f"\n[ERROR: {e}]" if last_text else f"ERROR: {e}"

            messages.append({"role": "assistant", "content": response.content})

            turn_text = "".join(b.text for b in response.content if b.type == "text")
            if turn_text:
                last_text = turn_text

            if response.stop_reason == "end_turn":
                print(f"[{self.name}] Done ({iteration} iterations)")
                return turn_text

            # Execute tool calls. A tool that raises must NOT crash the agent —
            # capture the error as the tool result and let the model react.
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    fn_name = block.name
                    fn_args = block.input

                    print(f"  [{self.name}] -> {fn_name}({', '.join(f'{k}={v!r}' for k, v in fn_args.items())})")

                    try:
                        if fn_name in self.tool_dispatch:
                            result = self.tool_dispatch[fn_name](**fn_args)
                        else:
                            result = f"Unknown tool: {fn_name}"
                    except Exception as e:
                        result = f"ERROR: tool '{fn_name}' raised: {e}"

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": str(result),
                    })

            if tool_results:
                messages.append({"role": "user", "content": tool_results})
            else:
                # Not end_turn and no tool call (e.g. a max_tokens truncation):
                # there is nothing to send back. Return what we have rather than
                # looping to send a message that ends on an assistant turn.
                print(f"[{self.name}] Stopped early (stop_reason={response.stop_reason}) with no tool call.")
                return last_text or f"(stopped: stop_reason={response.stop_reason})"

        print(f"[{self.name}] WARNING: max iterations reached")
        return last_text or "Max iterations reached without final response."
