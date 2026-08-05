"""Base agent class — shared agentic loop for all agents."""

import sys

import anthropic

# Fix Windows terminal encoding
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

MODEL = "claude-sonnet-4-6"


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
        self.model = MODEL
        self.max_iterations = 20

    def run(self, task: str, state: dict) -> str:
        """Run the agentic loop. Returns the final text response.

        Args:
            task: The task description to send to the agent.
            state: State dict available for subclass use; not consumed by the base class.
        """
        messages = [{"role": "user", "content": task}]

        print(f"\n[{self.name}] Starting — {task[:80]}")

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
                return f"ERROR: {e}"

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                result = ""
                for block in response.content:
                    if block.type == "text":
                        result += block.text
                print(f"[{self.name}] Done ({iteration} iterations)")
                return result

            # Execute tool calls
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    fn_name = block.name
                    fn_args = block.input

                    print(f"  [{self.name}] -> {fn_name}({', '.join(f'{k}={v!r}' for k, v in fn_args.items())})")

                    if fn_name in self.tool_dispatch:
                        result = self.tool_dispatch[fn_name](**fn_args)
                    else:
                        result = f"Unknown tool: {fn_name}"

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": str(result),
                    })

            if tool_results:
                messages.append({"role": "user", "content": tool_results})

        print(f"[{self.name}] WARNING: max iterations reached")
        return "Max iterations reached without final response."
