from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any


GROQ_MODEL_COSTS = {
    "llama-3.3-70b-versatile": {"input": 0.59, "output": 0.79},
    "llama-3.1-8b-instant": {"input": 0.05, "output": 0.08},
    "qwen/qwen3-32b": {"input": 0.10, "output": 0.20},
    "default": {"input": 0.50, "output": 0.75},
}

COST_PER_1M_TOKENS = 1_000_000


class CostTracker:
    """Registro de costos de API y consumo de tokens."""

    def __init__(self):
        self.calls: list[dict[str, Any]] = []
        self.start_time = time.time()
        self._log_dir = os.path.expanduser("~/.skoll/costs")
        os.makedirs(self._log_dir, exist_ok=True)

    def record(
        self,
        model: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        endpoint: str = "",
        success: bool = True,
    ) -> dict[str, Any]:
        model_costs = GROQ_MODEL_COSTS.get(model, GROQ_MODEL_COSTS["default"])
        input_cost = (input_tokens / COST_PER_1M_TOKENS) * model_costs["input"]
        output_cost = (output_tokens / COST_PER_1M_TOKENS) * model_costs["output"]
        total_cost = input_cost + output_cost

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "unix_ts": time.time(),
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "input_cost": round(input_cost, 6),
            "output_cost": round(output_cost, 6),
            "total_cost": round(total_cost, 6),
            "endpoint": endpoint,
            "success": success,
        }
        self.calls.append(entry)
        return entry

    def summary(self) -> dict[str, Any]:
        total_input = sum(c.get("input_tokens", 0) for c in self.calls)
        total_output = sum(c.get("output_tokens", 0) for c in self.calls)
        total_cost = sum(c.get("total_cost", 0) for c in self.calls)

        by_model: dict[str, dict[str, int | float]] = {}
        for c in self.calls:
            model = c.get("model", "unknown")
            if model not in by_model:
                by_model[model] = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost": 0.0}
            by_model[model]["calls"] += 1  # type: ignore
            by_model[model]["input_tokens"] += c.get("input_tokens", 0)  # type: ignore
            by_model[model]["output_tokens"] += c.get("output_tokens", 0)  # type: ignore
            by_model[model]["cost"] += c.get("total_cost", 0)  # type: ignore

        elapsed = time.time() - self.start_time
        return {
            "total_calls": len(self.calls),
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "total_tokens": total_input + total_output,
            "total_cost_usd": round(total_cost, 6),
            "elapsed_seconds": round(elapsed, 2),
            "by_model": by_model,
            "calls": self.calls[-10:],
        }

    def summary_markdown(self) -> str:
        s = self.summary()
        lines = [
            "# Cost Tracking",
            f"**Total API Calls:** {s['total_calls']}",
            f"**Total Tokens:** {s['total_tokens']:,}",
            f"**Total Cost:** ${s['total_cost_usd']:.6f} USD",
            f"**Elapsed:** {s['elapsed_seconds']:.1f}s",
            "",
            "## By Model",
            "| Model | Calls | Input Tokens | Output Tokens | Cost (USD) |",
            "|-------|-------|-------------|--------------|-----------|",
        ]
        for model, data in s["by_model"].items():
            lines.append(
                f"| {model} | {data['calls']} | {data['input_tokens']:,} | "
                f"{data['output_tokens']:,} | ${data['cost']:.6f} |"
            )
        lines.append("")
        lines.append("## Last 10 Calls")
        for c in s["calls"][-10:]:
            lines.append(
                f"- `{c['model']}` in={c['input_tokens']} out={c['output_tokens']} "
                f"${c['total_cost']:.6f} ({'OK' if c['success'] else 'FAIL'})"
            )
        return "\n".join(lines)

    def save(self, session_id: str = "") -> str:
        path = os.path.join(self._log_dir, f"costs_{session_id or int(time.time())}.json")
        with open(path, "w") as f:
            json.dump(self.summary(), f, indent=2)
        return path
