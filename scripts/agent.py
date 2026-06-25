from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import requests

ROOT = Path(__file__).resolve().parents[1]
SOC_DEFENDER_ROOT = ROOT.parent / "soc_defender"
_AGENT_CACHE: Dict[tuple[Any, ...], Any] = {}


def call_ollama(model: str, messages: List[Dict[str, str]], temperature: float, max_tokens: int) -> str:
    base_url = os.getenv("OLLAMA_BASE_URL")
    if not base_url:
        raise RuntimeError("OLLAMA_BASE_URL not set")
    prompt = "\n\n".join(f"{message.get('role', 'user').upper()}:\n{message.get('content', '')}" for message in messages)
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }
    resp = requests.post(f"{base_url.rstrip('/')}/api/generate", json=payload, timeout=float(os.getenv("OLLAMA_TIMEOUT", "60")))
    resp.raise_for_status()
    return str(resp.json().get("response", ""))


def _latest_observation_from_messages(messages: List[Dict[str, str]]) -> Dict[str, Any]:
    for message in reversed(messages):
        if message.get("role") != "user":
            continue
        content = message.get("content", "")
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        observation = dict(payload)
        if "step_index" not in observation and "step" in observation:
            observation["step_index"] = observation["step"]
        observation["eval_messages"] = messages
        return observation
    raise ValueError("Agent provider could not find an observation JSON message")


def _load_agent_builder():
    if not SOC_DEFENDER_ROOT.exists():
        raise RuntimeError(f"soc_defender package not found at {SOC_DEFENDER_ROOT}")
    root = str(SOC_DEFENDER_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    from defender import build_agent

    return build_agent


def _agent_cache_key(model_cfg: Dict[str, Any], max_steps: int) -> tuple[Any, ...]:
    agent_mode = model_cfg.get("agent_mode", model_cfg.get("name", "evidence_gate_only"))
    return (
        model_cfg.get("name", "evidence_gate_only"),
        agent_mode,
        max_steps,
        model_cfg.get("agent_llm", os.getenv("OPENSEC_AGENT_LLM", "none")),
        model_cfg.get("prompt_guard2_model"),
        bool(model_cfg.get("use_langgraph", False)),
    )


def call_agent(
    model_cfg: Dict[str, Any],
    messages: List[Dict[str, str]],
    temperature: float,
    max_tokens: int,
) -> str:
    observation = _latest_observation_from_messages(messages)
    max_steps = int(observation.get("max_steps") or model_cfg.get("max_steps") or 15)
    cache_key = _agent_cache_key(model_cfg, max_steps)
    agent = _AGENT_CACHE.get(cache_key)
    if agent is None:
        build_agent = _load_agent_builder()
        agent = build_agent(
            mode=model_cfg.get("agent_mode", model_cfg.get("name", "evidence_gate_only")),
            max_steps=max_steps,
            agent_llm=model_cfg.get("agent_llm", os.getenv("OPENSEC_AGENT_LLM", "none")),
            prompt_guard2_model=model_cfg.get("prompt_guard2_model"),
            use_langgraph=bool(model_cfg.get("use_langgraph", False)),
        )
        _AGENT_CACHE[cache_key] = agent

    if hasattr(agent, "act"):
        action = agent.act(observation)
    elif hasattr(agent, "next_action"):
        action = agent.next_action(observation)
    else:
        raise TypeError("Agent must expose act(observation) or next_action(observation)")
    return json.dumps(action)
