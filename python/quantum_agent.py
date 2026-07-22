# python/quantum_agent.py
import sys, json, os, asyncio
from sdk.llm_manager import LLMManager

# Legacy prompt maintained for compatibility
SYSTEM_PROMPT = """You are QuantumBlue, an AI agent for post-quantum cybersecurity.
Provide expert analysis in JSON: {"thought": "...", "action": "predict|analyze|harden|scan|sign|none", "data": {...}}
"""
CONFIG_PATH = os.path.expanduser("~/.quantumblue_llm_config.json")

def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f: return json.load(f)
        except: pass
    return {"provider": "openrouter", "model": "gpt-4o", "context": []}

def save_config(config):
    with open(CONFIG_PATH, "w") as f: json.dump(config, f)

LLM_CONFIG = load_config()
# Initialize the new LLMManager
llm_manager = LLMManager()

def handle_meta_command(command: str) -> dict:
    """Handles LLM configuration and meta commands."""
    cmd_lower = command.lower()
    if "switch provider" in cmd_lower:
        LLM_CONFIG["provider"] = command.split("to")[-1].strip()
    elif "set model" in cmd_lower:
        LLM_CONFIG["model"] = command.split("model")[-1].strip()
    elif "clear context" in cmd_lower:
        LLM_CONFIG["context"] = []
    else: return {"status": "info", "message": "Command processed", "config": LLM_CONFIG}
    save_config(LLM_CONFIG)
    # Update manager config if needed
    llm_manager.config = LLM_CONFIG
    return {"status": "success", "message": f"Updated: {LLM_CONFIG['provider']} / {LLM_CONFIG['model']}"}

async def run_query(task: str):
    """Unified query entrypoint using LLMManager."""
    response = await llm_manager.route_request(task)
    # Update global config with context changes made by manager
    save_config(llm_manager.config)
    return response

def main():
    if len(sys.argv) < 2: sys.exit(1)
    task = " ".join(sys.argv[1:])
    if "--meta" in sys.argv:
        print(json.dumps(handle_meta_command(task.replace("--meta", "").strip()), indent=2))
        return

    # Use the new async query handler
    result = asyncio.run(run_query(task))
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
