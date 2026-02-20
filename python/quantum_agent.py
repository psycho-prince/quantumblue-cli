# python/quantum_agent.py
import sys, json, os, requests
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

SYSTEM_PROMPT = """You are QuantumBlue, an AI agent for post-quantum cybersecurity.
Provide expert analysis in JSON: {"thought": "...", "action": "predict|analyze|harden|scan|sign|none", "data": {...}}
"""
CONFIG_PATH = os.path.expanduser("~/.quantumblue_llm_config.json")

def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f: return json.load(f)
        except: pass
    return {"provider": "groq", "model": "llama3-70b-8192", "context": []}

def save_config(config):
    with open(CONFIG_PATH, "w") as f: json.dump(config, f)

LLM_CONFIG = load_config()

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
    return {"status": "success", "message": f"Updated: {LLM_CONFIG['provider']} / {LLM_CONFIG['model']}"}

def query_huggingface(task: str):
    token = os.environ.get("HF_TOKEN")
    if not token: return {"error": "HF_TOKEN env var missing. Use your own token or access our tokens via a paid plan."}
    
    messages = [{"role": "system", "content": SYSTEM_PROMPT}] + LLM_CONFIG["context"] + [{"role": "user", "content": task}]
    
    try:
        if OpenAI:
            client = OpenAI(base_url="https://router.huggingface.co/v1", api_key=token)
            res = client.chat.completions.create(model=LLM_CONFIG["model"], messages=messages)
            content = res.choices[0].message.content
        else:
            # Fallback to requests if openai not installed
            url = f"https://router.huggingface.co/v1/chat/completions"
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            payload = {"model": LLM_CONFIG["model"], "messages": messages}
            res = requests.post(url, headers=headers, json=payload)
            res.raise_for_status()
            content = res.json()["choices"][0]["message"]["content"]

        LLM_CONFIG["context"].append({"role": "user", "content": task})
        LLM_CONFIG["context"].append({"role": "assistant", "content": content})
        save_config(LLM_CONFIG)
        try: return json.loads(content)
        except: return {"thought": "Response received", "action": "none", "data": {"response": content}}
    except Exception as e: return {"error": str(e)}

def main():
    if len(sys.argv) < 2: sys.exit(1)
    task = " ".join(sys.argv[1:])
    if "--meta" in sys.argv:
        print(json.dumps(handle_meta_command(task.replace("--meta", "").strip()), indent=2))
        return

    if LLM_CONFIG["provider"] == "huggingface":
        print(json.dumps(query_huggingface(task), indent=2))
    else:
        print(json.dumps({"thought": "Mocking " + LLM_CONFIG['provider'], "action": "none", "data": {"task": task}}, indent=2))

if __name__ == "__main__":
    main()
