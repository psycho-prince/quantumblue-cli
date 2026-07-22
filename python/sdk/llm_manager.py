import os
import json
import logging
from typing import Dict, Any

# Mocking or assuming availability of omni_router
# Since I need to integrate the local repo, I need to make sure the paths are correct.
# Assuming 'omni_router' will be added to the python path.
try:
    from omni_router.core.provider_router import ProviderRouter
    from omni_router.persistence.database import DatabaseManager
except ImportError:
    # Handle the case where omni_router isn't installed/importable yet
    ProviderRouter = None
    DatabaseManager = None

logger = logging.getLogger("QuantumBlueLLMManager")

class LLMManager:
    def __init__(self, config_path: str = "~/.quantumblue_llm_config.json"):
        self.config_path = os.path.expanduser(config_path)
        self.config = self._load_config()
        self.router = self._initialize_router()

    def _load_config(self) -> Dict[str, Any]:
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Could not load config: {e}")
        return {"provider": "openrouter", "model": "gpt-4o", "context": []}

    def _initialize_router(self):
        if not ProviderRouter or not DatabaseManager:
            logger.error("Omni-router dependencies not found.")
            return None
        
        # Initialize DB and Router
        db_path = os.path.expanduser("~/.quantum_router.db")
        db = DatabaseManager(db_path=db_path)
        return ProviderRouter(db)

    async def route_request(self, task: str) -> Dict[str, Any]:
        if not self.router:
            return {"error": "Router not initialized"}

        # Prepare request for router
        request = {
            "task": task,
            "model": self.config.get("model"),
            "provider": self.config.get("provider"),
            "context": self.config.get("context")
        }

        try:
            # This calls the omni-router logic
            response = await self.router.route_request(request)
            
            # Update local context (simplified for now)
            self.config["context"].append({"role": "user", "content": task})
            self.config["context"].append({"role": "assistant", "content": response.get("content")})
            
            return response
        except Exception as e:
            return {"error": str(e)}
