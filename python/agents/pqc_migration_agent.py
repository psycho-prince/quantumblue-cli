# python/agents/pqc_migration_agent.py
import json
from .codeagent import CodeAgent
from sdk.llm_manager import LLMManager

class PQCMigrationAgent(CodeAgent):
    """
    Orchestrates the migration of legacy systems to PQC standards
    by implementing Layer 1 (Inventory) and Layer 4 (Compliance) 
    of the AI-Assisted Governance Framework.
    """
    def __init__(self):
        super().__init__()
        self.llm_manager = LLMManager()

    async def run_inventory_scan(self, project_path: str):
        """
        Layer 1: Automated Cryptographic Inventory.
        Scans code for classical crypto artifacts (RSA/ECC)
        and outputs a compliance mapping.
        """
        # Orchestrate existing recon tools via LLMManager
        task = f"Analyze the project at {project_path} for classical cryptographic primitives (RSA/ECC). Generate a mapping for PQC migration."
        result = await self.llm_manager.route_request(task)
        
        # Structure the output for governance dashboard consumption
        report = {
            "phase": "Layer 1: Inventory",
            "findings": result.get("data", {}).get("findings", []),
            "remediation_priority": result.get("data", {}).get("priority", "medium")
        }
        return report

    async def propose_remediation(self, inventory_report: dict):
        """
        Layer 4: Automated Remediation.
        Uses LLMManager to propose PQC-agile wrappers for identified risks.
        """
        task = f"Propose PQC-agile code wrappers for the following inventory: {json.dumps(inventory_report)}"
        result = await self.llm_manager.route_request(task)
        return result
