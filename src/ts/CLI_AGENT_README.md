# CLI Agent Architecture & Usage

This document provides a detailed explanation of the `claw-cli-agent` autonomous agent, including its architecture, security model, and usage instructions.

## Agent Loop

The agent's operation follows a strict, five-stage loop to ensure security and predictability:

1.  **Input:** The agent receives a high-level task from the user via the command-line interface.
2.  **Plan:** A Large Language Model (LLM) planner (e.g., Gemini CLI) receives the task and decomposes it into a structured series of discrete, low-level actions. This plan is returned as a JSON object adhering to the Intent Schema.
3.  **Policy:** The agent's security policy engine intercepts the plan. Each proposed action is rigorously validated against a set of allow-listed, predefined capabilities and the Intent Schema. If any action is not recognized or violates the policy, the entire plan is rejected before execution.
4.  **Execute:** If the plan is approved, the executor module runs each action one by one. **Execution is sandboxed, auditable, and requires explicit user confirmation for sensitive actions (e.g., sending messages).** The executor operates with minimal privileges and controls a browser session (Web Bridge).

    **Execution is sandboxed and read-only by design.**
5.  **Audit:** The outcome of the execution, along with the original task and plan, is logged to ensure traceability and transparency.

## Architecture Overview

*   **CLI Entrypoint (`agent-cli/src/index.ts`):** Parses user commands and initiates the agent loop.
*   **Planner (Gemini CLI):** External tool. Interprets user intent and generates structured JSON plans based on the Intent Schema.
*   **Agent (`agent-cli/src/agent.ts`):** Orchestrates the `input \u2192 plan \u2192 policy \u2192 execute \u2192 audit` flow.
*   **Intent Schema (`agent-cli/src/intent-schema.ts`):** Defines the strict data structure for actions to be executed by the agent.
*   **Policy (`agent-cli/src/policy.ts`):** The security core. Defines and enforces the set of permissible actions and validates against the Intent Schema.
*   **Web Executor (`agent-cli/src/web-executor.ts`):** Controls a browser (Playwright) to perform web automation tasks. This module is isolated and requires user approval for sensitive actions.

## Security Rationale

The agent is built with a security-first mindset. Its primary goal is to prevent the LLM from causing unintended side effects and to ensure user control over web automation.

*   The agent **NEVER** executes raw shell commands directly.
*   All actions are constrained by a rigid, auditable policy.
*   **Browser automation is strictly limited to authenticated web sessions.**
*   **Explicit user confirmation is MANDATORY** before any message sending or other sensitive web actions.
*   The agent cannot modify its own source code or security policies.
*   No bulk sending and no background execution without explicit policy overrides.

## CLI Usage Examples

**Prerequisites:** Node.js, npm, and Playwright installed. Gemini CLI set up for planning.

1.  **Install & Build:**
    ```bash
    # Navigate to the agent's directory
    cd agent-cli

    # Install dependencies (including playwright)
    npm install

    # Build the project
    npm run build
    ```

2.  **Web Login (one-time setup per platform):**
    ```bash
    # For WhatsApp Web
    node dist/index.js web login whatsapp_web

    # For Instagram Web
    node dist/index.js web login instagram_web
    ```
    This will launch a browser for you to manually log in. Session cookies will be stored.

3.  **Check Web Status:**
    ```bash
    node dist/index.js web status
    ```
    This will show if you are logged in to the web platforms.

4.  **Execute the Agent:**
    Run the CLI command with a natural language task. The Gemini CLI (planner) will interpret this and generate a plan.

    ```bash
    # Example: Send a message on WhatsApp Web
    node dist/index.js do \send a reply on WhatsApp Web to Alice saying Hello!\

    # Example: Draft a message on Instagram Web
    node dist/index.js do \draft a message on Instagram Web to Bob with content Great post!\
    ```
    The agent will pause and ask for confirmation before executing the final `send_message` action.

