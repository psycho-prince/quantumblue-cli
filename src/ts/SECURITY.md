# Security Policy

This document outlines the security posture, threat model, and safe usage expectations for `claw-cli-agent`. This project prioritizes a "security-first" approach to autonomous agent execution.

## Threat Model

The primary threat this agent is designed to mitigate is unintended action execution resulting from a compromised or "hallucinating" Large Language Model (LLM).

*   **Adversary:** The LLM planner is treated as an untrusted source of commands. While a powerful tool, it can be manipulated via prompt injection or may generate unsafe instructions.
*   **Goal:** The agent's security goal is to prevent the LLM from executing arbitrary commands, reading sensitive data, or causing any unintended system modification.
*   **Attack Vectors:** The model assumes attack vectors originate from the LLM's output, such as a plan containing:
    *   Unauthorized shell commands (e.g., `rm -rf /`).
    *   Attempts to read sensitive files (e.g., `~/.ssh/id_rsa`).
    *   Unauthorized network connections to malicious endpoints.

## Philosophy: Fail-Closed and Policy-Driven

The cornerstone of this agent's security is its "fail-closed" philosophy.

*   **Explicit Allowance:** No action is ever implicitly trusted. Only capabilities that are explicitly defined in the `Policy` module are candidates for execution.
*   **Strict Validation:** Every proposed action and its arguments are rigorously validated against a predefined schema. Any deviation results in immediate rejection of the entire plan.
*   **Halt on Violation:** A single policy violation halts the agent's execution loop, preventing it from proceeding with a potentially unsafe plan.

This is **not a general-purpose shell agent**. It is a task-specific executor that operates under a highly restrictive and auditable security policy.

## Explicit Non-Goals

To maintain a clear security boundary, `claw-cli-agent` is **NOT** designed for:

*   **Multi-User Environments:** It is built for a single, trusted user on their local machine.
*   **Server-Side Automation:** Deployment on production servers without significant additional hardening is strongly discouraged.
*   **Arbitrary Shell Execution:** The agent is fundamentally incapable of executing raw shell commands.
*   **Self-Modification:** The agent cannot alter its own security policies or source code.

## Safe Usage Assumptions

The security model of `claw-cli-agent` relies on the following assumptions:

*   **Trusted User:** The user operating the CLI is trusted.
*   **Secure Host:** The machine running the agent is not already compromised.
*   **Policy Review:** The user is expected to understand the capabilities defined in the policy files. This is the definitive source of truth for what the agent can and cannot do.

If you discover a security vulnerability, please report it responsibly by opening a security advisory on the GitHub repository.

