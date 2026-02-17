# claw-cli

## Project Purpose

`claw-cli` is a command-line interface (CLI) first autonomous agent designed for secure, single-user execution of web-based tasks. It acts as a controlled interface between natural language instructions, parsed by a Large Language Model (LLM), and web browser automation.

## What `claw-cli` IS

`claw-cli` is a security-first, auditable, and policy-driven agent for automating web interactions. It enables users to articulate tasks in natural language, which are then rigorously validated against a predefined security policy before execution within a sandboxed browser environment. Its core focus is on controlled, transparent automation for a single, trusted user.

## What `claw-cli` IS NOT

`claw-cli` is NOT a general-purpose shell agent capable of executing arbitrary commands on your system. It is NOT designed for multi-user environments, server-side automation without additional hardening, or for bypassing security measures. It does NOT possess self-modification capabilities for its policies or source code. Its design explicitly prevents unrestricted access to the underlying system or network.

## Security-First, Single-User Design

The agent operates with a fail-closed philosophy. All actions are explicitly allow-listed and validated against a strict intent schema. This ensures that the LLM's outputs are always constrained and that the user retains ultimate control. It is intended solely for single-user, local execution in a trusted environment.

## Status

**Version:** v0.1.0-alpha

This project is currently in an alpha state. While significant effort has been invested in its security model, it should be used with caution.

## Further Documentation

For detailed usage examples, agent loop explanation, architecture overview, and in-depth security rationale, please refer to the [CLI_AGENT_README.md](./CLI_AGENT_README.md) file.