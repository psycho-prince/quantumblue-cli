import { Static, Type } from '@sinclair/typebox';

// Define the schema for actions
const ActionSchema = Type.Object({
  action: Type.String(),
  args: Type.Record(Type.String(), Type.Any()),
});

type AgentAction = Static<typeof ActionSchema>;

export class Policy {
  private allowedActions: Set<string>;

  constructor() {
    // CRITICAL: This set defines the ONLY actions the agent is permitted to execute.
    // Any action not in this list will be rejected by the policy enforcement.
    this.allowedActions = new Set([
      'read_file',
      'list_directory',
      // TODO: Add more safe and sandboxed actions here as the agent's capabilities expand.
      // Each addition must be carefully reviewed for security implications.
    ]);
  }

  /**
   * Validates a plan (a sequence of actions) against the defined security policy.
   * If any action or its arguments violate the policy, an error is thrown,
   * enforcing the "fail-closed" philosophy.
   */
  validatePlan(plan: AgentAction[]): void {
    for (const action of plan) {
      if (!this.allowedActions.has(action.action)) {
        throw new Error(`Policy violation: Action "${action.action}" is not allowed by the security policy.`);
      }
      // TODO: Implement more granular argument validation here.
      // This would involve checking specific properties of 'action.args'
      // For example, for 'read_file', ensure the path is within an allowed directory,
      // and does not contain sensitive system paths or traversal attempts.
      // Example:
      // if (action.action === 'read_file') {
      //   const filePath = action.args.path as string;
      //   if (!filePath.startsWith('/safe_data/') || filePath.includes('..')) {
      //     throw new Error(`Policy violation: Unauthorized file path for read_file: ${filePath}`);
      //   }
      // }
    }
    console.log('[Policy] Plan validated successfully. All actions adhere to the security policy.');
  }
}
