import path from 'path';
import process from 'process';

/**
 * A set of allowed actions that can be performed. This acts as a
 * security allowlist to prevent unauthorized operations.
 */
const allowedActions = new Set<string>([
  'harden',
  'encrypt',
  'decrypt',
  'generate-keypair',
  'encrypt-file',
  'decrypt-file',
  // 'analyze',
  // 'predict',
]);

/**
 * Checks if a given action is in the allowlist.
 * @param {string} action The action to check.
 * @returns {boolean} True if the action is allowed, false otherwise.
 */
export function isActionAllowed(action: string): boolean {
  return allowedActions.has(action);
}

/**
 * Resolves an input path against the current working directory, ensuring it
 * remains within the project's scope for security.
 *
 * Throws an error for paths that are absolute, attempt to traverse upwards
 * (e.g., '../'), or contain null bytes.
 *
 * @param {string} inputPath The user-provided path.
 * @returns {string} The resolved, safe absolute path.
 * @throws {Error} If the path is deemed unsafe.
 */
export function resolveSafePath(inputPath: string): string {
  const CWD = process.cwd();

  // 1. Disallow null bytes
  if (inputPath.includes('\0')) {
    throw new Error('Path not allowed: contains null byte.');
  }

  // 2. Disallow absolute paths and directory traversal
  if (path.isAbsolute(inputPath) || inputPath.startsWith('~') || inputPath.includes('..')) {
      throw new Error('Path not allowed: must be relative and within the project.');
  }

  const resolvedPath = path.resolve(CWD, inputPath);

  // 3. Ensure the resolved path is still within the original CWD
  if (!resolvedPath.startsWith(CWD)) {
    throw new Error('Path not allowed: resolves outside the project directory.');
  }

  return resolvedPath;
}
