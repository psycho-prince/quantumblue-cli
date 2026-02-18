export type AutonomyLevel = "readonly" | "supervised" | "full";

const validLevels: AutonomyLevel[] = ["readonly", "supervised", "full"];

/**
 * Reads the autonomy level from the QUANTUMBLUE_AUTONOMY_LEVEL environment variable.
 * Defaults to "supervised" if the variable is not set or is invalid.
 *
 * @returns {AutonomyLevel} The current autonomy level.
 */
export function getAutonomyLevel(): AutonomyLevel {
  const level = process.env.QUANTUMBLUE_AUTONOMY_LEVEL as AutonomyLevel;
  if (level && validLevels.includes(level)) {
    return level;
  }
  return "supervised";
}
