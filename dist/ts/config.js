const validLevels = ["readonly", "supervised", "full"];
/**
 * Reads the autonomy level from the QUANTUMBLUE_AUTONOMY_LEVEL environment variable.
 * Defaults to "supervised" if the variable is not set or is invalid.
 *
 * @returns {AutonomyLevel} The current autonomy level.
 */
export function getAutonomyLevel() {
    const level = process.env.QUANTUMBLUE_AUTONOMY_LEVEL;
    if (level && validLevels.includes(level)) {
        return level;
    }
    return "supervised";
}
