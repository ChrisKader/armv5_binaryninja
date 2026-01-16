/*
 * ARMv5 Plugin Environment Configuration
 *
 * Centralized environment variable handling for the plugin.
 *
 * ============================================================================
 * ENVIRONMENT VARIABLE REFERENCE
 * ============================================================================
 *
 * BN_ARMV5_DISABLE_WORKFLOW
 *   Purpose: Disable the firmware analysis workflow entirely
 *   Values:  Any non-empty value (e.g., "1", "true", "yes")
 *   Effect:  Firmware view loads but no automated scans run
 *   Use:     Debugging, manual analysis, performance testing
 *
 * BN_ARMV5_FIRMWARE_DISABLE_SCANS
 *   Purpose: Disable specific firmware scan passes
 *   Values:  Comma/semicolon/space separated list:
 *            - "all" - Disable all scans
 *            - "prologue" - Disable function prologue scanning
 *            - "calltarget" - Disable call target discovery
 *            - "pointer" - Disable pointer table scanning
 *            - "orphan" - Disable orphan code block recovery
 *            - "cleanup" - Disable invalid function cleanup
 *   Effect:  Specified scans are skipped during analysis
 *   Use:     Isolating which scan is causing issues
 *
 * BN_ARMV5_FIRMWARE_DISABLE_ACTIONS
 *   Purpose: Disable specific actions (dry run mode)
 *   Values:  Comma/semicolon/space separated list:
 *            - "all" - Disable all actions (pure dry run)
 *            - "add_function" - Don't create functions
 *            - "define_data" - Don't define data variables
 *            - "define_symbol" - Don't create symbols
 *            - "clear_data" - Don't undefine data
 *            - "remove_function" - Don't remove functions
 *   Effect:  Scans run but don't modify the binary view
 *   Use:     Seeing what scans would do without changes
 *
 * BN_ARMV5_FIRMWARE_ENABLE_CLEANUP
 *   Purpose: Enable invalid function cleanup pass
 *   Values:  Any non-empty value
 *   Effect:  Cleanup pass runs to remove false positive functions
 *   Note:    Cleanup is aggressive; may remove valid functions
 *
 * ============================================================================
 */

#pragma once

#include <string>
#include <vector>

namespace Armv5EnvConfig
{

/*
 * Environment variable name constants.
 * Using constexpr ensures compile-time string handling.
 */

/** Disable the firmware workflow entirely */
constexpr const char* kDisableWorkflow = "BN_ARMV5_DISABLE_WORKFLOW";

/** Disable specific scan passes (comma-separated list) */
constexpr const char* kDisableScans = "BN_ARMV5_FIRMWARE_DISABLE_SCANS";

/** Disable specific actions - dry run mode (comma-separated list) */
constexpr const char* kDisableActions = "BN_ARMV5_FIRMWARE_DISABLE_ACTIONS";

/** Enable the cleanup pass (removes false positive functions) */
constexpr const char* kEnableCleanup = "BN_ARMV5_FIRMWARE_ENABLE_CLEANUP";

/**
 * Parse a token list from an environment variable value.
 *
 * Supported delimiters: comma, semicolon, space, tab, newline
 * Empty tokens are skipped.
 *
 * @param value The raw environment variable value.
 * @return Vector of parsed tokens.
 */
std::vector<std::string> ParseTokenList(const char* value);

/**
 * Normalize a token for comparison.
 *
 * Converts to lowercase and replaces hyphens with underscores.
 * This allows flexible input: "call-target" == "call_target" == "CALL_TARGET"
 *
 * @param token The token to normalize.
 * @return Normalized token string.
 */
std::string NormalizeToken(std::string token);

/**
 * Check if an environment variable is set and non-empty.
 *
 * @param envVar The environment variable name.
 * @return true if set to a non-empty value.
 */
bool IsEnvSet(const char* envVar);

/**
 * Get the value of an environment variable.
 *
 * @param envVar The environment variable name.
 * @return The value, or nullptr if not set.
 */
const char* GetEnv(const char* envVar);

}

