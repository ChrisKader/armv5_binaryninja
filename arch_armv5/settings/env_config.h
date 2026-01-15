/*
 * ARMv5 Plugin Environment Configuration
 *
 * Centralized environment variable handling for the plugin.
 */

#pragma once

#include <string>
#include <vector>

namespace Armv5EnvConfig
{

// Environment variable names
constexpr const char* kDisableScans = "BN_ARMV5_FIRMWARE_DISABLE_SCANS";
constexpr const char* kDisableWorkflow = "BN_ARMV5_DISABLE_WORKFLOW";
constexpr const char* kDisableActions = "BN_ARMV5_FIRMWARE_DISABLE_ACTIONS";
constexpr const char* kEnableCleanup = "BN_ARMV5_FIRMWARE_ENABLE_CLEANUP";

// Parse a comma/semicolon/whitespace-separated token list from an env var value
std::vector<std::string> ParseTokenList(const char* value);

// Normalize a token: convert to lowercase, replace '-' with '_'
std::string NormalizeToken(std::string token);

// Check if an environment variable is set and non-empty
bool IsEnvSet(const char* envVar);

// Get the value of an environment variable (or nullptr if not set)
const char* GetEnv(const char* envVar);

}
