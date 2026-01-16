/*
 * ARMv5 Plugin Environment Configuration
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * This file provides utilities for reading and parsing environment variables.
 * Environment variables allow developer overrides of plugin behavior without
 * modifying UI settings - useful for debugging, testing, and CI.
 *
 * ============================================================================
 * ENVIRONMENT VARIABLE CONSTANTS
 * ============================================================================
 *
 * Defined in env_config.h:
 *
 *   kDisableWorkflow = "BN_ARMV5_DISABLE_WORKFLOW"
 *     - Any non-empty value disables the firmware workflow
 *     - Firmware view still works, but automated scans don't run
 *
 *   kDisableScans = "BN_ARMV5_FIRMWARE_DISABLE_SCANS"
 *     - Comma/semicolon/space separated list of scans to disable
 *     - "all" disables everything
 *     - Individual: "prologue", "calltarget", "pointer", "orphan", "cleanup"
 *
 *   kDisableActions = "BN_ARMV5_FIRMWARE_DISABLE_ACTIONS"
 *     - Comma/semicolon/space separated list of actions to disable
 *     - "all" disables all data mutations (dry run mode)
 *     - Individual: "add_function", "define_data", "define_symbol", "remove_function"
 *
 * ============================================================================
 * TOKEN PARSING
 * ============================================================================
 *
 * Environment values are parsed as token lists:
 *   - Delimiters: comma, semicolon, space, tab, newline
 *   - Tokens are normalized: lowercase, hyphens become underscores
 *   - Empty tokens are ignored
 *
 * Example:
 *   BN_ARMV5_FIRMWARE_DISABLE_SCANS="prologue, call-target"
 *   Parses to: ["prologue", "call_target"]
 *
 * ============================================================================
 */

#include "env_config.h"

#include <cctype>
#include <cstdlib>

namespace Armv5EnvConfig
{

std::vector<std::string> ParseTokenList(const char* value)
{
	std::vector<std::string> tokens;
	if (!value)
		return tokens;

	std::string current;
	for (const char* p = value; *p; ++p)
	{
		char c = *p;
		if (c == ',' || c == ';' || c == ' ' || c == '\t' || c == '\n' || c == '\r')
		{
			if (!current.empty())
			{
				tokens.emplace_back(current);
				current.clear();
			}
			continue;
		}
		current.push_back(c);
	}
	if (!current.empty())
		tokens.emplace_back(current);
	return tokens;
}

std::string NormalizeToken(std::string token)
{
	for (char& ch : token)
	{
		if (ch == '-')
			ch = '_';
		ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
	}
	return token;
}

bool IsEnvSet(const char* envVar)
{
	const char* value = std::getenv(envVar);
	return value && value[0] != '\0';
}

const char* GetEnv(const char* envVar)
{
	return std::getenv(envVar);
}

}
