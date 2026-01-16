/*
 * ARMv5 Firmware Action Policy
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * This file implements the action policy system for firmware scans. The
 * policy controls which types of mutations scans are allowed to perform.
 *
 * WHY ACTION POLICIES?
 * --------------------
 *
 * During debugging and development, it's useful to disable specific actions
 * to isolate problems:
 *
 * - "Functions keep disappearing" -> Disable remove_function
 * - "Too many false positive data variables" -> Disable define_data
 * - "Want to see what scans find without changes" -> Disable all (dry run)
 *
 * ============================================================================
 * POLICY STRUCTURE
 * ============================================================================
 *
 * FirmwareActionPolicy contains boolean flags for each action type:
 *
 *   allowAddFunction    - Create new functions (AddFunctionForAnalysis)
 *   allowDefineData     - Define data variables (DefineDataVariable)
 *   allowClearData      - Undefine data variables (UndefineDataVariable)
 *   allowDefineSymbol   - Create symbols (DefineAutoSymbol)
 *   allowRemoveFunction - Remove functions (RemoveAnalysisFunction)
 *
 * Default: All actions enabled (policy = allow everything)
 *
 * ============================================================================
 * CONFIGURATION
 * ============================================================================
 *
 * Set BN_ARMV5_FIRMWARE_DISABLE_ACTIONS environment variable:
 *
 *   # Disable all actions (dry run - see what would happen)
 *   export BN_ARMV5_FIRMWARE_DISABLE_ACTIONS=all
 *
 *   # Disable function removal only
 *   export BN_ARMV5_FIRMWARE_DISABLE_ACTIONS=remove_function
 *
 *   # Disable multiple actions
 *   export BN_ARMV5_FIRMWARE_DISABLE_ACTIONS="add_function,define_data"
 *
 * ============================================================================
 */

#include "action_policy.h"
#include "env_config.h"

namespace Armv5Settings
{

static FirmwareActionPolicy ParseFirmwareActionPolicy()
{
	FirmwareActionPolicy policy;
	const char* env = Armv5EnvConfig::GetEnv(Armv5EnvConfig::kDisableActions);
	if (!env || env[0] == '\0')
		return policy;

	auto tokens = Armv5EnvConfig::ParseTokenList(env);
	for (const auto& raw : tokens)
	{
		if (raw.empty())
			continue;

		auto token = Armv5EnvConfig::NormalizeToken(raw);

		if (token == "all")
		{
			policy.allowAddFunction = false;
			policy.allowDefineData = false;
			policy.allowClearData = false;
			policy.allowDefineSymbol = false;
			policy.allowRemoveFunction = false;
			continue;
		}
		if (token == "add_function" || token == "add_functions")
		{
			policy.allowAddFunction = false;
			continue;
		}
		if (token == "define_data" || token == "define_data_variable" || token == "define_data_variables")
		{
			policy.allowDefineData = false;
			continue;
		}
		if (token == "clear_data" || token == "undefine_data" || token == "undefine_data_variable"
			|| token == "undefine_data_variables")
		{
			policy.allowClearData = false;
			continue;
		}
		if (token == "define_symbol" || token == "define_symbols")
		{
			policy.allowDefineSymbol = false;
			continue;
		}
		if (token == "remove_function" || token == "remove_functions")
		{
			policy.allowRemoveFunction = false;
			continue;
		}
	}
	return policy;
}

const FirmwareActionPolicy& GetFirmwareActionPolicy()
{
	static FirmwareActionPolicy policy = ParseFirmwareActionPolicy();
	return policy;
}

}
