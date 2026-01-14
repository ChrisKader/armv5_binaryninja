/*
 * ARMv5 Firmware Action Policy
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
