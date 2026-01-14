/*
 * ARMv5 Plugin Environment Configuration
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
