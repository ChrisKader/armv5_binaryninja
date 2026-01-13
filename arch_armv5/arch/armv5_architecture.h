#pragma once

#include "binaryninjaapi.h"

class ArmCommonArchitecture;

ArmCommonArchitecture* InitArmv5Architecture(const char* name, BNEndianness endian);
