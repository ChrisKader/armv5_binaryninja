/*
 * ARMv5 Architecture Common Base
 */

#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <vector>

#include "binaryninjaapi.h"
#include "arch_armv5.h"
#include "il/il.h"

using namespace BinaryNinja;
using namespace armv5;
using namespace std;

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

static BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset, size_t size, bool zeroExtend = false)
{
  BNRegisterInfo result;
  result.fullWidthRegister = fullWidthReg;
  result.offset = offset;
  result.size = size;
  result.extend = zeroExtend ? ZeroExtendToFullWidth : NoExtend;
  return result;
}

/*
 * ArmCommonArchitecture Implementation
 */
ArmCommonArchitecture::ArmCommonArchitecture(const char *name, BNEndianness endian) : Architecture(name), m_endian(endian)
{
}

void ArmCommonArchitecture::SetArmAndThumbArchitectures(Architecture *arm, Architecture *thumb)
{
  m_armArch = arm;
  m_thumbArch = thumb;
}

/*
 * ArmCommonArchitecture base class method implementations
 * (ThumbArchitecture is now in thumb_disasm/arch_thumb.cpp)
 */

Ref<Architecture> ArmCommonArchitecture::GetAssociatedArchitectureByAddress(uint64_t &addr)
{
  if (addr & 1)
  {
    addr &= ~1LL;
    /*
     * Don't return Thumb architecture for very low addresses.
     * The ARM vector table at 0x00-0x1C should always be ARM mode.
     * Pointer sweep may find small integer values (1, 3, 5, 7, etc.) in data
     * sections that happen to look like "Thumb address" but aren't actually
     * function pointers. This prevents spurious Thumb function creation in
     * the vector table region.
     */
    if (addr < 0x20)
      return m_armArch;
    return m_thumbArch;
  }
  return m_armArch;
}

BNEndianness ArmCommonArchitecture::GetEndianness() const
{
  return m_endian;
}

size_t ArmCommonArchitecture::GetAddressSize() const
{
  return 4;
}

string ArmCommonArchitecture::GetFlagName(uint32_t flag)
{
  char result[32];
  switch (flag)
  {
  case IL_FLAG_N:
    return "n";
  case IL_FLAG_Z:
    return "z";
  case IL_FLAG_C:
    return "c";
  case IL_FLAG_V:
    return "v";
  case IL_FLAG_Q:
    return "q";
  default:
    snprintf(result, sizeof(result), "flag%" PRIu32, flag);
    return result;
  }
}

string ArmCommonArchitecture::GetFlagWriteTypeName(uint32_t flags)
{
  switch (flags)
  {
  case IL_FLAGWRITE_ALL:
    return "*";
  case IL_FLAGWRITE_NZ:
    return "nz";
  case IL_FLAGWRITE_CNZ:
    return "cnz";
  case IL_FLAGWRITE_NZC:
    return "nzc";
  case IL_FLAGWRITE_NZCV:
    return "nzcv";
  default:
    return "";
  }
}

BNFlagRole ArmCommonArchitecture::GetFlagRole(uint32_t flag, uint32_t)
{
  switch (flag)
  {
  case IL_FLAG_N:
    return NegativeSignFlagRole;
  case IL_FLAG_Z:
    return ZeroFlagRole;
  case IL_FLAG_C:
    return CarryFlagRole;
  case IL_FLAG_V:
    return OverflowFlagRole;
  default:
    return SpecialFlagRole;
  }
}

vector<uint32_t> ArmCommonArchitecture::GetFlagsWrittenByFlagWriteType(uint32_t flags)
{
  switch (flags)
  {
  case IL_FLAGWRITE_ALL:
  case IL_FLAGWRITE_NZCV:
    return vector<uint32_t>{IL_FLAG_N, IL_FLAG_Z, IL_FLAG_C, IL_FLAG_V};
  case IL_FLAGWRITE_NZ:
    return vector<uint32_t>{IL_FLAG_N, IL_FLAG_Z};
  case IL_FLAGWRITE_CNZ:
    return vector<uint32_t>{IL_FLAG_C, IL_FLAG_N, IL_FLAG_Z};
  case IL_FLAGWRITE_NZC:
    return vector<uint32_t>{IL_FLAG_N, IL_FLAG_Z, IL_FLAG_C};
  default:
    return vector<uint32_t>{};
  }
}

vector<uint32_t> ArmCommonArchitecture::GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t)
{
  switch (cond)
  {
  case LLFC_E:
  case LLFC_NE:
    return vector<uint32_t>{IL_FLAG_Z};
  case LLFC_SLT:
  case LLFC_SGE:
    return vector<uint32_t>{IL_FLAG_N, IL_FLAG_V};
  case LLFC_ULT:
  case LLFC_UGE:
    return vector<uint32_t>{IL_FLAG_C};
  case LLFC_SLE:
  case LLFC_SGT:
    return vector<uint32_t>{IL_FLAG_Z, IL_FLAG_N, IL_FLAG_V};
  case LLFC_ULE:
  case LLFC_UGT:
    return vector<uint32_t>{IL_FLAG_C, IL_FLAG_Z};
  case LLFC_NEG:
  case LLFC_POS:
    return vector<uint32_t>{IL_FLAG_N};
  case LLFC_O:
  case LLFC_NO:
    return vector<uint32_t>{IL_FLAG_V};
  default:
    return vector<uint32_t>{};
  }
}

size_t ArmCommonArchitecture::GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
                                                     uint32_t flag, BNRegisterOrConstant *operands, size_t operandCount, LowLevelILFunction &il)
{
  switch (op)
  {
  case LLIL_SBB:
    switch (flag)
    {
    case IL_FLAG_C:
      // r u< a || (r == a && flag_c)
      return il.Or(0,
                   il.CompareUnsignedLessThan(size,
                                              il.GetExprForRegisterOrConstantOperation(op, size, operands, operandCount),
                                              il.GetExprForRegisterOrConstant(operands[0], size)),
                   il.And(0,
                          il.CompareEqual(size,
                                          il.GetExprForRegisterOrConstantOperation(op, size, operands, operandCount),
                                          il.GetExprForRegisterOrConstant(operands[0], size)),
                          il.Flag(IL_FLAG_C)));
    case IL_FLAG_V:
      return il.CompareEqual(0,
                             il.CompareSignedLessThan(size,
                                                      il.GetExprForRegisterOrConstantOperation(op, size, operands, operandCount),
                                                      il.GetExprForRegisterOrConstant(operands[0], size)),
                             il.CompareEqual(size,
                                             il.GetExprForRegisterOrConstant(operands[0], size),
                                             il.Const(size, 0)));
    }
    break;
  case LLIL_LSR:
    switch (flag)
    {
    case IL_FLAG_C:
      return il.TestBit(0,
                        il.GetExprForRegisterOrConstant(operands[0], size),
                        il.Sub(size, il.GetExprForRegisterOrConstant(operands[1], size), il.Const(size, 1)));
    }
    break;
  case LLIL_LSL:
    switch (flag)
    {
    case IL_FLAG_C:
      return il.TestBit(0,
                        il.GetExprForRegisterOrConstant(operands[0], size),
                        il.Sub(size, il.Const(size, 8 * size), il.GetExprForRegisterOrConstant(operands[1], size)));
    }
  default:
    break;
  }

  BNFlagRole role = GetFlagRole(flag, GetSemanticClassForFlagWriteType(flagWriteType));
  return GetDefaultFlagWriteLowLevelIL(op, size, role, operands, operandCount, il);
}

string ArmCommonArchitecture::GetRegisterName(uint32_t reg)
{
  if (reg >= REG_R0 && reg < REG_INVALID)
  {
    return get_register_name((enum Register)reg);
  }

  //LogError("Unknown Register: %x - Please report this as a bug.\n", reg);
  return "unknown";
}

vector<uint32_t> ArmCommonArchitecture::GetFullWidthRegisters()
{
  return vector<uint32_t>{
      REG_R0,
      REG_R1,
      REG_R2,
      REG_R3,
      REG_R4,
      REG_R5,
      REG_R6,
      REG_R7,
      REG_R8,
      REG_R9,
      REG_R10,
      REG_R11,
      REG_R12,
      REG_R13,
      REG_R14,
      REG_R15,
      REG_D0,
      REG_D1,
      REG_D2,
      REG_D3,
      REG_D4,
      REG_D5,
      REG_D6,
      REG_D7,
      REG_D8,
      REG_D9,
      REG_D10,
      REG_D11,
      REG_D12,
      REG_D13,
      REG_D14,
      REG_D15,
  };
}

vector<uint32_t> ArmCommonArchitecture::GetAllRegisters()
{
  return vector<uint32_t>{
      REG_R0,
      REG_R1,
      REG_R2,
      REG_R3,
      REG_R4,
      REG_R5,
      REG_R6,
      REG_R7,
      REG_R8,
      REG_R9,
      REG_R10,
      REG_R11,
      REG_R12,
      REG_R13,
      REG_R14,
      REG_R15,
      REG_S0,
      REG_S1,
      REG_S2,
      REG_S3,
      REG_S4,
      REG_S5,
      REG_S6,
      REG_S7,
      REG_S8,
      REG_S9,
      REG_S10,
      REG_S11,
      REG_S12,
      REG_S13,
      REG_S14,
      REG_S15,
      REG_S16,
      REG_S17,
      REG_S18,
      REG_S19,
      REG_S20,
      REG_S21,
      REG_S22,
      REG_S23,
      REG_S24,
      REG_S25,
      REG_S26,
      REG_S27,
      REG_S28,
      REG_S29,
      REG_S30,
      REG_S31,
      REG_D0,
      REG_D1,
      REG_D2,
      REG_D3,
      REG_D4,
      REG_D5,
      REG_D6,
      REG_D7,
      REG_D8,
      REG_D9,
      REG_D10,
      REG_D11,
      REG_D12,
      REG_D13,
      REG_D14,
      REG_D15,

      /* special registers */
      REGS_FPSID,
      REGS_FPSCR,
      REGS_FPEXC,
  };
}

vector<uint32_t> ArmCommonArchitecture::GetAllFlags()
{
  return vector<uint32_t>{
      IL_FLAG_N, IL_FLAG_Z, IL_FLAG_C, IL_FLAG_V, IL_FLAG_Q};
}

vector<uint32_t> ArmCommonArchitecture::GetAllFlagWriteTypes()
{
  return vector<uint32_t>{
      IL_FLAGWRITE_ALL,
      IL_FLAGWRITE_NZ,
      IL_FLAGWRITE_CNZ,
      IL_FLAGWRITE_NZC,
      IL_FLAGWRITE_NZCV};
}

BNRegisterInfo ArmCommonArchitecture::GetRegisterInfo(uint32_t reg)
{
  switch (reg)
  {
  case REG_R0:
  case REG_R1:
  case REG_R2:
  case REG_R3:
  case REG_R4:
  case REG_R5:
  case REG_R6:
  case REG_R7:
  case REG_R8:
  case REG_R9:
  case REG_R10:
  case REG_R11:
  case REG_R12:
  case REG_R13:
  case REG_R14:
  case REG_R15:
    return RegisterInfo(reg, 0, 4);
  case REG_S0:
  case REG_S1:
  case REG_S2:
  case REG_S3:
  case REG_S4:
  case REG_S5:
  case REG_S6:
  case REG_S7:
  case REG_S8:
  case REG_S9:
  case REG_S10:
  case REG_S11:
  case REG_S12:
  case REG_S13:
  case REG_S14:
  case REG_S15:
  case REG_S16:
  case REG_S17:
  case REG_S18:
  case REG_S19:
  case REG_S20:
  case REG_S21:
  case REG_S22:
  case REG_S23:
  case REG_S24:
  case REG_S25:
  case REG_S26:
  case REG_S27:
  case REG_S28:
  case REG_S29:
  case REG_S30:
  case REG_S31:
    return RegisterInfo(REG_D0 + ((reg - REG_S0) / 2), ((reg - REG_S0) % 2) * 4, 4);
  case REG_D0:
  case REG_D1:
  case REG_D2:
  case REG_D3:
  case REG_D4:
  case REG_D5:
  case REG_D6:
  case REG_D7:
  case REG_D8:
  case REG_D9:
  case REG_D10:
  case REG_D11:
  case REG_D12:
  case REG_D13:
  case REG_D14:
  case REG_D15:
    return RegisterInfo(reg, 0, 8);
  default:
    return RegisterInfo(reg, 0, 4);
  }
}

uint32_t ArmCommonArchitecture::GetStackPointerRegister()
{
  return REG_SP;
}

uint32_t ArmCommonArchitecture::GetLinkRegister()
{
  return REG_LR;
}
bool ArmCommonArchitecture::CanAssemble()
{
  return true;
}

bool ArmCommonArchitecture::Assemble(const string &code, uint64_t addr, DataBuffer &result, string &errors)
{
  (void)addr;

  char *instrBytes = NULL, *err = NULL;
  int instrBytesLen = 0, errLen = 0;

  int assembleResult;

  string triple = GetAssemblerTriple();
  LogDebug("%s() retrieves and uses triple %s\n", __func__, triple.c_str());

  BNLlvmServicesInit();

  errors.clear();
  assembleResult = BNLlvmServicesAssemble(code.c_str(), LLVM_SVCS_DIALECT_UNSPEC,
                                          triple.c_str(), LLVM_SVCS_CM_DEFAULT, LLVM_SVCS_RM_STATIC,
                                          &instrBytes, &instrBytesLen, &err, &errLen);

  if (assembleResult || errLen)
  {
    errors = err;
    BNLlvmServicesAssembleFree(instrBytes, err);
    return false;
  }

  result.Clear();
  result.Append(instrBytes, instrBytesLen);
  BNLlvmServicesAssembleFree(instrBytes, err);
  return true;
}
