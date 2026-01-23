/*
 * ARMv5 Architecture Implementation (ARM mode)
 *
 * This file implements the Armv5Architecture class, which provides disassembly,
 * instruction text rendering, and IL lifting for 32-bit ARM mode instructions.
 *
 * ARCHITECTURE HIERARCHY:
 * -----------------------
 *   ArmCommonArchitecture (base class in arch_armv5.h)
 *       |
 *       +-- Armv5Architecture (this file) - 32-bit ARM mode ("armv5")
 *       |
 *       +-- ThumbArchitecture (thumb_disasm/arch_thumb.cpp) - 16-bit Thumb mode ("armv5t")
 *
 * Both architectures reference each other via m_armArch/m_thumbArch for ARM/Thumb
 * interworking. When a BX/BLX instruction switches modes (indicated by bit 0 of
 * the target address), Binary Ninja uses GetAssociatedArchitectureByAddress() to
 * find the appropriate architecture for the target.
 *
 * KEY DESIGN PATTERNS (matching ARMv7):
 * -------------------------------------
 * 1. Instruction coalescing: Multiple conditional instructions with related
 *    conditions (e.g., MOVEQ + MOVNE) are coalesced into a single IL if/else
 *    block for cleaner decompilation.
 *
 * 2. PC handling: PC reads return addr+8 (ARM pipeline), PC writes become jumps.
 *
 * 3. Flag handling: The S suffix on instructions sets flags via flagWriteType.
 *
 * REFERENCE: binaryninja-api/arch/armv7/arch_armv7.cpp
 */

#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <map>
#include <queue>
#include <set>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "arch_armv5.h"
#include "arch/armv5_architecture.h"
#include "common/armv5_utils.h"
#include "il/il.h"

using namespace BinaryNinja;
using namespace armv5;
using namespace std;

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

/*
 * Error codes for disassembly text generation.
 * These are returned by GetInstructionText when operand rendering fails.
 */
#define DISASM_SUCCESS 0
#define FAILED_TO_DISASSEMBLE_OPERAND 1
#define FAILED_TO_DISASSEMBLE_REGISTER 2

/*
 * Maximum number of instructions to consider for conditional coalescing.
 * Coalescing combines sequences like:
 *   MOVEQ r0, #1
 *   MOVNE r0, #0
 * into a single IL if/else block. This limit prevents runaway analysis
 * on pathological cases.
 */
#define COALESCE_MAX_INSTRS 100

/*
 * Helper macro for IsRelatedCondition switch statement.
 * Handles both directions of a condition pair (e.g., EQ/NE, CS/CC).
 */
#define HANDLE_CASE(orig, opposite) \
  case orig:                        \
  case opposite:                    \
    return (candidate == orig) || (candidate == opposite)

/*
 * Check if two condition codes are related (opposite pairs).
 *
 * ARM conditional instructions often come in pairs with opposite conditions.
 * For example, MOVEQ followed by MOVNE. This function identifies such pairs
 * for instruction coalescing, which produces cleaner IL.
 *
 * @param orig      The original condition code.
 * @param candidate The candidate condition to check.
 * @return true if the conditions are opposites of the same test.
 */
static bool IsRelatedCondition(Condition orig, Condition candidate)
{
  switch (orig)
  {
    HANDLE_CASE(COND_EQ, COND_NE);  /* Equal / Not Equal */
    HANDLE_CASE(COND_CS, COND_CC);  /* Carry Set / Carry Clear */
    HANDLE_CASE(COND_MI, COND_PL);  /* Minus / Plus */
    HANDLE_CASE(COND_VS, COND_VC);  /* Overflow Set / Overflow Clear */
    HANDLE_CASE(COND_HI, COND_LS);  /* Unsigned Higher / Lower or Same */
    HANDLE_CASE(COND_GE, COND_LT);  /* Signed Greater or Equal / Less Than */
    HANDLE_CASE(COND_GT, COND_LE);  /* Signed Greater Than / Less or Equal */
  default:
    return false;
  }
}


/*
 * Check if an instruction can be followed by more coalesced conditional instructions
 * Returns false for branches and instructions writing to PC
 */
static bool CanCoalesceAfterInstruction(Instruction &instr)
{
  switch (instr.operation)
  {
  case ARMV5_BX:
  case ARMV5_B:
    return false;

  case ARMV5_ADC:
  case ARMV5_ADD:
  case ARMV5_AND:
  case ARMV5_BIC:
  case ARMV5_EOR:
  case ARMV5_LDR:
  case ARMV5_MOV:
  case ARMV5_MVN:
  case ARMV5_ORR:
  case ARMV5_RSB:
  case ARMV5_RSC:
  case ARMV5_SUB:
  case ARMV5_SBC:
  case ARMV5_LDRH:
  case ARMV5_LDRB:
  case ARMV5_LDRSH:
  case ARMV5_LDRSB:
  case ARMV5_LDRD:
  case ARMV5_MUL:
  case ARMV5_CLZ:
    if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
      return false;
    return true;

  default:
    return true;
  }
}

/*
 * NOTE: GetOperandCount is now in common/armv5_utils.h
 * Use armv5::GetOperandCount(instr) instead.
 */

/*
 * Armv5Architecture class definition with inline implementations (matches ARMv7 pattern)
 */
class Armv5Architecture : public ArmCommonArchitecture
{
protected:
  virtual std::string GetAssemblerTriple() override
  {
    if (m_endian == BigEndian)
      return "armv5eb-none-none";

    return "armv5-none-none";
  }

  virtual bool Disassemble(const uint8_t *data, uint64_t addr, size_t maxLen, Instruction &result)
  {
    (void)addr;
    (void)maxLen;
    memset(&result, 0, sizeof(result));
    if (armv5_decompose(*(uint32_t*)data, &result, (uint32_t)addr, (uint32_t)(m_endian == BigEndian)) != 0)
      return false;
    return true;
  }

  uint32_t ReadInstructionWord(const uint8_t* data) const
  {
    uint32_t word = 0;
    memcpy(&word, data, sizeof(word));
    if (m_endian == BigEndian)
      word = __builtin_bswap32(word);
    return word;
  }

  void SetInstructionInfoForInstruction(uint64_t addr, const Instruction &instr, InstructionInfo &result)
  {
    result.length = 4;

    switch (instr.operation)
    {
    case ARMV5_BL:
      if (UNCONDITIONAL(instr.cond) && (instr.operands[0].cls == LABEL))
      {
        result.AddBranch(CallDestination, instr.operands[0].imm, this);
      }
      break;
    case ARMV5_BLX:
      result.archTransitionByTargetAddr = true;
      if(UNCONDITIONAL(instr.cond))
      {
        if (instr.operands[0].cls == LABEL)
        {
          /* BLX with immediate always switches to Thumb */
          result.AddBranch(CallDestination, instr.operands[0].imm, m_thumbArch);
        }
        else if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_LR)
        {
          result.AddBranch(FunctionReturn);
          /* if (instr.operands[0].reg == REG_LR)
          {
            result.AddBranch(FunctionReturn);
          }
          else
          {
            result.AddBranch(CallDestination, 0);
          } */
        }
      }
      break;
    case ARMV5_BX:
      if (UNCONDITIONAL(instr.cond))
      {
        result.archTransitionByTargetAddr = true;
        if (instr.operands[0].reg == REG_LR)
          result.AddBranch(FunctionReturn);
        else
          result.AddBranch(UnresolvedBranch);
      }
      else if (instr.operands[0].reg == REG_LR)
      {
        result.AddBranch(FalseBranch, addr + 4, this);
      }
      break;
    case ARMV5_B:
      if (UNCONDITIONAL(instr.cond))
      {
        result.AddBranch(UnconditionalBranch, instr.operands[0].imm, this);
      }
      else
      {
        result.AddBranch(TrueBranch, instr.operands[0].imm, this);
        result.AddBranch(FalseBranch, addr + 4, this);
      }
      break;

    case ARMV5_LDR:
      /* Check for PC load (indirect branch) */
      if (instr.operands[0].reg == REG_PC)
      {
        result.archTransitionByTargetAddr = true;
        result.AddBranch(UnresolvedBranch);
        /*
         * Note: We don't add FalseBranch here because the analysis code in
         * armv5_architecture.cpp handleAsFallback() detects the 
         * "mov lr, pc; ldr pc, [rx]" pattern and sets endsBlock = false.
         * Adding FalseBranch here would override that detection.
         * 
         * Conditional LDR PC can fall through naturally.
         */
        if (CONDITIONAL(instr.cond))
        {
          result.AddBranch(FalseBranch, addr + 4, this);
        }
      }
      break;

    case ARMV5_LDM:
    case ARMV5_LDMIA:
    case ARMV5_LDMIB:
    case ARMV5_LDMDA:
    case ARMV5_LDMDB:
      /* Match ARMv7 behavior for PC in register list */
      if (UNCONDITIONAL(instr.cond))
      {
        for (int i = 0; i < MAX_OPERANDS; i++)
        {
          if (instr.operands[i].cls == NONE)
            break;
          if (instr.operands[i].cls == REG_LIST)
          {
            uint32_t regList = instr.operands[i].imm;
            if (regList == (1U << REG_PC))
            {
              result.archTransitionByTargetAddr = true;
              result.AddBranch(UnresolvedBranch);
            }
            else if (regList & (1U << REG_PC))
            {
              result.archTransitionByTargetAddr = true;
              result.AddBranch(FunctionReturn);
            }
            break;
          }
        }
      }
      break;

    case ARMV5_POP:
      /* POP with PC in list is a return (matches ARMv7) */
      for (int i = 0; i < MAX_OPERANDS; i++)
      {
        if (instr.operands[i].cls == NONE)
          break;
        if (instr.operands[i].cls == REG_LIST)
        {
          uint32_t regList = instr.operands[i].imm;
          if (regList & (1U << REG_PC))
          {
            result.archTransitionByTargetAddr = true;
            result.AddBranch(FunctionReturn);
            if (CONDITIONAL(instr.cond))
              result.AddBranch(FalseBranch, addr + 4, this);
          }
          break;
        }
      }
      break;

    case ARMV5_MOV:
      /* MOV PC, LR is a return */
      if (instr.operands[0].reg == REG_PC && instr.operands[1].reg == REG_LR)
      {
        result.archTransitionByTargetAddr = true;
        result.AddBranch(FunctionReturn);
        if (CONDITIONAL(instr.cond))
        {
          result.AddBranch(FalseBranch, addr + 4, this);
        }
      }
      else if (instr.operands[0].reg == REG_PC)
      {
        result.archTransitionByTargetAddr = true;
        result.AddBranch(UnresolvedBranch);
        if (CONDITIONAL(instr.cond))
        {
          result.AddBranch(FalseBranch, addr + 4, this);
        }
      }
      break;

    case ARMV5_SWI:
    case ARMV5_SVC:
      result.AddBranch(SystemCall);
      break;

    case ARMV5_ADC:
    case ARMV5_ADCS:
    case ARMV5_ADD:
    case ARMV5_ADDS:
    case ARMV5_AND:
    case ARMV5_ANDS:
    case ARMV5_ASR:
    case ARMV5_ASRS:
    case ARMV5_BIC:
    case ARMV5_BICS:
    case ARMV5_EOR:
    case ARMV5_EORS:
    case ARMV5_LSL:
    case ARMV5_LSLS:
    case ARMV5_LSR:
    case ARMV5_LSRS:
    case ARMV5_MVN:
    case ARMV5_MVNS:
    case ARMV5_ORR:
    case ARMV5_ORRS:
    case ARMV5_ROR:
    case ARMV5_RORS:
    case ARMV5_RSB:
    case ARMV5_RSBS:
    case ARMV5_RSC:
    case ARMV5_SBC:
    case ARMV5_SBCS:
    case ARMV5_SUB:
    case ARMV5_SUBS:
      /* Data processing with PC as destination is a computed jump (matches ARMv7) */
      if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
      {
        result.archTransitionByTargetAddr = true;
        result.AddBranch(UnresolvedBranch);
        if (CONDITIONAL(instr.cond))
        {
          result.AddBranch(FalseBranch, addr + 4, this);
        }
      }
      break;

    default:
      break;
    }
  }

  bool GetCoalescedLowLevelIL(const uint8_t *data, uint64_t addr, size_t &len, LowLevelILFunction &il, Instruction &instr)
  {
    size_t remaining = len / 4;
    if (remaining > COALESCE_MAX_INSTRS)
      remaining = COALESCE_MAX_INSTRS;

    Condition cond = instr.cond;

    Instruction coalesced[COALESCE_MAX_INSTRS];
    bool liftInstruction[COALESCE_MAX_INSTRS];
    size_t disassembled = 1;

    coalesced[0] = instr;
    liftInstruction[0] = true;

    auto setsFlags = [](const Instruction &instr)
    {
      if (instr.setsFlags)
        return true;

      switch (instr.operation)
      {
      case ARMV5_CMP:
      case ARMV5_CMN:
      case ARMV5_TST:
        return true;

      case ARMV5_BL:
      case ARMV5_BLX:
        return true;

      default:
        return false;
      }
    };

    for (bool condValid[2] = {true, true}; (disassembled < remaining) && (condValid[0] || condValid[1]); disassembled++)
    {
      size_t consumed = disassembled * 4;
      auto &newInstr = coalesced[disassembled];

      if (!Disassemble(data + consumed, addr + consumed, len - consumed, newInstr))
        break;
      if (UNCONDITIONAL(newInstr.cond))
        break;
      if (!IsRelatedCondition(newInstr.cond, cond))
        break;

      liftInstruction[disassembled] = condValid[newInstr.cond != cond];
      if (!CanCoalesceAfterInstruction(newInstr))
        condValid[newInstr.cond != cond] = false;

      if (setsFlags(instr))
      {
        condValid[0] = true;
        condValid[1] = true;
      }
    }

    if (disassembled == 1)
    {
      len = 4;
      return GetLowLevelILForArmInstruction(this, addr, il, instr, 4);
    }

    LowLevelILLabel doneLabel;
    LowLevelILLabel condLabels[2];

    BNLowLevelILLabel *doneLabelExisting = il.GetLabelForAddress(this, addr + (disassembled * 4));
    BNLowLevelILLabel *doneLabelToUse = doneLabelExisting ? doneLabelExisting : &doneLabel;

    for (size_t blockStart = 0; blockStart < disassembled;)
    {
      auto &beginInstr = coalesced[blockStart];
      size_t stateIdx = (beginInstr.cond != cond);

      // determine how many instructions to lift this iteration.
      // generally, this will be set to `disassembled`, but in the
      // event that cmp/cmn/tst instructions are used in the conditional
      // block, they each require re-evaluation of the condition on the side
      // that executed the flag setting instructions
      size_t nextFlagSet = blockStart;
      for (; nextFlagSet < disassembled; nextFlagSet++)
      {
        if (!liftInstruction[nextFlagSet])
          continue; // skip unreachable instructions

        if (setsFlags(coalesced[nextFlagSet]))
          break;
      }

      // figure out where the next block start for the *other* condition in the sequence is
      size_t otherCondNext = blockStart + 1;
      for (; otherCondNext < disassembled; otherCondNext++)
      {
        if (!liftInstruction[otherCondNext])
          continue; // skip unreachable instructions

        if (coalesced[otherCondNext].cond != beginInstr.cond)
          break;
      }

      bool hasOtherPath = (otherCondNext < disassembled);

      il.SetCurrentAddress(this, addr + (blockStart * 4));
      il.AddInstruction(il.If(GetCondition(il, beginInstr.cond), condLabels[stateIdx],
                              hasOtherPath ? condLabels[1 - stateIdx] : *doneLabelToUse));

      auto liftInstructions = [&](Condition liftCond)
      {
        size_t stateIdx = (liftCond != cond);

        il.MarkLabel(condLabels[stateIdx]);
        condLabels[stateIdx] = LowLevelILLabel();

        bool exhausted = true;
        for (size_t i = nextFlagSet + 1; (i < disassembled) && exhausted; i++)
          if (coalesced[i].cond == liftCond)
            exhausted = false;

        size_t liftIdx = blockStart;
        for (; (liftIdx <= nextFlagSet) && (liftIdx < disassembled); liftIdx++)
        {
          if (!liftInstruction[liftIdx])
            continue; // skip unreachable instructions

          auto &curInstr = coalesced[liftIdx];
          if (curInstr.cond != liftCond)
            continue;

          uint64_t instrAddr = addr + (liftIdx * 4);

          il.SetCurrentAddress(this, instrAddr);

          curInstr.cond = COND_AL;
          GetLowLevelILForArmInstruction(this, instrAddr, il, curInstr, 4);
          curInstr.cond = liftCond;
        }

        // CASE 1: last instr was a flag-setting instruction, do nothing, next lifting fixes it
        if ((nextFlagSet < disassembled) && (coalesced[nextFlagSet].cond == liftCond))
          return;

        // CASE 2: no further instructions with this cond exist: goto done
        else if (exhausted)
          il.AddInstruction(il.Goto(*doneLabelToUse));

        // CASE 3: last instr was not a flag-setting instruction, goto next block of this cond (or end)
        else
          il.AddInstruction(il.Goto(condLabels[stateIdx]));
      };

      bool liftAfter = false;
      if (hasOtherPath && (otherCondNext <= nextFlagSet))
      {
        // if we have two different cases to lift, and one of them contains a flag-setting
        // instruction, make sure the condition with the the flag-setting instruction is
        // lifted last. this lets us avoid an unnecessary LLIL_GOTO to the next if statement
        if ((nextFlagSet < disassembled) && (coalesced[nextFlagSet].cond == beginInstr.cond))
          liftInstructions(coalesced[otherCondNext].cond);
        else
          liftAfter = true;
      }

      liftInstructions(beginInstr.cond);

      if (liftAfter)
        liftInstructions(coalesced[otherCondNext].cond);

      blockStart = nextFlagSet + 1;
    }

    if (!doneLabelExisting)
      il.MarkLabel(doneLabel);

    len = disassembled * 4;
    return (doneLabelExisting == nullptr);
  }

public:
  Armv5Architecture(const char *name, BNEndianness endian)
      : ArmCommonArchitecture(name, endian)
  {
  }

  virtual size_t GetInstructionAlignment() const override
  {
    return 4;
  }

  virtual size_t GetMaxInstructionLength() const override
  {
    return 4;  // ARM instructions are always 4 bytes
  }

  virtual size_t GetOpcodeDisplayLength() const override
  {
    return 4;
  }

  virtual std::vector<uint32_t> GetSystemRegisters() override
  {
    return {REG_CPSR, REG_SPSR, REG_FPSCR};
  }

  /*
   * Check if an instruction word looks like a function prologue.
   * ARM function prologues typically:
   * - PUSH {regs} or STMFD SP!, {regs} - save registers
   * - MOV R11, SP or MOV R7, SP - set up frame pointer
   * - SUB SP, SP, #imm - allocate stack space
   *
   * Returns true if this looks like a function start.
   */
  bool IsFunctionPrologue(uint32_t instrWord)
  {
    // PUSH {regs} - encoded as STMDB SP!, {regs} with writeback
    // Encoding: cond 100 1 0 0 1 0 1101 reglist
    // Mask: 0x0FFF0000, expect: 0x092D0000 (unconditional: 0xE92D0000)
    if ((instrWord & 0x0FFF0000) == 0x092D0000)
    {
      uint16_t reglist = instrWord & 0xFFFF;
      // Valid prologue typically saves LR and possibly other regs
      // At minimum, PUSH {LR} (reglist bit 14 set)
      if (reglist & (1 << 14))  // LR is saved
        return true;
      // Or saves multiple registers (r4-r11 range)
      if (__builtin_popcount(reglist & 0x0FF0) >= 2)  // At least 2 of r4-r11
        return true;
    }

    // STMFD SP!, {regs} - same encoding, alternate mnemonic
    // Already covered above

    // MOV R11, SP (frame pointer setup) - common in AAPCS
    // Encoding: cond 0001101 S 0000 Rd 00000000 Rm
    // MOV R11, SP: 0xE1A0B00D (Rd=11=0xB, Rm=13=0xD)
    if ((instrWord & 0x0FFFFFFF) == 0x01A0B00D)
      return true;

    // MOV R7, SP (Thumb-compatible frame pointer)
    // MOV R7, SP: 0xE1A0700D (Rd=7, Rm=13)
    if ((instrWord & 0x0FFFFFFF) == 0x01A0700D)
      return true;

    // SUB SP, SP, #imm (stack allocation) - can be a prologue indicator
    // Encoding: cond 0010 0100 1101 1101 imm12
    // Mask: 0x0FFF0000, expect: 0x024DD000
    if ((instrWord & 0x0FFF0000) == 0x024DD000)
    {
      // Only count as prologue if allocating reasonable stack (4-4096 bytes)
      uint32_t imm12 = instrWord & 0xFFF;
      uint32_t rotate = (imm12 >> 8) & 0xF;
      uint32_t imm8 = imm12 & 0xFF;
      uint32_t stackSize = (imm8 >> (rotate * 2)) | (imm8 << (32 - rotate * 2));
      if (stackSize >= 4 && stackSize <= 4096)
        return true;
    }

    return false;
  }

  /*
   * Check if an instruction word looks like a function epilogue.
   * ARM function epilogues typically:
   * - POP {regs, PC} or LDMFD SP!, {regs, PC} - restore registers and return
   * - BX LR - return via link register
   * - MOV PC, LR - return via link register
   *
   * Returns true if this looks like a function end.
   */
  bool IsFunctionEpilogue(uint32_t instrWord)
  {
    // POP {regs, PC} - encoded as LDMIA SP!, {regs} with PC in reglist
    // Encoding: cond 100 0 1 0 1 1 1101 reglist
    // Mask: 0x0FFF0000, expect: 0x08BD0000
    if ((instrWord & 0x0FFF0000) == 0x08BD0000)
    {
      uint16_t reglist = instrWord & 0xFFFF;
      // PC must be in the register list for this to be a return
      if (reglist & (1 << 15))  // PC is loaded
        return true;
    }

    // LDMFD SP!, {regs, PC} - same encoding, alternate mnemonic
    // Already covered above

    // BX LR - return via link register
    // Encoding: cond 0001 0010 1111 1111 1111 0001 Rm
    // BX LR: 0xE12FFF1E (Rm=14=LR)
    if ((instrWord & 0x0FFFFFFF) == 0x012FFF1E)
      return true;

    // MOV PC, LR - return via link register (older style)
    // Encoding: cond 0001101 S 0000 1111 00000000 1110
    // MOV PC, LR: 0xE1A0F00E (Rd=15=PC, Rm=14=LR)
    if ((instrWord & 0x0FFFFFFF) == 0x01A0F00E)
      return true;

    // LDMFD SP!, {regs}^ with PC - return from exception with SPSR restore
    // Encoding: cond 100 0 1 1 0 1 1101 reglist (bit 22 set for ^ modifier)
    // Mask: 0x0FFF0000, expect: 0x08DD0000
    if ((instrWord & 0x0FDF0000) == 0x08DD0000)
    {
      uint16_t reglist = instrWord & 0xFFFF;
      if (reglist & (1 << 15))  // PC is loaded
        return true;
    }

    return false;
  }

  /*
   * Check if an instruction word looks like literal pool data rather than code.
   * Literal pools contain constants loaded via PC-relative LDR instructions.
   * Common patterns:
   * - Addresses (0x10xxxxxx, 0x11xxxxxx, etc.)
   * - Small constants that look like addresses
   * - MMIO addresses (0x90xxxxxx, 0xDCxxxxxx, etc.)
   *
   * This is checked AFTER IsLikelyData() - it catches values that decode
   * to valid instructions but are actually data.
   */
  bool IsLikelyLiteralPoolEntry(uint32_t instrWord, uint64_t addr)
  {
    // Address-like patterns common in literal pools:
    // - ROM addresses: 0x00xxxxxx, 0x10xxxxxx, 0x11xxxxxx, 0x13xxxxxx
    // - SRAM addresses: 0xA4xxxxxx
    // - MMIO addresses: 0x90xxxxxx, 0xDCxxxxxx

    uint32_t highByte = (instrWord >> 24) & 0xFF;

    // Common firmware base addresses
    if (highByte == 0x10 || highByte == 0x11 || highByte == 0x12 || highByte == 0x13)
    {
      // Check if it looks like an aligned address
      if ((instrWord & 0x3) == 0)  // 4-byte aligned
        return true;
    }

    // SRAM/uncached RAM alias range
    if (highByte == 0xA4)
    {
      if ((instrWord & 0x3) == 0)
        return true;
    }

    // MMIO/peripheral ranges
    if (highByte == 0x90 || highByte == 0x91 || highByte == 0xDC)
    {
      if ((instrWord & 0x3) == 0)
        return true;
    }

    // Zero or small positive constants (common in literal pools)
    // But be careful - these can also be NOP or valid instructions
    // Only flag as literal pool if it's a suspiciously round number
    if (instrWord == 0x00000000)
      return false;  // Could be NOP (andeq r0, r0, r0), let other checks handle it

    return false;
  }

  /*
   * Heuristic to detect instruction patterns that are likely data, not code.
   * ARM's dense instruction encoding means almost any 32-bit value decodes to
   * something, but certain patterns are very unlikely to appear in real code.
   *
   * PERFORMANCE: Checks are ordered from cheapest to most expensive:
   * 1. Pure bit pattern checks (no struct access)
   * 2. Simple operation enum checks
   * 3. Register/operand field checks
   * 4. Loop-based checks (most expensive)
   *
   * Reference: firebird emulator disasm.c uses mask-value tables with explicit
   * invalid patterns marked as "???"
   */
  bool IsLikelyData(uint32_t instrWord, const Instruction& instr)
  {
    // Extract commonly used bit fields once
    uint32_t cond = (instrWord >> 28) & 0xF;
    uint32_t bits27_25 = (instrWord >> 25) & 0x7;
    uint32_t highByte = (instrWord >> 24) & 0xFF;

    // === FAST PATH: Pure bit pattern checks (no struct access) ===

    // Pattern: ASCII string / text data detection
    // ASCII strings decode to ARM instructions with unusual condition codes
    // (MI, PL, VS, VC) because printable ASCII has bit 5 or 6 set.
    //
    // IMPORTANT: Skip this check for common valid instructions like branches,
    // because their encoding can accidentally match ASCII patterns.
    // For example: B 0x... (0xEAxxxxxx) can have printable + null bytes.
    {
      // First check if this is a common valid instruction that we should NOT
      // flag as ASCII even if the bytes look like text.
      bool isCommonValidInstruction = false;
      switch (instr.operation)
      {
        // Branches - very common, encoding can look like ASCII
        case ARMV5_B:
        case ARMV5_BL:
        case ARMV5_BX:
        case ARMV5_BLX:
        // Load/store - common instructions
        case ARMV5_LDR:
        case ARMV5_STR:
        case ARMV5_LDM:
        case ARMV5_STM:
        case ARMV5_LDMIA:
        case ARMV5_LDMIB:
        case ARMV5_LDMDA:
        case ARMV5_LDMDB:
        case ARMV5_STMIA:
        case ARMV5_STMIB:
        case ARMV5_STMDA:
        case ARMV5_STMDB:
        case ARMV5_PUSH:
        case ARMV5_POP:
        // Data processing with common condition codes (AL, EQ, NE, etc.)
        case ARMV5_MOV:
        case ARMV5_ADD:
        case ARMV5_SUB:
        case ARMV5_CMP:
        case ARMV5_AND:
        case ARMV5_ORR:
          // These are valid if condition is common (AL, EQ, NE, CS, CC, etc.)
          if (cond <= 0xE)  // Not condition 0xF (unconditional/special)
            isCommonValidInstruction = true;
          break;
        default:
          break;
      }

      // Only apply ASCII detection to unusual instructions
      if (!isCommonValidInstruction)
      {
        uint8_t b0 = (instrWord >> 0) & 0xFF;
        uint8_t b1 = (instrWord >> 8) & 0xFF;
        uint8_t b2 = (instrWord >> 16) & 0xFF;
        uint8_t b3 = (instrWord >> 24) & 0xFF;
        
        // Printable ASCII: space through tilde
        auto isPrintable = [](uint8_t c) { return c >= 0x20 && c <= 0x7E; };
        
        // Text characters: printable + common control characters found in strings
        auto isTextChar = [](uint8_t c) { 
          if (c >= 0x20 && c <= 0x7E) return true;  // Printable
          if (c == 0x00) return true;  // Null terminator
          if (c == 0x09) return true;  // Tab
          if (c == 0x0A) return true;  // LF
          if (c == 0x0D) return true;  // CR
          if (c == 0x1B) return true;  // ESC (ANSI escape sequences)
          return false;
        };
        
        // Control characters that appear in text but not in code
        auto isControlChar = [](uint8_t c) {
          return c == 0x00 || c == 0x09 || c == 0x0A || c == 0x0D || c == 0x1B;
        };
        
        int printableCount = isPrintable(b0) + isPrintable(b1) + isPrintable(b2) + isPrintable(b3);
        int textCount = isTextChar(b0) + isTextChar(b1) + isTextChar(b2) + isTextChar(b3);
        int controlCount = isControlChar(b0) + isControlChar(b1) + isControlChar(b2) + isControlChar(b3);
        
        // All 4 bytes printable ASCII -> definitely a string
        if (printableCount == 4)
          return true;
        
        // All 4 bytes are text characters (printable + control) -> likely text
        if (textCount == 4 && printableCount >= 2)
          return true;
        
        // Mix of printable and control chars is very suspicious
        // Real code rarely has CR/LF/ESC bytes mixed with printable ASCII
        if (printableCount >= 2 && controlCount >= 1 && (printableCount + controlCount >= 3))
          return true;
      }
    }

    // Pattern 1: Condition code 0xF with invalid encoding
    // Only PLD, BLX (immediate), and coprocessor instructions are valid
    if (cond == 0xF)
    {
      // Coprocessor instructions (bits 27:24 = 1100, 1101, 1110) are valid
      uint32_t bits27_24 = highByte & 0xF;
      bool isCoproc = (bits27_24 >= 0xC && bits27_24 <= 0xE);

      if (instr.operation != ARMV5_BLX && instr.operation != ARMV5_PLD && !isCoproc)
        return true;
    }

    // Pattern: Branch encoding (bits 27:25 = 101) should decode to B/BL
    if (bits27_25 == 0x5)
    {
      if (instr.operation != ARMV5_B && instr.operation != ARMV5_BL)
        return true;
    }

    // Pattern: Coprocessor load/store to invalid coprocessor
    // bits27_25 == 6 covers LDC/STC and MCRR/MRRC instructions
    // Valid coprocessors: p10/p11 (VFP), p14 (debug), p15 (system control)
    if (bits27_25 == 0x6)
    {
      uint32_t cpnum = (instrWord >> 8) & 0xF;
      if (cpnum != 10 && cpnum != 11 && cpnum != 14 && cpnum != 15)
        return true;
    }

    // Pattern: Coprocessor data/transfer to invalid coprocessor
    if (bits27_25 == 0x7)
    {
      uint32_t bit24 = (instrWord >> 24) & 0x1;
      if (bit24 == 0)  // Coprocessor (not SWI)
      {
        uint32_t cpnum = (instrWord >> 8) & 0xF;
        if (cpnum != 10 && cpnum != 11 && cpnum != 14 && cpnum != 15)
          return true;
      }
    }

    // Pattern: Explicitly undefined instruction space
    // ARM architecture reserves this encoding as permanently undefined
    // From ARM ARM: when bits 27:25 = 011, bit 4 = 1, bits 24:20 = 11111
    // Reference: Firebird emulator arm_interpreter.cpp line 430
    if ((instrWord & 0x0FF000F0) == 0x07F000F0)
      return true;

    // Pattern: Invalid multiply encoding
    // Bits 27:25 = 000, bits 7:4 = 1001 is the multiply group
    // If our decoder produced something other than a multiply, it's invalid
    // Reference: Firebird disasm.c line 84: {0xE0000F0, 0x0000090, "???"}
    if ((instrWord & 0x0E0000F0) == 0x00000090)
    {
      // This has the multiply signature - verify it decoded to a valid multiply
      if (instr.operation != ARMV5_MUL && instr.operation != ARMV5_MULS &&
          instr.operation != ARMV5_MLA &&
          instr.operation != ARMV5_UMULL && instr.operation != ARMV5_UMLAL &&
          instr.operation != ARMV5_SMULL && instr.operation != ARMV5_SMLAL &&
          instr.operation != ARMV5_SWP && instr.operation != ARMV5_SWPB &&
          // DSP multiplies also use this encoding space
          instr.operation != ARMV5_SMULBB && instr.operation != ARMV5_SMULBT &&
          instr.operation != ARMV5_SMULTB && instr.operation != ARMV5_SMULTT &&
          instr.operation != ARMV5_SMULWB && instr.operation != ARMV5_SMULWT &&
          instr.operation != ARMV5_SMLABB && instr.operation != ARMV5_SMLABT &&
          instr.operation != ARMV5_SMLATB && instr.operation != ARMV5_SMLATT &&
          instr.operation != ARMV5_SMLAWB && instr.operation != ARMV5_SMLAWT &&
          instr.operation != ARMV5_SMLALBB && instr.operation != ARMV5_SMLALBT &&
          instr.operation != ARMV5_SMLALTB && instr.operation != ARMV5_SMLALTT &&
          // Saturating adds also share the encoding
          instr.operation != ARMV5_QADD && instr.operation != ARMV5_QSUB &&
          instr.operation != ARMV5_QDADD && instr.operation != ARMV5_QDSUB)
        return true;
    }

    // === MEDIUM PATH: Simple operation enum checks ===

    // Note: RSC is rare but valid - don't reject it outright
    // It's used for multi-word arithmetic (e.g., 64-bit negation)

    // Pattern: Long multiply with unusual flags/registers
    if (instr.operation == ARMV5_UMULL || instr.operation == ARMV5_UMLAL ||
        instr.operation == ARMV5_SMULL || instr.operation == ARMV5_SMLAL)
    {
      // Conditional + S flag together is extremely rare for 64-bit multiply
      if (instr.setsFlags && CONDITIONAL(instr.cond))
        return true;

      // Check for overlapping RdLo/RdHi with Rm/Rs (UNPREDICTABLE)
      if (instr.operands[0].reg == instr.operands[2].reg ||
          instr.operands[0].reg == instr.operands[3].reg ||
          instr.operands[1].reg == instr.operands[2].reg ||
          instr.operands[1].reg == instr.operands[3].reg)
        return true;

      // Destination to PC is very unusual (LR is fine - often used as scratch after push)
      if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
        return true;
      if (instr.operands[1].cls == REG && instr.operands[1].reg == REG_PC)
        return true;

      // Source from PC or SP is unusual
      if (instr.operands[2].cls == REG &&
          (instr.operands[2].reg == REG_PC || instr.operands[2].reg == REG_SP))
        return true;
      if (instr.operands[3].cls == REG &&
          (instr.operands[3].reg == REG_PC || instr.operands[3].reg == REG_SP))
        return true;
    }

    // Pattern: Compare/test with PC as Rn
    if (instr.operation == ARMV5_TST || instr.operation == ARMV5_TEQ ||
        instr.operation == ARMV5_CMP || instr.operation == ARMV5_CMN)
    {
      if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
        return true;
    }

    // Pattern: ADC/SBC with LR as destination
    if ((instr.operation == ARMV5_ADC || instr.operation == ARMV5_ADCS ||
         instr.operation == ARMV5_SBC || instr.operation == ARMV5_SBCS) &&
        instr.operands[0].cls == REG && instr.operands[0].reg == REG_LR)
      return true;

    // Pattern: Data processing with PC as source (except ADD/SUB/MOV)
    if (instr.operands[1].cls == REG && instr.operands[1].reg == REG_PC)
    {
      if (instr.operation != ARMV5_ADD && instr.operation != ARMV5_ADDS &&
          instr.operation != ARMV5_SUB && instr.operation != ARMV5_SUBS &&
          instr.operation != ARMV5_MOV && instr.operation != ARMV5_MOVS)
        return true;
    }

    // === SLOWER PATH: Loop-based and address pattern checks ===

    // Pattern: SP as shift amount register (loop through operands)
    for (int i = 0; i < MAX_OPERANDS; i++)
    {
      if (instr.operands[i].cls == NONE)
        break;
      if (instr.operands[i].flags.offsetRegUsed && instr.operands[i].offset == REG_SP)
        return true;
    }

    // === ADDRESS PATTERN CHECKS: Detect common literal pool values ===
    // These are addresses that decode to valid-looking instructions but are actually data

    // 0x10xxxxxx - 0x13xxxxxx: ROM/Flash addresses
    // Check if 4-byte aligned and decodes to suspicious instruction
    if (highByte >= 0x10 && highByte <= 0x13 && (instrWord & 0x3) == 0)
    {
      // ADC/SBC with conditional + S flag is rare in real code
      if ((instr.operation == ARMV5_ADC || instr.operation == ARMV5_ADCS ||
           instr.operation == ARMV5_SBC || instr.operation == ARMV5_SBCS) &&
          CONDITIONAL(instr.cond) && instr.setsFlags)
        return true;
    }

    // 0xA4xxxxxx: SRAM addresses (decode to various instructions)
    if (highByte == 0xA4)
    {
      if ((instrWord & 0x3) == 0)
      {
        // SRAM addresses commonly decode to BCS/BCC (0xAxxxxxxx branch encoding)
        // but with suspicious target addresses
        if (instr.operation == ARMV5_B)
        {
          // Branch target would be way outside any reasonable code range
          // If the instruction decodes as a branch but the offset would be huge
          int32_t offset = (instrWord & 0x00FFFFFF);
          if (offset & 0x800000)
            offset |= 0xFF000000;  // Sign extend
          // If branch offset > 16MB, likely data
          if (offset > 0x1000000 || offset < -0x1000000)
            return true;
        }
      }
    }

    // 0x90xxxxxx, 0xDCxxxxxx: MMIO addresses
    if (highByte == 0x90 || highByte == 0x91 || highByte == 0xDC)
    {
      if ((instrWord & 0x3) == 0)
      {
        // MMIO addresses decode to various coprocessor or multiply patterns
        // If we got here without matching earlier coprocessor checks, flag it
        if (bits27_25 == 0x0)  // Data processing (register)
        {
          // Check for multiply operations with unusual register combos
          // 0x90xxxxxx often decodes to MUL/MLA variants
          if (instr.operation == ARMV5_MUL || instr.operation == ARMV5_MLA)
          {
            // Check for PC/SP as operands (unusual for multiply)
            for (int i = 0; i < MAX_OPERANDS && instr.operands[i].cls != NONE; i++)
            {
              if (instr.operands[i].cls == REG &&
                  (instr.operands[i].reg == REG_PC || instr.operands[i].reg == REG_SP))
                return true;
            }
          }
        }
      }
    }

    return false;
  }

  virtual bool GetInstructionInfo(const uint8_t *data, uint64_t addr, size_t maxLen, InstructionInfo &result) override
  {
    if (maxLen < 4)
      return false;
    Instruction instr;
    if (!Disassemble(data, addr, maxLen, instr))
    {
      uint32_t instrWord = ReadInstructionWord(data);
      if (instrWord == 0xE1A00000)
      {
        result.length = 4;
        return true;
      }
      return false;
    }

    /* Return false for undefined/unpredictable instructions - matches ARMv7 pattern */
    if (instr.operation == ARMV5_UNDEFINED || instr.operation == ARMV5_UDF ||
      instr.operation == ARMV5_UNPREDICTABLE)
  {
    return false;
  }

    SetInstructionInfoForInstruction(addr, instr, result);
    return true;
  }

  virtual bool GetInstructionText(const uint8_t *data, uint64_t addr, size_t &len,
                                  std::vector<InstructionTextToken> &result) override
  {
    Instruction instr;
    if (!Disassemble(data, addr, 4, instr))
    {
      uint32_t instrWord = ReadInstructionWord(data);
      if (instrWord == 0xE1A00000)
      {
        len = 4;
        result.emplace_back(InstructionToken, "nop");
        return true;
      }
      len = 4;
      return false;
    }

    /* Return false for undefined/unpredictable instructions - matches ARMv7 pattern */
    if (instr.operation == ARMV5_UNDEFINED || instr.operation == ARMV5_UDF ||
        instr.operation == ARMV5_UNPREDICTABLE)
    {
      len = 4;
      return false;
    }

    len = 4;

    int operandCount = GetOperandCount(instr);

    /* Operation name */
    const char *opname = get_operation(instr.operation);
    const char *cond = "";
    if (CONDITIONAL(instr.cond))
    {
      cond = get_condition(instr.cond);
    }
    auto allowsSuffixS = [](Operation op)
    {
      switch (op)
      {
      case ARMV5_AND:
      case ARMV5_EOR:
      case ARMV5_SUB:
      case ARMV5_RSB:
      case ARMV5_ADD:
      case ARMV5_ADC:
      case ARMV5_SBC:
      case ARMV5_RSC:
      case ARMV5_ORR:
      case ARMV5_MOV:
      case ARMV5_BIC:
      case ARMV5_MVN:
        return true;
      default:
        return false;
      }
    };
    const char *s = (instr.setsFlags && allowsSuffixS(instr.operation)) ? "s" : "";

    string mnemonic = string(opname) + cond + s;
    result.emplace_back(InstructionToken, mnemonic);

    if (operandCount > 0)
    {
      result.emplace_back(TextToken, " ");
    }

    for (int i = 0; i < operandCount; i++)
    {
      if (i > 0)
      {
        result.emplace_back(OperandSeparatorToken, ", ");
      }

      const InstructionOperand &op = instr.operands[i];

      switch (op.cls)
      {
      case REG:
      {
        const char *name = get_register_name(op.reg);
        if (name)
        {
          result.emplace_back(RegisterToken, name, (uint32_t)op.reg);
        }
        else if (op.reg >= REG_S0 && op.reg <= REG_S31)
        {
          char buf[8];
          snprintf(buf, sizeof(buf), "s%d", op.reg - REG_S0);
          result.emplace_back(RegisterToken, buf, (uint32_t)op.reg);
        }
        else if (op.reg >= REG_D0 && op.reg <= REG_D15)
        {
          char buf[8];
          snprintf(buf, sizeof(buf), "d%d", op.reg - REG_D0);
          result.emplace_back(RegisterToken, buf, (uint32_t)op.reg);
        }
        if (op.shift != SHIFT_NONE)
        {
          result.emplace_back(TextToken, ", ");
          result.emplace_back(TextToken, get_shift(op.shift));
          result.emplace_back(TextToken, " ");
          if (op.flags.offsetRegUsed && op.offset != REG_INVALID)
          {
            const char *offsetName = get_register_name(op.offset);
            if (offsetName)
              result.emplace_back(RegisterToken, offsetName, (uint32_t)op.offset);
          }
          else
          {
            char buf[16];
            snprintf(buf, sizeof(buf), "#0x%x", op.imm);
            result.emplace_back(TextToken, buf);
          }
        }
        if (op.flags.wb && op.cls == REG)
        {
          result.emplace_back(TextToken, "!");
        }
        break;
      }

      case REG_COPROCP:
      {
        /* Coprocessor number: p0-p15 */
        char buf[8];
        snprintf(buf, sizeof(buf), "p%d", op.reg);
        result.emplace_back(RegisterToken, buf, (uint32_t)op.reg);
        break;
      }

      case REG_COPROCC:
      {
        /* Coprocessor register: c0-c15 */
        char buf[8];
        snprintf(buf, sizeof(buf), "c%d", op.reg);
        result.emplace_back(RegisterToken, buf, (uint32_t)op.reg);
        break;
      }

      case COPROC_OPC:
      {
        /* Coprocessor opcode: plain number without # prefix */
        char buf[8];
        snprintf(buf, sizeof(buf), "%d", (int)op.imm);
        result.emplace_back(IntegerToken, buf, op.imm);
        break;
      }

      case IMM:
      {
        char buf[32];
        snprintf(buf, sizeof(buf), "#0x%llx", (unsigned long long)op.imm);
        result.emplace_back(IntegerToken, buf, op.imm);
        break;
      }

      case LABEL:
      {
        /* For load/store, wrap in brackets to show memory dereference */
        bool isLoadStore = (instr.operation == ARMV5_LDR || instr.operation == ARMV5_LDRB ||
                            instr.operation == ARMV5_LDRH || instr.operation == ARMV5_LDRSB ||
                            instr.operation == ARMV5_LDRSH || instr.operation == ARMV5_LDRD ||
                            instr.operation == ARMV5_STR || instr.operation == ARMV5_STRB ||
                            instr.operation == ARMV5_STRH || instr.operation == ARMV5_STRD);
        if (isLoadStore)
        {
          result.emplace_back(BeginMemoryOperandToken, "[");
        }
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)op.imm);
        result.emplace_back(PossibleAddressToken, buf, op.imm);
        if (isLoadStore)
        {
          result.emplace_back(EndMemoryOperandToken, "]");
        }
        break;
      }

      case REG_LIST:
      {
        result.emplace_back(BeginMemoryOperandToken, "{");
        bool first = true;
        uint32_t regList = op.imm;
        for (int r = 0; r < 16; r++)
        {
          if (regList & (1 << r))
          {
            if (!first)
            {
              result.emplace_back(OperandSeparatorToken, ", ");
            }
            const char *regName = get_register_name((::Register)r);
            if (regName)
              result.emplace_back(RegisterToken, regName, r);
            first = false;
          }
        }
        result.emplace_back(EndMemoryOperandToken, "}");
        /* Add ^ suffix if S bit was set (user mode / exception return) */
        if (op.flags.wb)
          result.emplace_back(OperationToken, " ^");
        break;
      }

      case MEM_IMM:
      case MEM_REG:
      case MEM_PRE_IDX:
      case MEM_POST_IDX:
      {
        bool postIndexed = (op.cls == MEM_POST_IDX);

        result.emplace_back(BeginMemoryOperandToken, "[");
        const char *regName = get_register_name(op.reg);
        if (regName)
          result.emplace_back(RegisterToken, regName, (uint32_t)op.reg);

        if (!postIndexed)
        {
          if (op.flags.offsetRegUsed && op.offset != REG_INVALID)
          {
            result.emplace_back(TextToken, ", ");
            if (!op.flags.add)
              result.emplace_back(TextToken, "-");
            const char *offsetName = get_register_name(op.offset);
            if (offsetName)
              result.emplace_back(RegisterToken, offsetName, (uint32_t)op.offset);
            if (op.shift != SHIFT_NONE)
            {
              result.emplace_back(TextToken, ", ");
              result.emplace_back(TextToken, get_shift(op.shift));
              char buf[16];
              snprintf(buf, sizeof(buf), " #0x%x", op.imm);
              result.emplace_back(IntegerToken, buf, op.imm);
            }
          }
          else if (op.imm != 0)
          {
            long long v = (long long)(int32_t)op.imm;
            if (!op.flags.add)
              v = -v;
            unsigned long long absv = (unsigned long long)(v < 0 ? -v : v);
            char buf[32];
            snprintf(buf, sizeof(buf), ", #%s0x%llx", v < 0 ? "-" : "", absv);
            result.emplace_back(TextToken, buf);
          }
          result.emplace_back(EndMemoryOperandToken, "]");
          if (op.flags.wb)
          {
            result.emplace_back(TextToken, "!");
          }
        }
        else
        {
          result.emplace_back(EndMemoryOperandToken, "]");
          result.emplace_back(TextToken, ", ");
          if (op.flags.offsetRegUsed && op.offset != REG_INVALID)
          {
            if (!op.flags.add)
              result.emplace_back(TextToken, "-");
            const char *offsetName = get_register_name(op.offset);
            if (offsetName)
              result.emplace_back(RegisterToken, offsetName, (uint32_t)op.offset);
          }
          else
          {
            long long v = (long long)(int32_t)op.imm;
            if (!op.flags.add)
              v = -v;
            unsigned long long absv = (unsigned long long)(v < 0 ? -v : v);
            char buf[32];
            snprintf(buf, sizeof(buf), "#%s0x%llx", v < 0 ? "-" : "", absv);
            result.emplace_back(IntegerToken, buf, op.imm);
          }
        }
        break;
      }

      case SYS_REG:
        if (op.reg == REG_CPSR)
        {
          result.emplace_back(RegisterToken, "cpsr");
        }
        else if (op.reg == REG_SPSR)
        {
          result.emplace_back(RegisterToken, "spsr");
        }
        else if (op.reg == REG_FPSCR)
        {
          result.emplace_back(RegisterToken, "fpscr");
        }
        else if (op.reg == REG_FPSID)
        {
          result.emplace_back(RegisterToken, "fpsid");
        }
        else if (op.reg == REG_FPEXC)
        {
          result.emplace_back(RegisterToken, "fpexc");
        }
        else
        {
          // For CPSR/SPSR with flags mask, use the register name directly
          const char* name = get_register_name(op.reg);
          result.emplace_back(RegisterToken, name ? name : "???");
        }
        break;

      case FIMM:
      {
        /* Floating-point immediate (used for VCMP/VCMPE with zero) */
        char buf[32];
        snprintf(buf, sizeof(buf), "#%.1f", (double)op.immf);
        result.emplace_back(IntegerToken, buf, (uint64_t)0);
        break;
      }

      default:
        break;
      }
    }

    return true;
  }

  virtual bool GetInstructionLowLevelIL(const uint8_t *data, uint64_t addr, size_t &len,
                                        LowLevelILFunction &il) override
  {
    Instruction instr;
    if (!Disassemble(data, addr, len, instr))
    {
      uint32_t instrWord = ReadInstructionWord(data);
      if (instrWord == 0xE1A00000)
      {
        il.AddInstruction(il.Nop());
        len = 4;
        return true;
      }
      il.AddInstruction(il.Undefined());
      len = 4;
      return false;
    }

    /* Return false for undefined/unpredictable instructions - matches ARMv7 pattern */
    if (instr.operation == ARMV5_UNDEFINED || instr.operation == ARMV5_UDF ||
        instr.operation == ARMV5_UNPREDICTABLE)
    {
      il.AddInstruction(il.Undefined());
      len = 4;
      return false;
    }

    /* Use coalescing for conditional instructions */
    if (!UNCONDITIONAL(instr.cond))
      return GetCoalescedLowLevelIL(data, addr, len, il, instr);

    len = 4;
    return GetLowLevelILForArmInstruction(this, addr, il, instr, 4);
  }

  virtual string GetIntrinsicName(uint32_t intrinsic) override
  {
    switch (intrinsic)
    {
    case ARMV5_INTRIN_CLZ:
      return "CountLeadingZeros";
    case ARMV5_INTRIN_QADD:
      return "SaturatingAdd";
    case ARMV5_INTRIN_QSUB:
      return "SaturatingSub";
    case ARMV5_INTRIN_QDADD:
      return "SaturatingDoubleAdd";
    case ARMV5_INTRIN_QDSUB:
      return "SaturatingDoubleSub";
    case ARMV5_INTRIN_SMULBB:
      return "SignedMulBottomBottom";
    case ARMV5_INTRIN_SMULBT:
      return "SignedMulBottomTop";
    case ARMV5_INTRIN_SMULTB:
      return "SignedMulTopBottom";
    case ARMV5_INTRIN_SMULTT:
      return "SignedMulTopTop";
    case ARMV5_INTRIN_SMULWB:
      return "SignedMulWordBottom";
    case ARMV5_INTRIN_SMULWT:
      return "SignedMulWordTop";
    case ARMV5_INTRIN_SMLABB:
      return "SignedMulAccBottomBottom";
    case ARMV5_INTRIN_SMLABT:
      return "SignedMulAccBottomTop";
    case ARMV5_INTRIN_SMLATB:
      return "SignedMulAccTopBottom";
    case ARMV5_INTRIN_SMLATT:
      return "SignedMulAccTopTop";
    case ARMV5_INTRIN_SMLAWB:
      return "SignedMulAccWordBottom";
    case ARMV5_INTRIN_SMLAWT:
      return "SignedMulAccWordTop";
    case ARMV5_INTRIN_SMLALBB:
      return "SignedMulAccLongBottomBottom";
    case ARMV5_INTRIN_SMLALBT:
      return "SignedMulAccLongBottomTop";
    case ARMV5_INTRIN_SMLALTB:
      return "SignedMulAccLongTopBottom";
    case ARMV5_INTRIN_SMLALTT:
      return "SignedMulAccLongTopTop";
    case ARMV5_INTRIN_MRS:
      return "__get_CPSR";  /* MRS Rd, CPSR - like IDA */
    case ARMV5_INTRIN_MSR:
      return "__set_CPSR";  /* MSR CPSR, Rm - like IDA */
    case ARMV5_INTRIN_CDP:
      return "__cdp";       /* CDP - coprocessor data processing */
    case ARMV5_INTRIN_LDC:
      return "__ldc";       /* LDC - load coprocessor */
    case ARMV5_INTRIN_STC:
      return "__stc";       /* STC - store coprocessor */
    case ARMV5_INTRIN_MCR:
    case ARMV5_INTRIN_COPROC_SENDONEWORD:
      return "__mcr";       /* MCR p<cp>, <op1>, Rd, CRn, CRm, <op2> - like IDA */
    case ARMV5_INTRIN_MRC:
    case ARMV5_INTRIN_COPROC_GETONEWORD:
      return "__mrc";       /* MRC p<cp>, <op1>, Rd, CRn, CRm, <op2> - like IDA */
    case ARMV5_INTRIN_SWP:
      return "Swap";
    case ARMV5_INTRIN_SWPB:
      return "SwapByte";
    case ARMV5_INTRIN_BKPT:
      return "Breakpoint";
    case ARMV5_INTRIN_PLD:
      return "PreloadData";
    default:
      return "";
    }
  }

  virtual vector<uint32_t> GetAllIntrinsics() override
  {
    return vector<uint32_t>{
        ARMV5_INTRIN_CLZ,
        ARMV5_INTRIN_QADD,
        ARMV5_INTRIN_QSUB,
        ARMV5_INTRIN_QDADD,
        ARMV5_INTRIN_QDSUB,
        ARMV5_INTRIN_SMULBB,
        ARMV5_INTRIN_SMULBT,
        ARMV5_INTRIN_SMULTB,
        ARMV5_INTRIN_SMULTT,
        ARMV5_INTRIN_SMULWB,
        ARMV5_INTRIN_SMULWT,
        ARMV5_INTRIN_SMLABB,
        ARMV5_INTRIN_SMLABT,
        ARMV5_INTRIN_SMLATB,
        ARMV5_INTRIN_SMLATT,
        ARMV5_INTRIN_SMLAWB,
        ARMV5_INTRIN_SMLAWT,
        ARMV5_INTRIN_SMLALBB,
        ARMV5_INTRIN_SMLALBT,
        ARMV5_INTRIN_SMLALTB,
        ARMV5_INTRIN_SMLALTT,
        ARMV5_INTRIN_MRS,
        ARMV5_INTRIN_MSR,
        ARMV5_INTRIN_COPROC_GETONEWORD,
        ARMV5_INTRIN_COPROC_SENDONEWORD,
        ARMV5_INTRIN_COPROC_GETTWOWORDS,
        ARMV5_INTRIN_COPROC_SENDTWOWORDS,
        ARMV5_INTRIN_CDP,
        ARMV5_INTRIN_LDC,
        ARMV5_INTRIN_STC,
        ARMV5_INTRIN_MCR,
        ARMV5_INTRIN_MRC,
        ARMV5_INTRIN_SWP,
        ARMV5_INTRIN_SWPB,
        ARMV5_INTRIN_BKPT,
        ARMV5_INTRIN_PLD,
    };
  }

  virtual vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override
  {
    switch (intrinsic)
    {
    case ARMV5_INTRIN_CLZ:
      return {NameAndType("value", Type::IntegerType(4, false))};
    case ARMV5_INTRIN_QADD:
    case ARMV5_INTRIN_QSUB:
    case ARMV5_INTRIN_QDADD:
    case ARMV5_INTRIN_QDSUB:
    case ARMV5_INTRIN_SMULBB:
    case ARMV5_INTRIN_SMULBT:
    case ARMV5_INTRIN_SMULTB:
    case ARMV5_INTRIN_SMULTT:
    case ARMV5_INTRIN_SMULWB:
    case ARMV5_INTRIN_SMULWT:
    case ARMV5_INTRIN_SWP:
    case ARMV5_INTRIN_SWPB:
      return {
          NameAndType("a", Type::IntegerType(4, false)),
          NameAndType("b", Type::IntegerType(4, false)),
      };
    case ARMV5_INTRIN_SMLABB:
    case ARMV5_INTRIN_SMLABT:
    case ARMV5_INTRIN_SMLATB:
    case ARMV5_INTRIN_SMLATT:
    case ARMV5_INTRIN_SMLAWB:
    case ARMV5_INTRIN_SMLAWT:
      return {
          NameAndType("a", Type::IntegerType(4, false)),
          NameAndType("b", Type::IntegerType(4, false)),
          NameAndType("acc", Type::IntegerType(4, false)),
      };
    case ARMV5_INTRIN_SMLALBB:
    case ARMV5_INTRIN_SMLALBT:
    case ARMV5_INTRIN_SMLALTB:
    case ARMV5_INTRIN_SMLALTT:
      return {
          NameAndType("a", Type::IntegerType(4, false)),
          NameAndType("b", Type::IntegerType(4, false)),
          NameAndType("accLo", Type::IntegerType(4, false)),
          NameAndType("accHi", Type::IntegerType(4, false)),
      };
    case ARMV5_INTRIN_MRS:
      /* MRS: psr_type (0=CPSR, 1=SPSR) */
      return {
          NameAndType("psr", Type::IntegerType(1, false)),
      };
    case ARMV5_INTRIN_MSR:
      /* MSR: psr_mask, value */
      return {
          NameAndType("psr_mask", Type::IntegerType(1, false)),
          NameAndType("value", Type::IntegerType(4, false)),
      };
    case ARMV5_INTRIN_MRC:
    case ARMV5_INTRIN_COPROC_GETONEWORD:
      /* MRC: cp, opc1, CRn, CRm, opc2 */
      return {
          NameAndType("cp", Type::IntegerType(1, false)),
          NameAndType("opc1", Type::IntegerType(1, false)),
          NameAndType("CRn", Type::IntegerType(1, false)),
          NameAndType("CRm", Type::IntegerType(1, false)),
          NameAndType("opc2", Type::IntegerType(1, false)),
      };
    case ARMV5_INTRIN_MCR:
    case ARMV5_INTRIN_COPROC_SENDONEWORD:
      /* MCR: cp, opc1, value, CRn, CRm, opc2 */
      return {
          NameAndType("cp", Type::IntegerType(1, false)),
          NameAndType("opc1", Type::IntegerType(1, false)),
          NameAndType("value", Type::IntegerType(4, false)),
          NameAndType("CRn", Type::IntegerType(1, false)),
          NameAndType("CRm", Type::IntegerType(1, false)),
          NameAndType("opc2", Type::IntegerType(1, false)),
      };
    case ARMV5_INTRIN_PLD:
      return {
          NameAndType("address", Type::PointerType(4,
                                                   Confidence<Ref<Type>>(Type::VoidType(), 0),
                                                   Confidence<bool>(false),
                                                   Confidence<bool>(false),
                                                   PointerReferenceType)),
      };
    default:
      return vector<NameAndType>();
    }
  }

  virtual vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override
  {
    switch (intrinsic)
    {
    case ARMV5_INTRIN_CLZ:
    case ARMV5_INTRIN_QADD:
    case ARMV5_INTRIN_QSUB:
    case ARMV5_INTRIN_QDADD:
    case ARMV5_INTRIN_QDSUB:
    case ARMV5_INTRIN_SMULBB:
    case ARMV5_INTRIN_SMULBT:
    case ARMV5_INTRIN_SMULTB:
    case ARMV5_INTRIN_SMULTT:
    case ARMV5_INTRIN_SMULWB:
    case ARMV5_INTRIN_SMULWT:
    case ARMV5_INTRIN_SMLABB:
    case ARMV5_INTRIN_SMLABT:
    case ARMV5_INTRIN_SMLATB:
    case ARMV5_INTRIN_SMLATT:
    case ARMV5_INTRIN_SMLAWB:
    case ARMV5_INTRIN_SMLAWT:
    case ARMV5_INTRIN_MRS:
    case ARMV5_INTRIN_MRC:
    case ARMV5_INTRIN_COPROC_GETONEWORD:
    case ARMV5_INTRIN_SWP:
    case ARMV5_INTRIN_SWPB:
      return {Type::IntegerType(4, false)};
    case ARMV5_INTRIN_SMLALBB:
    case ARMV5_INTRIN_SMLALBT:
    case ARMV5_INTRIN_SMLALTB:
    case ARMV5_INTRIN_SMLALTT:
      /* Returns two 32-bit values (64-bit result split) */
      return {Type::IntegerType(4, false), Type::IntegerType(4, false)};
    default:
      return vector<Confidence<Ref<Type>>>();
    }
  }

  virtual bool IsNeverBranchPatchAvailable(const uint8_t *data, uint64_t addr, size_t len) override
  {
    Instruction instr;
    if (!Disassemble(data, addr, len, instr))
      return false;
    return (instr.operation == ARMV5_B && CONDITIONAL(instr.cond));
  }

  virtual bool IsAlwaysBranchPatchAvailable(const uint8_t *data, uint64_t addr, size_t len) override
  {
    Instruction instr;
    if (!Disassemble(data, addr, len, instr))
      return false;
    return (instr.operation == ARMV5_B && CONDITIONAL(instr.cond));
  }

  virtual bool IsInvertBranchPatchAvailable(const uint8_t *data, uint64_t addr, size_t len) override
  {
    Instruction instr;
    if (!Disassemble(data, addr, len, instr))
      return false;
    return (instr.operation == ARMV5_B && CONDITIONAL(instr.cond));
  }

  virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t *data, uint64_t addr, size_t len) override
  {
    Instruction instr;
    if (!Disassemble(data, addr, len, instr))
      return false;
    return (instr.operation == ARMV5_BL) || (instr.operation == ARMV5_BLX);
  }

  virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t *data, uint64_t addr, size_t len) override
  {
    Instruction instr;
    if (!Disassemble(data, addr, len, instr))
      return false;
    return (instr.operation == ARMV5_BL) || (instr.operation == ARMV5_BLX);
  }

  virtual bool ConvertToNop(uint8_t *data, uint64_t addr, size_t len) override
  {
    (void)addr;
    /* ARM NOP: MOV R0, R0 (0xe1a00000) */
    uint32_t nop = 0xe1a00000;
    if (len < sizeof(nop))
      return false;
    for (size_t i = 0; i < len / sizeof(nop); i++)
      ((uint32_t *)data)[i] = nop;
    return true;
  }

  virtual bool AlwaysBranch(uint8_t *data, uint64_t addr, size_t len) override
  {
    (void)addr;
    if (len < 4)
      return false;
    /* Clear condition field (bits 31-28) and set to AL (0xe = always) */
    uint32_t *value = (uint32_t *)data;
    *value = (*value & 0x0fffffff) | (COND_AL << 28);
    return true;
  }

  virtual bool InvertBranch(uint8_t *data, uint64_t addr, size_t len) override
  {
    (void)addr;
    if (len < sizeof(uint32_t))
      return false;
    uint32_t *value = (uint32_t *)data;
    Condition cond = COND_AL;
    switch (*value >> 28)
    {
    case COND_EQ:
      cond = COND_NE;
      break;
    case COND_NE:
      cond = COND_EQ;
      break;
    case COND_CS:
      cond = COND_CC;
      break;
    case COND_CC:
      cond = COND_CS;
      break;
    case COND_MI:
      cond = COND_PL;
      break;
    case COND_PL:
      cond = COND_MI;
      break;
    case COND_VS:
      cond = COND_VC;
      break;
    case COND_VC:
      cond = COND_VS;
      break;
    case COND_HI:
      cond = COND_LS;
      break;
    case COND_LS:
      cond = COND_HI;
      break;
    case COND_GE:
      cond = COND_LT;
      break;
    case COND_LT:
      cond = COND_GE;
      break;
    case COND_GT:
      cond = COND_LE;
      break;
    case COND_LE:
      cond = COND_GT;
      break;
    default:
      return false;
    }
    *value = (*value & 0x0fffffff) | (cond << 28);
    return true;
  }

  virtual bool SkipAndReturnValue(uint8_t *data, uint64_t addr, size_t len, uint64_t value) override
  {
    (void)addr;
    /* Return value is put in R0. The largest value we can put in a single MOV is 12 bits */
    if (value > 0xfff || len < 4)
      return false;

    /* MOV R0, #value (0xe3a00000 | imm12) */
    uint32_t movValueR0 = 0xe3a00000;
    uint32_t *inst = (uint32_t *)data;
    *inst = movValueR0 | (value & 0xfff);
    return true;
  }

  /*
   * Custom analysis for ARM switch table detection.
   *
   * Pattern: ADD PC, PC, Rn (optionally with shift)
   * - Look backward for: ADD Rx, PC, #offset to get table base
   * - Look backward for: LDR Rx, [Rx, Rn, LSL #2] to confirm table access pattern
   * - Look backward for: CMP Rn, #max to get table bounds
   * - Compute all targets: PC_at_jump + 8 + table[i]
   */
  /*
   * Detect ARM switch table pattern and add indirect branch targets.
   *
   * Pattern: ADD PC, PC, Rn (optionally with shift)
   * - Look backward for: ADD Rx, PC, #offset to get table base
   * - Look backward for: CMP Rn, #max to get table bounds
   * - Compute all targets: PC_at_jump + 8 + table[i]
   *
   * This is called from GetInstructionInfo context indirectly through
   * the IndirectBranches provided in the analysis context.
   */
  bool DetectSwitchTable(BinaryView *view, uint64_t jumpAddr,
                         vector<pair<Ref<Architecture>, uint64_t>> &targets)
  {
    /* Read the jump instruction */
    DataBuffer data = view->ReadBuffer(jumpAddr, 4);
    if (data.GetLength() < 4)
      return false;

    Instruction instr;
    if (!Disassemble((const uint8_t *)data.GetData(), jumpAddr, 4, instr))
      return false;

    /* Check for ADD PC, PC, Rn pattern */
    if (instr.operation != ARMV5_ADD)
      return false;
    if (instr.operands[0].cls != REG || instr.operands[0].reg != REG_PC)
      return false;
    if (instr.operands[1].cls != REG || instr.operands[1].reg != REG_PC)
      return false;

    /* Found ADD PC, PC, Rx - scan backward to find table info */
    uint64_t tableBase = 0;
    uint32_t maxCases = 0;
    bool foundTable = false;
    bool hasCmp = false;

    /* Scan up to 16 instructions backward */
    for (int i = 1; i <= 16; i++)
    {
      uint64_t scanAddr = jumpAddr - (i * 4);
      DataBuffer scanData = view->ReadBuffer(scanAddr, 4);
      if (scanData.GetLength() < 4)
        break;

      Instruction scanInstr;
      if (!Disassemble((const uint8_t *)scanData.GetData(), scanAddr, 4, scanInstr))
        continue;

      /* Look for ADD Rx, PC, #imm (table base calculation) */
      if (!foundTable && scanInstr.operation == ARMV5_ADD &&
          scanInstr.operands[1].cls == REG && scanInstr.operands[1].reg == REG_PC &&
          scanInstr.operands[2].cls == IMM)
      {
        tableBase = scanAddr + 8 + scanInstr.operands[2].imm;
        foundTable = true;
      }

      /* Look for CMP Rx, #imm (bounds check) */
      if (maxCases == 0 && scanInstr.operation == ARMV5_CMP && scanInstr.operands[1].cls == IMM)
      {
        /* CMP Rx, #N followed by BHI/BCS means valid cases are 0..N-1 (N entries)
         * CMP Rx, #N followed by BGE/BPL means valid cases are 0..N-1 (N entries)
         * The comparison value is the first invalid case, so maxCases = imm */
        maxCases = (uint32_t)scanInstr.operands[1].imm;
        hasCmp = true;
        if (maxCases == 0)
          maxCases = 1; /* Ensure at least 1 entry */
      }

      if (foundTable && maxCases > 0)
        break;
    }

    if (!foundTable || tableBase == 0)
      return false;

    /* Default to reasonable max if no CMP found */
    if (maxCases == 0)
      maxCases = 16;
    else if (maxCases > 256)
      maxCases = 256;

    /* PC at the ADD instruction + 8 (pipeline) */
    uint64_t pcValue = jumpAddr + 8;

    /* Read the jump table and compute targets */
    uint32_t validEntries = 0;
    bool requireExecutable = view->IsOffsetExecutable(jumpAddr);
    for (uint32_t i = 0; i < maxCases; i++)
    {
      uint64_t entryAddr = tableBase + (i * 4);
      DataBuffer entryData = view->ReadBuffer(entryAddr, 4);
      if (entryData.GetLength() < 4)
        break;

      int32_t offset = *(int32_t *)entryData.GetData();

      /* Sanity check: offset should be reasonable */
      if ((offset > 0x100000) || (offset < -0x100000))
        break;
      if ((offset & 0x3) != 0)
        break;

      uint64_t target = pcValue + (int64_t)offset;
      uint64_t targetAddr = target;
      Ref<Architecture> targetArch = GetAssociatedArchitectureByAddress(targetAddr);

      if (!view->IsValidOffset(targetAddr))
        break;
      if (requireExecutable && !view->IsOffsetExecutable(targetAddr))
        break;

      targets.push_back({targetArch, targetAddr});
      validEntries++;
    }

    if (validEntries == 0)
      return false;
    if (!hasCmp && validEntries < 2)
      return false;
    return true;
  }

  bool DetectLdrPcJumpTable(BinaryView *view, uint64_t jumpAddr,
                            vector<pair<Ref<Architecture>, uint64_t>> &targets)
  {
    DataBuffer data = view->ReadBuffer(jumpAddr, 4);
    if (data.GetLength() < 4)
      return false;

    Instruction instr;
    if (!Disassemble((const uint8_t *)data.GetData(), jumpAddr, 4, instr))
      return false;

    if (instr.operation != ARMV5_LDR)
      return false;
    if (instr.operands[0].cls != REG || instr.operands[0].reg != REG_PC)
      return false;

    const InstructionOperand &memOp = instr.operands[1];
    if (memOp.cls != MEM_IMM)
      return false;
    if (memOp.reg != REG_PC)
      return false;
    if (!memOp.flags.offsetRegUsed || memOp.offset == REG_INVALID)
      return false;
    if (!memOp.flags.add)
      return false;
    if (memOp.shift != SHIFT_LSL || memOp.imm != 2)
      return false;

    uint64_t tableBase = jumpAddr + 8;
    const uint32_t maxEntries = 256;

    bool requireExecutable = view->IsOffsetExecutable(jumpAddr);
    for (uint32_t i = 0; i < maxEntries; i++)
    {
      uint64_t entryAddr = tableBase + (i * 4);
      DataBuffer entryData = view->ReadBuffer(entryAddr, 4);
      if (entryData.GetLength() < 4)
        break;

      uint32_t targetRaw = *(uint32_t *)entryData.GetData();
      uint64_t targetAddr = targetRaw;
      Ref<Architecture> targetArch = GetAssociatedArchitectureByAddress(targetAddr);
      if (!view->IsValidOffset(targetAddr))
        break;
      if (requireExecutable && !view->IsOffsetExecutable(targetAddr))
        break;

      targets.push_back({targetArch, targetAddr});
    }

    return !targets.empty();
  }

  bool DetectLdrPcLiteralTarget(BinaryView *view, uint64_t jumpAddr,
                                vector<pair<Ref<Architecture>, uint64_t>> &targets)
  {
    DataBuffer data = view->ReadBuffer(jumpAddr, 4);
    if (data.GetLength() < 4)
      return false;

    Instruction instr;
    if (!Disassemble((const uint8_t *)data.GetData(), jumpAddr, 4, instr))
      return false;

    if (instr.operation != ARMV5_LDR)
      return false;
    if (instr.operands[0].cls != REG || instr.operands[0].reg != REG_PC)
      return false;

    const InstructionOperand &memOp = instr.operands[1];
    uint64_t literalAddr = 0;
    if (memOp.cls == LABEL)
    {
      /* Disassembler pre-computes PC-relative effective address into LABEL */
      literalAddr = memOp.imm;
    }
    else
    {
      if (memOp.cls != MEM_IMM)
        return false;
      if (memOp.reg != REG_PC)
        return false;
      if (memOp.flags.offsetRegUsed)
        return false;

      literalAddr = jumpAddr + 8;
      if (memOp.flags.add)
        literalAddr += memOp.imm;
      else
        literalAddr -= memOp.imm;
    }

    DataBuffer entryData = view->ReadBuffer(literalAddr, 4);
    if (entryData.GetLength() < 4)
      return false;

    uint32_t targetRaw = *(uint32_t *)entryData.GetData();
    uint64_t targetAddr = targetRaw;
    Ref<Architecture> targetArch = GetAssociatedArchitectureByAddress(targetAddr);
    if (!view->IsValidOffset(targetAddr))
      return false;
    if (view->IsOffsetExecutable(jumpAddr) && !view->IsOffsetExecutable(targetAddr))
      return false;

    targets.push_back({targetArch, targetAddr});
    return true;
  }

  bool IsReturnThunk(BinaryView *view, uint64_t addr)
  {
    const uint32_t maxInstrs = 6;
    for (uint32_t i = 0; i < maxInstrs; i++)
    {
      uint64_t cur = addr + (i * 4);
      DataBuffer data = view->ReadBuffer(cur, 4);
      if (data.GetLength() < 4)
        return false;

      uint32_t word = *(const uint32_t *)data.GetData();
      if (word == 0xE1A00000) // NOP
        continue;

      Instruction instr;
      if (!Disassemble((const uint8_t *)data.GetData(), cur, 4, instr))
        return false;

      if (UNCONDITIONAL(instr.cond))
      {
        if (instr.operation == ARMV5_BX &&
            instr.operands[0].cls == REG && instr.operands[0].reg == REG_LR)
          return true;

        if (instr.operation == ARMV5_MOV &&
            instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC &&
            instr.operands[1].cls == REG && instr.operands[1].reg == REG_LR)
          return true;

        if (instr.operation == ARMV5_POP || instr.operation == ARMV5_LDM ||
            instr.operation == ARMV5_LDMIA || instr.operation == ARMV5_LDMIB ||
            instr.operation == ARMV5_LDMDA || instr.operation == ARMV5_LDMDB)
        {
          for (int op = 0; op < MAX_OPERANDS; op++)
          {
            if (instr.operands[op].cls == NONE)
              break;
            if (instr.operands[op].cls == REG_LIST &&
                (instr.operands[op].imm & (1U << REG_PC)))
              return true;
          }
        }
      }

      return false;
    }

    return false;
  }

  bool IsPaddingStart(BinaryView *view, uint64_t addr)
  {
    // Conservative padding detection for raw blobs:
    // - Require a run of NOPs/zeros.
    // - Require context: a preceding terminator/branch OR a following prologue.
    // - Never suppress if there's a direct call target into the gap.
    if (!view->GetCallers(addr).empty())
      return false;

    auto isPadWord = [](uint32_t word) {
      return (word == 0xE1A00000) || (word == 0x00000000);
    };

    const uint32_t maxPad = 16;
    const uint32_t minPad = 8;
    uint32_t padCount = 0;
    bool hasNonPad = false;
    uint32_t firstNonPadWord = 0;
    Instruction firstNonPadInstr{};

    for (uint32_t i = 0; i < maxPad; i++)
    {
      uint64_t cur = addr + (i * 4);
      DataBuffer data = view->ReadBuffer(cur, 4);
      if (data.GetLength() < 4)
        return false;

      uint32_t word = *(const uint32_t *)data.GetData();
      if (isPadWord(word))
      {
        padCount++;
        continue;
      }

      if (!Disassemble((const uint8_t *)data.GetData(), cur, 4, firstNonPadInstr))
        return false;
      firstNonPadWord = word;
      hasNonPad = true;
      break;
    }

    if (padCount < minPad)
      return false;

    bool prevIsTerminator = false;
    if (addr >= 4)
    {
      DataBuffer prevData = view->ReadBuffer(addr - 4, 4);
      if (prevData.GetLength() == 4)
      {
        uint32_t prevWord = *(const uint32_t *)prevData.GetData();
        if (IsFunctionEpilogue(prevWord))
          prevIsTerminator = true;

        Instruction prevInstr;
        if (!prevIsTerminator &&
            Disassemble((const uint8_t *)prevData.GetData(), addr - 4, 4, prevInstr))
        {
          if (prevInstr.operation == ARMV5_B && UNCONDITIONAL(prevInstr.cond))
            prevIsTerminator = true;
        }
      }
    }

    bool nextIsPrologue = false;
    if (hasNonPad)
    {
      if (IsFunctionPrologue(firstNonPadWord))
        nextIsPrologue = true;
    }

    // If we can't anchor the gap to a terminator or the next prologue, don't suppress it.
    if (!prevIsTerminator && !nextIsPrologue)
      return false;

    return true;
  }

  virtual void AnalyzeBasicBlocks(Function *function, BasicBlockAnalysisContext &context) override
  {
    auto data = function->GetView();
    queue<ArchAndAddr> blocksToProcess;
    map<ArchAndAddr, Ref<BasicBlock>> instrBlocks;
    set<ArchAndAddr> seenBlocks;

    bool guidedAnalysisMode = context.GetGuidedAnalysisMode();
    bool triggerGuidedOnInvalidInstruction = context.GetTriggerGuidedOnInvalidInstruction();
    bool translateTailCalls = context.GetTranslateTailCalls();
    bool disallowBranchToString = context.GetDisallowBranchToString();

    auto &indirectBranches = context.GetIndirectBranches();
    auto &indirectNoReturnCalls = context.GetIndirectNoReturnCalls();

    auto &contextualFunctionReturns = context.GetContextualReturns();

    auto &directRefs = context.GetDirectCodeReferences();
    auto &directNoReturnCalls = context.GetDirectNoReturnCalls();
    auto &haltedDisassemblyAddresses = context.GetHaltedDisassemblyAddresses();
    auto &inlinedUnresolvedIndirectBranches = context.GetInlinedUnresolvedIndirectBranches();

    auto defineLocalLabel = [&](uint64_t addr) {
      if (addr == function->GetStart())
        return;
      if (!data->IsOffsetCodeSemantics(addr))
        return;
      DataVariable dataVar;
      if (data->GetDataVariableAtAddress(addr, dataVar) && (dataVar.address == addr))
        return;
      if (!data->GetAnalysisFunctionsForAddress(addr).empty())
        return;
      if (data->GetSymbolByAddress(addr))
        return;
      size_t width = data->GetAddressSize() * 2;
      string name = fmt::format("loc_{:0{}X}", addr, width);
      data->DefineAutoSymbol(new Symbol(LocalLabelSymbol, name, addr, LocalBinding));
    };

    bool hasInvalidInstructions = false;
    set<ArchAndAddr> guidedSourceBlockTargets;
    auto guidedSourceBlocks = function->GetGuidedSourceBlocks();
    set<ArchAndAddr> guidedSourceBlocksSet;
    for (const auto &block : guidedSourceBlocks)
      guidedSourceBlocksSet.insert(block);
    set<uint64_t> loggedUnresolvedIndirect;

    BNStringReference strRef;
    auto targetExceedsByteLimit = [](const BNStringReference &strRef)
    {
      size_t byteLimit = 8;
      if (strRef.type == Utf16String)
        byteLimit *= 2;
      else if (strRef.type == Utf32String)
        byteLimit *= 4;
      return (strRef.length >= byteLimit);
    };

    Ref<Platform> funcPlatform = function->GetPlatform();
    auto start = function->GetStart();
    blocksToProcess.emplace(funcPlatform->GetArchitecture(), start);
    seenBlocks.emplace(funcPlatform->GetArchitecture(), start);

    bool validateExecutable = data->IsOffsetExecutable(start);

    bool fastValidate = false;
    uint64_t fastEndAddr = 0;
    uint64_t fastStartAddr = UINT64_MAX;
    if (validateExecutable)
    {
      for (auto &sec : data->GetSectionsAt(start))
      {
        if (sec->GetSemantics() == ReadOnlyDataSectionSemantics)
          continue;
        if (sec->GetSemantics() == ReadWriteDataSectionSemantics)
          continue;
        if (!data->IsOffsetBackedByFile(sec->GetStart()))
          continue;
        if (!data->IsOffsetExecutable(sec->GetStart()))
          continue;
        if (fastStartAddr > sec->GetStart())
          fastStartAddr = sec->GetStart();
        if (fastEndAddr < (sec->GetEnd() - 1))
        {
          fastEndAddr = sec->GetEnd() - 1;
          Ref<Segment> segment = data->GetSegmentAt(fastEndAddr);
          if (segment)
            fastEndAddr = (std::min)(fastEndAddr, segment->GetDataEnd() - 1);
        }
        fastValidate = true;
        break;
      }
    }

    uint64_t totalSize = 0;
    uint64_t maxSize = context.GetMaxFunctionSize();
    bool maxSizeReached = false;

    while (blocksToProcess.size() != 0)
    {
      if (data->AnalysisIsAborted())
        return;

      ArchAndAddr location = blocksToProcess.front();
      ArchAndAddr instructionGroupStart = location;
      blocksToProcess.pop();

      bool isGuidedSourceBlock = guidedSourceBlocksSet.count(location) ? true : false;

      Ref<BasicBlock> block = context.CreateBasicBlock(location.arch, location.address);

      if ((location.address == function->GetStart()) && IsPaddingStart(data, location.address))
      {
        // Avoid creating functions on alignment padding between real function bodies.
        string text = fmt::format("Padding/alignment at {:#x}", location.address);
        function->CreateAutoAddressTag(location.arch, location.address, "Padding", text, true);
        context.Finalize();
        return;
      }

      Ref<Function> nextFunc;
      bool hasNextFunc = GetNextFunctionAfterAddress(data, funcPlatform, location.address, nextFunc);
      uint64_t nextFuncAddr = (hasNextFunc && nextFunc) ? nextFunc->GetStart() : 0;
      set<Ref<Function>> calledFunctions;

      uint8_t delaySlotCount = 0;
      bool delayInstructionEndsBlock = false;

      while (true)
      {
        if (data->AnalysisIsAborted())
          return;

        DataVariable dataVar;
        if (data->GetDataVariableAtAddress(location.address, dataVar) &&
            (dataVar.address == location.address) && (location.address != function->GetStart()))
        {
          bool smallAutoData = false;
          if (dataVar.type.GetValue())
          {
            uint64_t width = dataVar.type.GetValue()->GetWidth();
            smallAutoData = (width <= 1);
          }
          bool canRecover =
              dataVar.autoDiscovered && (smallAutoData || !dataVar.type.GetValue()) &&
              data->IsOffsetCodeSemantics(location.address) &&
              (location.address - function->GetStart() <= 0x40);
          if (canRecover)
          {
            uint8_t probe[BN_MAX_INSTRUCTION_LENGTH];
            size_t probeLen = data->Read(probe, location.address, location.arch->GetMaxInstructionLength());
            InstructionInfo probeInfo;
            if (probeLen && location.arch->GetInstructionInfo(probe, location.address, probeLen, probeInfo) &&
                probeInfo.length > 0)
            {
              uint64_t nextAddr = location.address + probeInfo.length;
              uint8_t probeNext[BN_MAX_INSTRUCTION_LENGTH];
              size_t probeNextLen = data->Read(probeNext, nextAddr, location.arch->GetMaxInstructionLength());
              InstructionInfo probeNextInfo;
              if (probeNextLen &&
                  location.arch->GetInstructionInfo(probeNext, nextAddr, probeNextLen, probeNextInfo) &&
                  probeNextInfo.length > 0)
              {
                data->UndefineDataVariable(location.address, true);
                continue;
              }
            }
          }

          // Stop at typed data (literal pools) or non-code bytes.
          break;
        }

        if (!delaySlotCount)
        {
          auto blockIter = instrBlocks.find(location);
          if (blockIter != instrBlocks.end())
          {
            Ref<BasicBlock> targetBlock = blockIter->second;
            if (targetBlock->GetStart() == location.address)
            {
              block->AddPendingOutgoingEdge(UnconditionalBranch, location.address, nullptr,
                                            (block->GetStart() != location.address));
              break;
            }
            else
            {
              Ref<BasicBlock> splitBlock = context.CreateBasicBlock(location.arch, location.address);
              size_t instrDataLen;
              const uint8_t *instrData = targetBlock->GetInstructionData(location.address, &instrDataLen);
              splitBlock->AddInstructionData(instrData, instrDataLen);
              splitBlock->SetFallThroughToFunction(targetBlock->IsFallThroughToFunction());
              splitBlock->SetUndeterminedOutgoingEdges(targetBlock->HasUndeterminedOutgoingEdges());
              splitBlock->SetCanExit(targetBlock->CanExit());
              splitBlock->SetEnd(targetBlock->GetEnd());

              targetBlock->SetFallThroughToFunction(false);
              targetBlock->SetUndeterminedOutgoingEdges(false);
              targetBlock->SetCanExit(true);
              targetBlock->SetEnd(location.address);

              for (size_t j = location.address; j < splitBlock->GetEnd(); j++)
              {
                auto k = instrBlocks.find(ArchAndAddr(location.arch, j));
                if ((k != instrBlocks.end()) && (k->second == targetBlock))
                  k->second = splitBlock;
              }

              for (auto &k : targetBlock->GetPendingOutgoingEdges())
                splitBlock->AddPendingOutgoingEdge(k.type, k.target, k.arch, k.fallThrough);
              targetBlock->ClearPendingOutgoingEdges();
              targetBlock->AddPendingOutgoingEdge(UnconditionalBranch, location.address, nullptr, true);

              seenBlocks.insert(location);
              defineLocalLabel(location.address);
              context.AddFunctionBasicBlock(splitBlock);

              block->AddPendingOutgoingEdge(UnconditionalBranch, location.address);
              break;
            }
          }
        }

        uint8_t opcode[BN_MAX_INSTRUCTION_LENGTH];
        size_t maxLen = data->Read(opcode, location.address, location.arch->GetMaxInstructionLength());
        if (maxLen == 0)
        {
          string text = fmt::format("Could not read instruction at {:#x}", location.address);
          function->CreateAutoAddressTag(location.arch, location.address, "Invalid Instruction", text, true);
          if (location.arch->GetInstructionAlignment() == 0)
            location.address++;
          else
            location.address += location.arch->GetInstructionAlignment();
          block->SetHasInvalidInstructions(true);
          break;
        }

        InstructionInfo info;
        info.delaySlots = delaySlotCount;
        if (!location.arch->GetInstructionInfo(opcode, location.address, maxLen, info))
        {
          string text = fmt::format("Could not get instruction info at {:#x}", location.address);
          function->CreateAutoAddressTag(location.arch, location.address, "Invalid Instruction", text, true);
          if (location.arch->GetInstructionAlignment() == 0)
            location.address++;
          else
            location.address += location.arch->GetInstructionAlignment();
          block->SetHasInvalidInstructions(true);
          break;
        }

        if ((info.length == 0) || (info.length > maxLen))
        {
          string text = fmt::format("Instruction of invalid length at {:#x}", location.address);
          function->CreateAutoAddressTag(location.arch, location.address, "Invalid Instruction", text, true);
          if (location.arch->GetInstructionAlignment() == 0)
            location.address++;
          else
            location.address += location.arch->GetInstructionAlignment();
          block->SetHasInvalidInstructions(true);
          break;
        }

        uint64_t instrEnd = location.address + info.length - 1;
        bool slowPath = !fastValidate || (instrEnd < fastStartAddr) || (instrEnd > fastEndAddr);
        if (slowPath &&
            ((!data->IsOffsetCodeSemantics(instrEnd) && data->IsOffsetCodeSemantics(location.address)) ||
             (!data->IsOffsetBackedByFile(instrEnd) && data->IsOffsetBackedByFile(location.address))))
        {
          string text = fmt::format("Instruction at {:#x} straddles a non-code section", location.address);
          function->CreateAutoAddressTag(location.arch, location.address, "Invalid Instruction", text, true);
          if (location.arch->GetInstructionAlignment() == 0)
            location.address++;
          else
            location.address += location.arch->GetInstructionAlignment();
          block->SetHasInvalidInstructions(true);
          break;
        }

        bool endsBlock = false;
        ArchAndAddr target;
        map<ArchAndAddr, set<ArchAndAddr>>::const_iterator indirectBranchIter, endIter;
        if (!delaySlotCount)
        {
          instrBlocks[location] = block;
          instructionGroupStart = location;

          for (size_t i = 0; i < info.branchCount; i++)
          {
            bool fastPath;

            auto handleAsFallback = [&]()
            {
              endsBlock = true;

              bool callLikeIndirect = false;
              if (info.branchType[i] == IndirectBranch || info.branchType[i] == UnresolvedBranch)
              {
                Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(location.arch, nullptr);
                ilFunc->SetCurrentAddress(location.arch, location.address);
                location.arch->GetInstructionLowLevelIL(opcode, location.address, maxLen, *ilFunc);
                for (size_t idx = 0; idx < ilFunc->GetInstructionCount(); idx++)
                {
                  if ((*ilFunc)[idx].operation == LLIL_CALL)
                  {
                    callLikeIndirect = true;
                    endsBlock = false;
                    break;
                  }
                  if ((*ilFunc)[idx].operation == LLIL_TAILCALL)
                  {
                    callLikeIndirect = true;
                    break;
                  }
                }
              }

              /*
               * Heuristic: treat "MOV/ADD LR, PC; LDR PC, [Rn, #imm]" as an indirect call.
               *
               * Rationale:
               * - On ARMv5, compilers often synthesize a call through a function pointer
               *   (vtable/dispatch) using:
               *       mov lr, pc
               *       ldr pc, [rX, #imm]
               * - Semantically this behaves like BLX/BL: LR is set to the return address
               *   and control returns to the next instruction after the LDR.
               * - We cannot resolve the target statically, but we can avoid logging it as
               *   "unresolved indirect control flow" because it is a normal callsite.
               *
               * Implementation notes:
               * - Only apply in ARM mode (4-byte instructions).
               * - Confirm the current instruction is an LDR into PC.
               * - Look back one instruction for LR being set from PC (MOV or ADD #imm).
               * - If matched, mark as call-like and allow fallthrough (endsBlock = false).
               */
              if (!callLikeIndirect && (info.branchType[i] == IndirectBranch || info.branchType[i] == UnresolvedBranch) &&
                  (info.length == 4) && (location.address >= 4))
              {
                Instruction curInstr{};
                uint32_t bigEndian = (location.arch->GetEndianness() == BigEndian);
                if (armv5_decompose(*(uint32_t *)opcode, &curInstr, (uint32_t)location.address, bigEndian) == 0)
                {
                  bool isLdrPc =
                      (curInstr.operation == ARMV5_LDR) &&
                      (curInstr.operands[0].cls == REG) &&
                      (curInstr.operands[0].reg == REG_PC);

                  if (isLdrPc)
                  {
                    DataBuffer prevData = data->ReadBuffer(location.address - 4, 4);
                    if (prevData.GetLength() == 4)
                    {
                      Instruction prevInstr{};
                      if (armv5_decompose(*(uint32_t *)prevData.GetData(), &prevInstr,
                                          (uint32_t)(location.address - 4), bigEndian) == 0)
                      {
                        bool movLrPc =
                            (prevInstr.operation == ARMV5_MOV) &&
                            (prevInstr.operands[0].cls == REG) &&
                            (prevInstr.operands[0].reg == REG_LR) &&
                            (prevInstr.operands[1].cls == REG) &&
                            (prevInstr.operands[1].reg == REG_PC);

                        bool addLrPcImm =
                            (prevInstr.operation == ARMV5_ADD) &&
                            (prevInstr.operands[0].cls == REG) &&
                            (prevInstr.operands[0].reg == REG_LR) &&
                            (prevInstr.operands[1].cls == REG) &&
                            (prevInstr.operands[1].reg == REG_PC) &&
                            (prevInstr.operands[2].cls == IMM);

                        if (movLrPc || addLrPcImm)
                        {
                          callLikeIndirect = true;
                          endsBlock = false;
                        }
                      }
                    }
                  }
                }
              }

              set<ArchAndAddr> resolvedTargets;
              indirectBranchIter = indirectBranches.find(location);
              endIter = indirectBranches.end();
              if (indirectBranchIter != endIter)
              {
                for (auto &branch : indirectBranchIter->second)
                  resolvedTargets.insert(branch);
              }
              else if (info.branchType[i] == IndirectBranch || info.branchType[i] == UnresolvedBranch)
              {
                vector<pair<Ref<Architecture>, uint64_t>> jumpTableTargets;
                DetectSwitchTable(data, location.address, jumpTableTargets);
                DetectLdrPcJumpTable(data, location.address, jumpTableTargets);
                DetectLdrPcLiteralTarget(data, location.address, jumpTableTargets);
                for (auto &branch : jumpTableTargets)
                {
                  Ref<Architecture> targetArch = branch.first ? branch.first : location.arch;
                  resolvedTargets.emplace(targetArch, branch.second);
                }
              }

              if (!resolvedTargets.empty())
              {
                constexpr size_t kMaxIndirectTargets = 4095;
                size_t emittedTargets = 0;
                if (resolvedTargets.size() > kMaxIndirectTargets)
                {
                  auto clampLogger = LogRegistry::CreateLogger("BinaryView.ARMv5Architecture");
                  if (clampLogger)
                    clampLogger->LogWarn("Clamping indirect branch targets at 0x%llx from %zu to %zu",
                                         (unsigned long long)location.address,
                                         resolvedTargets.size(), kMaxIndirectTargets);
                }
                for (auto &branch : resolvedTargets)
                {
                  if (emittedTargets++ >= kMaxIndirectTargets)
                    break;
                  directRefs[branch.address].emplace(location);
                  Ref<Platform> targetPlatform = funcPlatform;
                  if (branch.arch != function->GetArchitecture())
                    targetPlatform = funcPlatform->GetRelatedPlatform(branch.arch);

                  if (translateTailCalls && targetPlatform &&
                      data->GetAnalysisFunction(targetPlatform, branch.address))
                    continue;

                if (isGuidedSourceBlock)
                  guidedSourceBlockTargets.insert(branch);

                defineLocalLabel(branch.address);
                block->AddPendingOutgoingEdge(IndirectBranch, branch.address, branch.arch);
                if (seenBlocks.count(branch) == 0)
                {
                  blocksToProcess.push(branch);
                  seenBlocks.insert(branch);
                  }
                }
              }
              else if (info.branchType[i] == ExceptionBranch)
              {
                block->SetCanExit(false);
              }
              else if (info.branchType[i] == FunctionReturn && function->CanReturn().GetValue())
              {
                auto it = contextualFunctionReturns.find(location);
                if (it != contextualFunctionReturns.end())
                {
                  endsBlock = it->second;
                }
                else
                {
                  Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(location.arch, nullptr);
                  ilFunc->SetCurrentAddress(location.arch, location.address);
                  location.arch->GetInstructionLowLevelIL(opcode, location.address, maxLen, *ilFunc);
                  if (ilFunc->GetInstructionCount() && ((*ilFunc)[0].operation == LLIL_CALL))
                    contextualFunctionReturns[location] = false;
                  else
                    contextualFunctionReturns[location] = true;
                  endsBlock = contextualFunctionReturns[location];
                }
              }
              else
              {
                if ((info.branchType[i] == IndirectBranch || info.branchType[i] == UnresolvedBranch) &&
                    !callLikeIndirect && resolvedTargets.empty() &&
                    (loggedUnresolvedIndirect.count(location.address) == 0))
                {
                  loggedUnresolvedIndirect.insert(location.address);
                }
                block->SetUndeterminedOutgoingEdges(true);
              }
            };

            switch (info.branchType[i])
            {
            case UnconditionalBranch:
            case TrueBranch:
            case FalseBranch:
              endsBlock = true;
              if (data->IsOffsetExternSemantics(info.branchTarget[i]))
              {
                DataVariable dataVar;
                if (data->GetDataVariableAtAddress(info.branchTarget[i], dataVar) &&
                    (dataVar.address == info.branchTarget[i]) && dataVar.type.GetValue() &&
                    (dataVar.type->GetClass() == FunctionTypeClass))
                {
                  directRefs[info.branchTarget[i]].emplace(location);
                  if (!dataVar.type->CanReturn())
                  {
                    directNoReturnCalls.insert(location);
                    endsBlock = true;
                    block->SetCanExit(false);
                  }
                }
                break;
              }

              if (data->IsValidOffset(info.branchTarget[i]) && IsReturnThunk(data, info.branchTarget[i]))
              {
                endsBlock = true;
                block->SetCanExit(true);
                break;
              }

              fastPath = fastValidate && (info.branchTarget[i] >= fastStartAddr) &&
                         (info.branchTarget[i] <= fastEndAddr);
              if (fastPath ||
                  (data->IsValidOffset(info.branchTarget[i]) &&
                   data->IsOffsetBackedByFile(info.branchTarget[i]) &&
                   ((!validateExecutable) || data->IsOffsetExecutable(info.branchTarget[i]))))
              {
                target = ArchAndAddr(info.branchArch[i] ? new CoreArchitecture(info.branchArch[i]) : location.arch,
                                     info.branchTarget[i]);

                if (data->ShouldSkipTargetAnalysis(location, function, instrEnd, target))
                  break;

                Ref<Platform> targetPlatform = funcPlatform;
                if (target.arch != funcPlatform->GetArchitecture())
                  targetPlatform = funcPlatform->GetRelatedPlatform(target.arch);

                directRefs[info.branchTarget[i]].insert(location);

                if (translateTailCalls && (info.branchType[i] == UnconditionalBranch) &&
                    (target.address < function->GetStart()))
                {
                  if (!IsValidFunctionStart(data, targetPlatform, target.address))
                    break;
                  Ref<Function> forcedFunc = data->AddFunctionForAnalysis(targetPlatform, target.address, true);
                  if (forcedFunc)
                  {
                    context.AddTempOutgoingReference(forcedFunc);
                    calledFunctions.insert(forcedFunc);
                    if (!forcedFunc->CanReturn() && !forcedFunc->IsInlinedDuringAnalysis().GetValue())
                    {
                      directNoReturnCalls.insert(location);
                      endsBlock = true;
                      block->SetCanExit(false);
                    }
                    break;
                  }
                }

                auto otherFunc = function->GetCalleeForAnalysis(targetPlatform, target.address, true);
                if (translateTailCalls && targetPlatform && otherFunc && (otherFunc->GetStart() != function->GetStart()))
                {
                  calledFunctions.insert(otherFunc);
                  if (info.branchType[i] == UnconditionalBranch)
                  {
                    if (!otherFunc->CanReturn() && !otherFunc->IsInlinedDuringAnalysis().GetValue())
                    {
                      directNoReturnCalls.insert(location);
                      endsBlock = true;
                      block->SetCanExit(false);
                    }
                    break;
                  }
                }
                else if (disallowBranchToString && data->GetStringAtAddress(target.address, strRef) &&
                         targetExceedsByteLimit(strRef))
                {
                  BNLogInfo("Not adding branch target from 0x%" PRIx64 " to string at 0x%" PRIx64 " length:%zu",
                            location.address, target.address, strRef.length);
                  break;
                }
                else
                {
                  if (isGuidedSourceBlock)
                    guidedSourceBlockTargets.insert(target);

                  if (info.branchType[i] != FalseBranch)
                    defineLocalLabel(target.address);
                  block->AddPendingOutgoingEdge(info.branchType[i], target.address, target.arch);
                  if (seenBlocks.count(target) == 0)
                  {
                    blocksToProcess.push(target);
                    seenBlocks.insert(target);
                  }
                }
              }
              break;

            case CallDestination:
              if (data->IsOffsetExternSemantics(info.branchTarget[i]))
              {
                DataVariable dataVar;
                if (data->GetDataVariableAtAddress(info.branchTarget[i], dataVar) &&
                    (dataVar.address == info.branchTarget[i]) && dataVar.type.GetValue() &&
                    (dataVar.type->GetClass() == FunctionTypeClass))
                {
                  directRefs[info.branchTarget[i]].emplace(location);
                  if (!dataVar.type->CanReturn())
                  {
                    directNoReturnCalls.insert(location);
                    endsBlock = true;
                    block->SetCanExit(false);
                  }
                }
                break;
              }

              fastPath = fastValidate && (info.branchTarget[i] >= fastStartAddr) &&
                         (info.branchTarget[i] <= fastEndAddr);
              if (fastPath ||
                  (data->IsValidOffset(info.branchTarget[i]) && data->IsOffsetBackedByFile(info.branchTarget[i]) &&
                   ((!validateExecutable) || data->IsOffsetExecutable(info.branchTarget[i]))))
              {
                target = ArchAndAddr(info.branchArch[i] ? new CoreArchitecture(info.branchArch[i]) : location.arch,
                                     info.branchTarget[i]);

                if (!fastPath && !data->IsOffsetCodeSemantics(target.address) &&
                    data->IsOffsetCodeSemantics(location.address))
                {
                  string message = fmt::format("Non-code call target {:#x}", target.address);
                  function->CreateAutoAddressTag(target.arch, location.address, "Non-code Branch", message, true);
                  break;
                }

                Ref<Platform> platform = funcPlatform;
                if (target.arch != platform->GetArchitecture())
                {
                  platform = funcPlatform->GetRelatedPlatform(target.arch);
                  if (!platform)
                    platform = funcPlatform;
                }

                if (data->ShouldSkipTargetAnalysis(location, function, instrEnd, target))
                  break;

                if (!IsValidFunctionStart(data, platform, target.address))
                  break;
                Ref<Function> func = data->AddFunctionForAnalysis(platform, target.address, true);
                if (!func)
                {
                  if (!data->IsOffsetBackedByFile(target.address))
                    BNLogError("Function at 0x%" PRIx64 " failed to add target not backed by file.",
                               function->GetStart());
                  break;
                }

                context.AddTempOutgoingReference(func);
                calledFunctions.emplace(func);
                directRefs[target.address].emplace(location);
                if (!func->CanReturn())
                {
                  if (func->IsInlinedDuringAnalysis().GetValue() && func->HasUnresolvedIndirectBranches())
                  {
                    auto unresolved = func->GetUnresolvedIndirectBranches();
                    if (unresolved.size() == 1)
                    {
                      inlinedUnresolvedIndirectBranches[location] = *unresolved.begin();
                      handleAsFallback();
                      break;
                    }
                  }

                  directNoReturnCalls.insert(location);
                  endsBlock = true;
                  block->SetCanExit(false);
                }
              }
              break;

            case SystemCall:
              break;

            default:
              handleAsFallback();
              break;
            }
          }
        }

        if (indirectNoReturnCalls.count(location))
        {
          size_t instrLength = info.length;
          if (info.delaySlots)
          {
            InstructionInfo delayInfo;
            delayInfo.delaySlots = info.delaySlots;
            size_t archMax = location.arch->GetMaxInstructionLength();
            uint8_t delayOpcode[BN_MAX_INSTRUCTION_LENGTH];
            do
            {
              delayInfo.delaySlots--;
              if (!location.arch->GetInstructionInfo(delayOpcode, location.address + instrLength,
                                                     archMax - instrLength, delayInfo))
                break;
              instrLength += delayInfo.length;
            } while (delayInfo.delaySlots && (instrLength < archMax));
          }

          Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(location.arch, nullptr);
          ilFunc->SetCurrentAddress(location.arch, location.address);
          location.arch->GetInstructionLowLevelIL(opcode, location.address, maxLen, *ilFunc);
          if (!(ilFunc->GetInstructionCount() && ((*ilFunc)[0].operation == LLIL_IF)))
          {
            endsBlock = true;
            block->SetCanExit(false);
          }
        }

        location.address += info.length;
        block->AddInstructionData(opcode, info.length);

        if (endsBlock && !info.delaySlots)
          break;

        totalSize += info.length;
        auto analysisSkipOverride = context.GetAnalysisSkipOverride();
        if (analysisSkipOverride == NeverSkipFunctionAnalysis)
          maxSize = 0;
        else if (!maxSize && (analysisSkipOverride == AlwaysSkipFunctionAnalysis))
          maxSize = context.GetMaxFunctionSize();

        if (maxSize && (totalSize > maxSize))
        {
          maxSizeReached = true;
          break;
        }

        if (delaySlotCount)
        {
          delaySlotCount--;
          if (!delaySlotCount && delayInstructionEndsBlock)
            break;
        }
        else
        {
          delaySlotCount = info.delaySlots;
          delayInstructionEndsBlock = endsBlock;
        }

        if (block->CanExit() && translateTailCalls && !delaySlotCount && hasNextFunc &&
            (location.address == nextFuncAddr))
        {
          if (calledFunctions.count(nextFunc) == 0)
          {
            block->SetFallThroughToFunction(true);
            if (!nextFunc->CanReturn())
            {
              directNoReturnCalls.insert(instructionGroupStart);
              block->SetCanExit(false);
            }
            break;
          }
          hasNextFunc = GetNextFunctionAfterAddress(data, funcPlatform, location.address, nextFunc);
          nextFuncAddr = (hasNextFunc && nextFunc) ? nextFunc->GetStart() : 0;
        }
      }

      if (location.address != block->GetStart())
      {
        block->SetEnd(location.address);
        context.AddFunctionBasicBlock(block);
      }

      if (maxSizeReached)
        break;

      if (triggerGuidedOnInvalidInstruction && block->HasInvalidInstructions())
        hasInvalidInstructions = true;

      if (guidedAnalysisMode || hasInvalidInstructions || guidedSourceBlocksSet.size())
      {
        queue<ArchAndAddr> guidedBlocksToProcess;
        while (!blocksToProcess.empty())
        {
          auto i = blocksToProcess.front();
          blocksToProcess.pop();
          if (guidedSourceBlockTargets.count(i))
            guidedBlocksToProcess.emplace(i);
          else
            haltedDisassemblyAddresses.emplace(i);
        }
        blocksToProcess = guidedBlocksToProcess;
      }
    }

    if (maxSizeReached)
      context.SetMaxSizeReached(true);

    context.Finalize();
  }
};

ArmCommonArchitecture* InitArmv5Architecture(const char* name, BNEndianness endian)
{
  return new Armv5Architecture(name, endian);
}
