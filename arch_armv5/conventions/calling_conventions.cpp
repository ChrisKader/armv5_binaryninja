/*
 * ARMv5 Calling Conventions
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * This file defines calling conventions for ARMv5 code. Calling conventions
 * specify how functions pass arguments, return values, and preserve registers.
 * Correct calling conventions are essential for accurate decompilation.
 *
 * CONVENTIONS DEFINED:
 * --------------------
 *
 * 1. AAPCS (ARM EABI) - "aapcs"
 *    - Modern standard for ARM embedded and Linux
 *    - 8-byte stack alignment at public interfaces
 *    - r0-r3 for arguments, r0-r1 for return values
 *    - Default convention for this plugin
 *
 * 2. CDECL - "cdecl"
 *    - Compatibility alias for AAPCS
 *    - Used by Binary Ninja for default function handling
 *
 * 3. APCS (Legacy ARM) - "apcs"
 *    - Older ARM/Thumb Procedure Call Standard
 *    - 4-byte stack alignment (vs 8-byte in AAPCS)
 *    - Common in older ARM SDKs (ADS, ARM SDT)
 *
 * 4. IRQ Handler - "irq-handler"
 *    - For interrupt and exception handlers
 *    - No arguments (hardware-initiated)
 *    - All registers treated as volatile (conservative)
 *    - Apply manually to irq_handler, fiq_handler, etc.
 *
 * 5. Task Entry - "task-entry"
 *    - For RTOS task entry points
 *    - r0/r1 as parameters (argc/argv or task-specific)
 *    - Apply manually to RTOS task functions
 *
 * 6. Linux Syscall - "linux-syscall"
 *    - For Linux kernel system call interface
 *    - r7 = syscall number, r0-r6 = arguments
 *    - Apply to syscall stubs if analyzing Linux binaries
 *
 * ============================================================================
 * USAGE
 * ============================================================================
 *
 * Most functions should use the default AAPCS convention. For special cases:
 *
 * 1. In Binary Ninja UI:
 *    - Right-click function -> "Edit Function Properties"
 *    - Change "Calling Convention" dropdown
 *
 * 2. In Python API:
 *    func.calling_convention = arch.calling_conventions['irq-handler']
 *
 * 3. Apply to exception handlers discovered by firmware view:
 *    - Functions named irq_handler, fiq_handler should use irq-handler
 *    - Functions named reset_handler may use aapcs (normal startup code)
 *
 * ============================================================================
 * REGISTER USAGE SUMMARY
 * ============================================================================
 *
 *   Register   AAPCS/APCS    IRQ Handler   Purpose
 *   --------   ----------    -----------   -------
 *   r0-r3      Volatile      Volatile      Arguments/scratch
 *   r4-r11     Preserved     Volatile*     Callee-saved
 *   r12 (IP)   Volatile      Volatile      Intra-procedure scratch
 *   r13 (SP)   Preserved     Special       Stack pointer
 *   r14 (LR)   Volatile      Special       Link register / return address
 *   r15 (PC)   -             -             Program counter
 *
 *   * IRQ handlers save/restore all registers explicitly
 *
 * ============================================================================
 * REFERENCE: ARM AAPCS (ARM IHI 0042), ARM APCS (ARM DUI 0041)
 * ============================================================================
 */

#include <vector>

#include "binaryninjaapi.h"
#include "arch_armv5.h"
#include "conventions/calling_conventions.h"

using namespace BinaryNinja;
using namespace armv5;
using namespace std;

/*
 * AAPCS (ARM EABI) Calling Convention - Modern default
 * - r0-r3: arguments
 * - r0: return value, r1: high word of 64-bit return
 * - r0-r3, r12, lr: caller-saved (volatile)
 * - r4-r11: callee-saved (non-volatile)
 * - 8-byte stack alignment at public interfaces
 */
class Armv5AAPCSCallingConvention : public CallingConvention
{
public:
  Armv5AAPCSCallingConvention(Architecture *arch) : CallingConvention(arch, "aapcs")
  {
  }

  virtual vector<uint32_t> GetIntegerArgumentRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1, REG_R2, REG_R3};
  }

  virtual vector<uint32_t> GetCallerSavedRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1, REG_R2, REG_R3, REG_R12, REG_LR};
  }

  virtual vector<uint32_t> GetCalleeSavedRegisters() override
  {
    return vector<uint32_t>{REG_R4, REG_R5, REG_R6, REG_R7, REG_R8, REG_R9, REG_R10, REG_R11};
  }

  virtual uint32_t GetIntegerReturnValueRegister() override
  {
    return REG_R0;
  }

  virtual uint32_t GetHighIntegerReturnValueRegister() override
  {
    return REG_R1;
  }

  virtual uint32_t GetGlobalPointerRegister() override
  {
    return REG_R9;  // Common embedded usage for static base / TLS
  }
};

// Keep cdecl as alias for compatibility
class Armv5CallingConvention : public CallingConvention
{
public:
  Armv5CallingConvention(Architecture *arch) : CallingConvention(arch, "cdecl")
  {
  }

  virtual vector<uint32_t> GetIntegerArgumentRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1, REG_R2, REG_R3};
  }

  virtual vector<uint32_t> GetCallerSavedRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1, REG_R2, REG_R3, REG_R12, REG_LR};
  }

  virtual vector<uint32_t> GetCalleeSavedRegisters() override
  {
    return vector<uint32_t>{REG_R4, REG_R5, REG_R6, REG_R7, REG_R8, REG_R9, REG_R10, REG_R11};
  }

  virtual uint32_t GetIntegerReturnValueRegister() override
  {
    return REG_R0;
  }

  virtual uint32_t GetHighIntegerReturnValueRegister() override
  {
    return REG_R1;
  }
};

/*
 * APCS-32 / ATPCS Calling Convention - Legacy embedded
 * Same as AAPCS but with 4-byte stack alignment
 */
class Armv5APCSCallingConvention : public CallingConvention
{
public:
  Armv5APCSCallingConvention(Architecture *arch) : CallingConvention(arch, "apcs")
  {
  }

  virtual vector<uint32_t> GetIntegerArgumentRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1, REG_R2, REG_R3};
  }

  virtual vector<uint32_t> GetCallerSavedRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1, REG_R2, REG_R3, REG_R12, REG_LR};
  }

  virtual vector<uint32_t> GetCalleeSavedRegisters() override
  {
    return vector<uint32_t>{REG_R4, REG_R5, REG_R6, REG_R7, REG_R8, REG_R9, REG_R10, REG_R11};
  }

  virtual uint32_t GetIntegerReturnValueRegister() override
  {
    return REG_R0;
  }

  virtual uint32_t GetHighIntegerReturnValueRegister() override
  {
    return REG_R1;
  }

  virtual uint32_t GetGlobalPointerRegister() override
  {
    return REG_R9;  // APCS commonly uses r9 as SB (static base)
  }
};

/*
 * IRQ / Exception Handler Calling Convention
 * - No arguments (hardware-initiated)
 * - No return registers (uses exception return)
 * - All GPRs treated as caller-saved (conservative)
 * - 4-byte stack alignment
 */
class Armv5IRQCallingConvention : public CallingConvention
{
public:
  Armv5IRQCallingConvention(Architecture *arch) : CallingConvention(arch, "irq-handler")
  {
  }

  virtual vector<uint32_t> GetIntegerArgumentRegisters() override
  {
    return vector<uint32_t>{};  // No arguments
  }

  virtual vector<uint32_t> GetCallerSavedRegisters() override
  {
    // Conservative: treat all GPRs as caller-saved
    return vector<uint32_t>{
      REG_R0, REG_R1, REG_R2, REG_R3, REG_R4, REG_R5, REG_R6, REG_R7,
      REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_LR
    };
  }

  virtual vector<uint32_t> GetCalleeSavedRegisters() override
  {
    return vector<uint32_t>{};  // None - all clobbered
  }

  virtual uint32_t GetIntegerReturnValueRegister() override
  {
    return REG_R0;  // Not really used, but need to return something valid
  }

  virtual bool IsEligibleForHeuristics() override
  {
    return false;  // Don't auto-detect this convention
  }
};

/*
 * RTOS Task Entry Calling Convention
 * Many RTOS task entry points are invoked with:
 * - r0 = argc (or task parameter)
 * - r1 = argv (or additional parameter)
 * - lr = task exit stub
 * - sp = task stack top
 * Tasks generally do not return normally.
 */
class Armv5TaskEntryCallingConvention : public CallingConvention
{
public:
  Armv5TaskEntryCallingConvention(Architecture *arch) : CallingConvention(arch, "task-entry")
  {
  }

  virtual vector<uint32_t> GetIntegerArgumentRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1};  // argc, argv or task params
  }

  virtual vector<uint32_t> GetCallerSavedRegisters() override
  {
    return vector<uint32_t>{REG_R0, REG_R1, REG_R2, REG_R3, REG_R12, REG_LR};
  }

  virtual vector<uint32_t> GetCalleeSavedRegisters() override
  {
    return vector<uint32_t>{REG_R4, REG_R5, REG_R6, REG_R7, REG_R8, REG_R9, REG_R10, REG_R11};
  }

  virtual uint32_t GetIntegerReturnValueRegister() override
  {
    return REG_R0;  // Tasks don't return, but need valid register
  }

  virtual uint32_t GetGlobalPointerRegister() override
  {
    return REG_R9;
  }

  virtual bool IsEligibleForHeuristics() override
  {
    return false;  // Don't auto-detect - must be explicitly applied
  }
};

/*
 * Linux System Call Calling Convention
 * R7 contains syscall number, R0-R6 contain arguments
 */
class LinuxArmv5SystemCallConvention : public CallingConvention
{
public:
  LinuxArmv5SystemCallConvention(Architecture *arch) : CallingConvention(arch, "linux-syscall")
  {
  }

  virtual vector<uint32_t> GetIntegerArgumentRegisters() override
  {
    return vector<uint32_t>{REG_R7, REG_R0, REG_R1, REG_R2, REG_R3, REG_R4, REG_R5, REG_R6};
  }

  virtual vector<uint32_t> GetCallerSavedRegisters() override
  {
    return vector<uint32_t>{REG_R0};
  }

  virtual vector<uint32_t> GetCalleeSavedRegisters() override
  {
    return vector<uint32_t>{REG_R4, REG_R5, REG_R6, REG_R7, REG_R8, REG_R10, REG_R11};
  }

  virtual uint32_t GetIntegerReturnValueRegister() override
  {
    return REG_R0;
  }

  virtual bool IsEligibleForHeuristics() override
  {
    return false;
  }
};

void RegisterArmv5CallingConventions(Architecture* armv5, Architecture* thumb)
{
  if (!armv5 || !thumb)
    return;

  Ref<CallingConvention> conv;

  // ARM AAPCS (modern default)
  Ref<CallingConvention> aapcsConv = new Armv5AAPCSCallingConvention(armv5);
  armv5->RegisterCallingConvention(aapcsConv);
  armv5->SetDefaultCallingConvention(aapcsConv);

  // ARM cdecl (compatibility alias)
  conv = new Armv5CallingConvention(armv5);
  armv5->RegisterCallingConvention(conv);
  armv5->SetCdeclCallingConvention(conv);
  armv5->SetFastcallCallingConvention(conv);
  armv5->SetStdcallCallingConvention(conv);

  // ARM APCS (legacy)
  conv = new Armv5APCSCallingConvention(armv5);
  armv5->RegisterCallingConvention(conv);

  // ARM IRQ/Exception handler
  conv = new Armv5IRQCallingConvention(armv5);
  armv5->RegisterCallingConvention(conv);

  // ARM RTOS task entry
  conv = new Armv5TaskEntryCallingConvention(armv5);
  armv5->RegisterCallingConvention(conv);

  // ARM Linux syscall
  conv = new LinuxArmv5SystemCallConvention(armv5);
  armv5->RegisterCallingConvention(conv);

  // Thumb AAPCS (modern default)
  Ref<CallingConvention> thumbAapcsConv = new Armv5AAPCSCallingConvention(thumb);
  thumb->RegisterCallingConvention(thumbAapcsConv);
  thumb->SetDefaultCallingConvention(thumbAapcsConv);

  // Thumb cdecl (compatibility alias)
  conv = new Armv5CallingConvention(thumb);
  thumb->RegisterCallingConvention(conv);
  thumb->SetCdeclCallingConvention(conv);
  thumb->SetFastcallCallingConvention(conv);
  thumb->SetStdcallCallingConvention(conv);

  // Thumb APCS (legacy)
  conv = new Armv5APCSCallingConvention(thumb);
  thumb->RegisterCallingConvention(conv);

  // Thumb IRQ/Exception handler
  conv = new Armv5IRQCallingConvention(thumb);
  thumb->RegisterCallingConvention(conv);

  // Thumb RTOS task entry
  conv = new Armv5TaskEntryCallingConvention(thumb);
  thumb->RegisterCallingConvention(conv);

  // Thumb Linux syscall
  conv = new LinuxArmv5SystemCallConvention(thumb);
  thumb->RegisterCallingConvention(conv);
}
