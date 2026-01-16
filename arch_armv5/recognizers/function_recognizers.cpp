/*
 * ARMv5 Function Recognizers
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * Function recognizers analyze newly-discovered functions and apply
 * metadata such as calling conventions, signatures, and type information.
 *
 * RECOGNIZERS:
 * ------------
 *
 * 1. ArmFunctionRecognizer
 *    - Detects thunks (B target, LDR PC patterns)
 *    - Identifies constant-return functions
 *    - Marks import wrappers
 *
 * 2. ThumbImportedFunctionRecognizer
 *    - Detects Thumb->ARM veneers
 *    - Handles inline switching stubs
 *
 * 3. ArmAnalysisRecognizer
 *    - Applies calling convention detection
 *    - Performs signature recovery
 *    - Only runs when analysis features are enabled
 *
 * ============================================================================
 */

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "arch_armv5.h"
#include "recognizers/function_recognizers.h"
#include "analysis/calling_convention_detector.h"
#include "analysis/signature_recovery.h"
#include "settings/plugin_settings.h"

using namespace BinaryNinja;
using namespace armv5;
using namespace std;

/*
 * Function Recognizer for ARM thunks and tail-call stubs
 *
 * Detects simple functions that are just wrappers/thunks:
 * - Single unconditional branch (B target) - tail call thunk
 * - LDR PC, [PC, #imm] - jump through literal pool (PLT-style)
 * - MOV r0, #const + BX LR - constant return function
 *
 * When a thunk targets an imported function, marks the thunk as an import.
 */
class ArmFunctionRecognizer : public FunctionRecognizer
{
public:
  virtual bool RecognizeLowLevelIL(BinaryView *data, Function *func, LowLevelILFunction *il) override
  {
    size_t instrCount = il->GetInstructionCount();
    if (instrCount == 0 || instrCount > 3)
      return false;

    /* Pattern 1: Single jump/tailcall to a constant address */
    if (instrCount == 1)
    {
      LowLevelILInstruction instr = il->GetInstruction(0);
      if (instr.operation == LLIL_JUMP || instr.operation == LLIL_TAILCALL)
      {
        LowLevelILInstruction dest = instr.GetDestExpr();
        if (dest.operation == LLIL_CONST_PTR || dest.operation == LLIL_CONST)
        {
          uint64_t target = dest.GetConstant();

          /* Check if target is an imported function */
          Ref<Symbol> sym = data->GetSymbolByAddress(target);
          if (sym && sym->GetType() == ImportedFunctionSymbol)
          {
            Ref<Function> targetFunc = data->GetRecentAnalysisFunctionForAddress(target);
            if (targetFunc)
            {
              Confidence<Ref<Type>> type = targetFunc->GetType();
              data->DefineImportedFunction(sym, func, type.GetValue());
              return true;
            }
          }
        }
      }
    }

    /* Pattern 2: SET_REG r0, const + RETURN (constant return function)
     * These are common for error code returns, boolean returns, etc.
     */
    if (instrCount == 2)
    {
      LowLevelILInstruction instr0 = il->GetInstruction(0);
      LowLevelILInstruction instr1 = il->GetInstruction(1);

      if (instr0.operation == LLIL_SET_REG && instr1.operation == LLIL_RET)
      {
        /* Could potentially set return type to int/bool based on value */
        /* For now, just recognize the pattern */
      }
    }

    return false;
  }
};

/*
 * Imported Function Recognizer for Thumb veneers
 * Detects inline veneers for thumb -> arm transitions
 */
class ThumbImportedFunctionRecognizer : public FunctionRecognizer
{
public:
  virtual bool RecognizeLowLevelIL(BinaryView *data, Function *func, LowLevelILFunction *il) override
  {
    /* Detection for inline veneers for thumb -> arm transitions */
    if (il->GetInstructionCount() == 1)
    {
      LowLevelILInstruction instr = il->GetInstruction(0);
      if ((instr.operation == LLIL_JUMP) || (instr.operation == LLIL_TAILCALL))
      {
        LowLevelILInstruction operand = instr.GetDestExpr();
        if (operand.operation == LLIL_CONST_PTR)
        {
          uint64_t entry = operand.GetConstant();
          if (entry == (func->GetStart() + 4))
          {
            Ref<Function> entryFunc = data->GetRecentAnalysisFunctionForAddress(entry);
            Ref<Symbol> sym = data->GetSymbolByAddress(entry);
            if (!entryFunc || !sym || (sym->GetType() != ImportedFunctionSymbol))
              return false;

            Confidence<Ref<Type>> type = entryFunc->GetType();
            data->DefineImportedFunction(sym, func, type.GetValue());
            return true;
          }
        }
      }
    }

    return false;
  }
};

/*
 * Analysis-based Function Recognizer
 *
 * Applies automatic calling convention detection and signature recovery
 * to analyzed functions. This runs after the basic IL is available.
 *
 * Features:
 * - Detects IRQ/exception handlers and applies irq-handler convention
 * - Identifies task entry functions and applies task-entry convention
 * - Recovers function signatures from register usage patterns
 *
 * Can be disabled via settings:
 * - armv5.analysis.autoDetectCallingConvention
 * - armv5.analysis.recoverSignatures
 */
class ArmAnalysisRecognizer : public FunctionRecognizer
{
public:
  virtual bool RecognizeLowLevelIL(BinaryView *data, Function *func, LowLevelILFunction *il) override
  {
    if (!data || !func || !il)
      return false;

    bool modified = false;

    /*
     * Calling Convention Detection
     *
     * Analyze function patterns to determine the appropriate calling
     * convention. This is particularly useful for:
     * - IRQ/exception handlers (need irq-handler convention)
     * - RTOS task entry functions (need task-entry convention)
     * - Leaf functions (optimization hints)
     */
    if (IsCallingConventionDetectionEnabled(data))
    {
      auto result = CallingConventionDetector::DetectConvention(data, func, il);
      if (result.confidence >= 128)
      {
        if (CallingConventionDetector::ApplyDetectedConvention(data, func, result))
        {
          modified = true;
        }
      }
    }

    /*
     * Signature Recovery
     *
     * Analyze register usage to infer function parameters and return type.
     * This helps with:
     * - Determining parameter count from r0-r3 reads
     * - Inferring pointer vs integer types from dereference patterns
     * - Detecting void vs non-void returns from r0 writes
     */
    if (IsSignatureRecoveryEnabled(data))
    {
      auto sig = SignatureRecovery::RecoverSignature(data, func, il);
      if (sig.overallConfidence >= 128)
      {
        if (SignatureRecovery::ApplyRecoveredSignature(data, func, sig))
        {
          modified = true;
        }
      }
    }

    return modified;
  }

private:
  /*
   * Check if calling convention detection is enabled in settings.
   * Default: enabled
   */
  static bool IsCallingConventionDetectionEnabled(BinaryView* view)
  {
    // Check Binary Ninja settings
    Ref<Settings> settings = Settings::Instance();
    if (settings->Contains("analysis.armv5.autoDetectCallingConvention"))
    {
      return settings->Get<bool>("analysis.armv5.autoDetectCallingConvention", view);
    }
    return true;  // Default enabled
  }

  /*
   * Check if signature recovery is enabled in settings.
   * Default: enabled
   */
  static bool IsSignatureRecoveryEnabled(BinaryView* view)
  {
    Ref<Settings> settings = Settings::Instance();
    if (settings->Contains("analysis.armv5.recoverSignatures"))
    {
      return settings->Get<bool>("analysis.armv5.recoverSignatures", view);
    }
    return true;  // Default enabled
  }
};

void RegisterArmv5FunctionRecognizers(Architecture* armv5, Architecture* thumb)
{
  if (armv5)
  {
    armv5->RegisterFunctionRecognizer(new ArmFunctionRecognizer());
    armv5->RegisterFunctionRecognizer(new ArmAnalysisRecognizer());
  }
  if (thumb)
  {
    thumb->RegisterFunctionRecognizer(new ThumbImportedFunctionRecognizer());
    thumb->RegisterFunctionRecognizer(new ArmAnalysisRecognizer());
  }
}
