/*
 * ARMv5 Function Recognizers
 */

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "arch_armv5.h"
#include "recognizers/function_recognizers.h"

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

void RegisterArmv5FunctionRecognizers(Architecture* armv5, Architecture* thumb)
{
  if (armv5)
    armv5->RegisterFunctionRecognizer(new ArmFunctionRecognizer());
  if (thumb)
    thumb->RegisterFunctionRecognizer(new ThumbImportedFunctionRecognizer());
}
