# ARM926EJ-S (ARMv5TEJ) Calling Conventions for Binary Ninja (C/C++)

This document consolidates the complete calling-convention portion of the ARM926EJ-S / ARMv5 plugin guidance, including:
- AAPCS (EABI) calling convention
- APCS-32 / ATPCS (legacy) calling convention
- IRQ/exception handler calling convention
- RTOS task entry calling convention
- Registration + default selection in `CorePluginInit`

> Scope: **Calling conventions only.** (No lifter / CFG / exception-return terminators / interworking IL here.)

---

## 1. Why multiple calling conventions matter on ARM926EJ-S embedded firmware

ARM926EJ-S systems (ARMv5TEJ) in embedded/RTOS environments commonly mix:
- Modern **AAPCS (EABI)** compiled code
- Legacy **APCS-32 / ATPCS** code (older ARM/ADS & some RTOS builds)
- **Exception vectors / IRQ handlers** with non-standard entry/exit behavior
- **RTOS task entry points** created by the scheduler, not called like normal C functions

Binary Ninja can model this correctly by registering multiple calling conventions for your architecture and allowing user/heuristic selection.

---

## 2. Baseline ABIs

### 2.1 AAPCS (ARM EABI) - recommended default
**Arguments**
- `r0-r3`: first 4 integer/pointer args
- remaining args: on stack

**Returns**
- `r0`: return value
- `r0-r1`: 64-bit return values

**Caller-saved (volatile)**
- `r0-r3`, `r12 (ip)`, `lr`

**Callee-saved (non-volatile)**
- `r4-r11`
- `r9` is platform-specific but is often treated as callee-saved in embedded builds

**Stack**
- **8-byte aligned** at public interfaces
- caller cleans the stack (ARM convention)

### 2.2 APCS-32 / ATPCS - legacy embedded
**Arguments / returns**
- same as AAPCS (r0-r3 args, r0 return)

**Caller-saved**
- `r0-r3`, `r12`, `lr`

**Callee-saved**
- `r4-r11`, often `r9`

**Stack**
- **4-byte alignment** common
- caller cleans

### 2.3 IRQ / Exception handlers (not standard calls)
Conservative modeling:
- no arguments
- no return registers
- **treat all GPRs as clobbered** (caller-saved)
- stack alignment often 4

### 2.4 RTOS Task Entry (Nucleus-like)
Many RTOS task entry points are invoked with:
- `r0 = argc`
- `r1 = argv`
- `lr = task exit stub`
- `sp = task stack top`

Conservative convention:
- args: `r0, r1`
- no return registers
- otherwise similar to AAPCS
- typically treated as `noreturn` at the function level (not part of CC metadata)

---

## 3. Binary Ninja implementation approach (C/C++)

Binary Ninja calling conventions are **metadata objects** describing:
- argument registers
- return registers
- caller/callee-saved registers
- stack pointer / link register / optional global pointer
- stack alignment

They are created from `BNCallingConventionInfo`, registered with `BNRegisterCallingConvention`, and defaults are typically set on the **Platform**.

---

## 4. Complete C++ Code

### 4.1 Helpers

```cpp
#include "binaryninjaapi.h"
using namespace BinaryNinja;

static uint32_t Reg(Architecture* arch, const char* name)
{
    uint32_t idx = BNGetRegisterIndexByName(arch->GetObject(), name);
    if (idx == BN_INVALID_REGISTER)
        LogWarn("Missing register '%s' in architecture", name);
    return idx;
}
```

---

### 4.2 AAPCS (EABI)

```cpp
static BNCallingConvention* CreateCC_AAPCS(Architecture* arch)
{
    BNCallingConventionInfo info = {};
    info.name = "armv5_aapcs";

    // Integer argument registers r0-r3
    static uint32_t intArgs[] = { Reg(arch,"r0"), Reg(arch,"r1"), Reg(arch,"r2"), Reg(arch,"r3") };
    info.intArgRegs = intArgs; info.intArgRegCount = 4;

    // Return register r0 (and r1 for 64-bit)
    static uint32_t retRegs[] = { Reg(arch,"r0") };
    info.intReturnRegs = retRegs; info.intReturnRegCount = 1;

    static uint32_t highRet[] = { Reg(arch,"r1") };
    info.highIntReturnRegs = highRet; info.highIntReturnRegCount = 1;

    // Caller-saved regs: r0-r3, r12, lr
    static uint32_t callerSaved[] = {
        Reg(arch,"r0"),Reg(arch,"r1"),Reg(arch,"r2"),Reg(arch,"r3"),
        Reg(arch,"r12"),Reg(arch,"lr")
    };
    info.callerSavedRegs = callerSaved; info.callerSavedRegCount = 6;

    // Callee-saved regs: r4-r11 (+r9 commonly)
    static uint32_t calleeSaved[] = {
        Reg(arch,"r4"),Reg(arch,"r5"),Reg(arch,"r6"),Reg(arch,"r7"),
        Reg(arch,"r8"),Reg(arch,"r9"),Reg(arch,"r10"),Reg(arch,"r11")
    };
    info.calleeSavedRegs = calleeSaved; info.calleeSavedRegCount = 8;

    info.stackPointerReg = Reg(arch,"sp");
    info.linkReg = Reg(arch,"lr");
    info.globalPointerReg = Reg(arch,"r9"); // optional but common embedded

    info.stackAlignment = 8;
    info.stackAdjustRet = 0; // caller cleans (ARM)

    return BNCreateCallingConvention(arch->GetObject(), &info);
}
```

---

### 4.3 APCS-32 / ATPCS (legacy)

```cpp
static BNCallingConvention* CreateCC_APCS(Architecture* arch)
{
    BNCallingConventionInfo info = {};
    info.name = "armv5_apcs";

    static uint32_t intArgs[] = { Reg(arch,"r0"), Reg(arch,"r1"), Reg(arch,"r2"), Reg(arch,"r3") };
    info.intArgRegs = intArgs; info.intArgRegCount = 4;

    static uint32_t retRegs[] = { Reg(arch,"r0") };
    info.intReturnRegs = retRegs; info.intReturnRegCount = 1;

    static uint32_t callerSaved[] = {
        Reg(arch,"r0"),Reg(arch,"r1"),Reg(arch,"r2"),Reg(arch,"r3"),
        Reg(arch,"r12"),Reg(arch,"lr")
    };
    info.callerSavedRegs = callerSaved; info.callerSavedRegCount = 6;

    static uint32_t calleeSaved[] = {
        Reg(arch,"r4"),Reg(arch,"r5"),Reg(arch,"r6"),Reg(arch,"r7"),
        Reg(arch,"r8"),Reg(arch,"r9"),Reg(arch,"r10"),Reg(arch,"r11")
    };
    info.calleeSavedRegs = calleeSaved; info.calleeSavedRegCount = 8;

    info.stackPointerReg = Reg(arch,"sp");
    info.linkReg = Reg(arch,"lr");
    info.globalPointerReg = Reg(arch,"r9"); // APCS commonly uses r9 as SB

    info.stackAlignment = 4;
    info.stackAdjustRet = 0;

    return BNCreateCallingConvention(arch->GetObject(), &info);
}
```

---

### 4.4 IRQ / Exception handler convention

```cpp
static BNCallingConvention* CreateCC_IRQ(Architecture* arch)
{
    BNCallingConventionInfo info = {};
    info.name = "armv5_irq_handler";

    // No explicit args
    info.intArgRegs = nullptr; info.intArgRegCount = 0;

    // No returns
    info.intReturnRegs = nullptr; info.intReturnRegCount = 0;

    // Conservatively treat all regs as caller-saved
    static uint32_t callerSaved[] = {
        Reg(arch,"r0"),Reg(arch,"r1"),Reg(arch,"r2"),Reg(arch,"r3"),
        Reg(arch,"r4"),Reg(arch,"r5"),Reg(arch,"r6"),Reg(arch,"r7"),
        Reg(arch,"r8"),Reg(arch,"r9"),Reg(arch,"r10"),Reg(arch,"r11"),
        Reg(arch,"r12"),Reg(arch,"lr")
    };
    info.callerSavedRegs = callerSaved;
    info.callerSavedRegCount = sizeof(callerSaved)/sizeof(callerSaved[0]);

    info.calleeSavedRegs = nullptr;
    info.calleeSavedRegCount = 0;

    info.stackPointerReg = Reg(arch,"sp");
    info.linkReg = Reg(arch,"lr");
    info.stackAlignment = 4;

    return BNCreateCallingConvention(arch->GetObject(), &info);
}
```

---

### 4.5 RTOS Task Entry convention

```cpp
static BNCallingConvention* CreateCC_TaskEntry(Architecture* arch)
{
    BNCallingConventionInfo info = {};
    info.name = "armv5_task_entry";

    // Common RTOS task entry args: (argc, argv) in r0/r1
    static uint32_t intArgs[] = { Reg(arch,"r0"), Reg(arch,"r1") };
    info.intArgRegs = intArgs; info.intArgRegCount = 2;

    // Tasks generally do not return; model as no return regs
    info.intReturnRegs = nullptr; info.intReturnRegCount = 0;

    static uint32_t callerSaved[] = {
        Reg(arch,"r0"),Reg(arch,"r1"),Reg(arch,"r2"),Reg(arch,"r3"),
        Reg(arch,"r12"),Reg(arch,"lr")
    };
    info.callerSavedRegs = callerSaved; info.callerSavedRegCount = 6;

    static uint32_t calleeSaved[] = {
        Reg(arch,"r4"),Reg(arch,"r5"),Reg(arch,"r6"),Reg(arch,"r7"),
        Reg(arch,"r8"),Reg(arch,"r9"),Reg(arch,"r10"),Reg(arch,"r11")
    };
    info.calleeSavedRegs = calleeSaved; info.calleeSavedRegCount = 8;

    info.stackPointerReg = Reg(arch,"sp");
    info.linkReg = Reg(arch,"lr");
    info.globalPointerReg = Reg(arch,"r9");

    info.stackAlignment = 8;
    info.stackAdjustRet = 0;

    return BNCreateCallingConvention(arch->GetObject(), &info);
}
```

---

## 5. Registration + default selection in `CorePluginInit`

```cpp
extern "C"
{
    BN_DECLARE_CORE_ABI_VERSION

    BINARYNINJAPLUGIN bool CorePluginInit()
    {
        Ref<Architecture> arch = Architecture::GetByName("armv5");
        if (!arch)
        {
            LogError("armv5 architecture not found. Ensure your architecture is registered first.");
            return false;
        }

        BNCallingConvention* aapcs = CreateCC_AAPCS(arch.get());
        BNCallingConvention* apcs  = CreateCC_APCS(arch.get());
        BNCallingConvention* irq   = CreateCC_IRQ(arch.get());
        BNCallingConvention* task  = CreateCC_TaskEntry(arch.get());

        if (!aapcs || !apcs || !irq || !task)
        {
            LogError("Failed to create calling conventions.");
            return false;
        }

        BNRegisterCallingConvention(arch->GetObject(), aapcs);
        BNRegisterCallingConvention(arch->GetObject(), apcs);
        BNRegisterCallingConvention(arch->GetObject(), irq);
        BNRegisterCallingConvention(arch->GetObject(), task);

        // Defaults are set per-platform (standalone platform shown here)
        Ref<Platform> plat = arch->GetStandalonePlatform();
        if (plat)
        {
            plat->SetDefaultCallingConvention(CallingConvention(plat->GetObject(), aapcs));
            plat->SetSystemCallConvention(CallingConvention(plat->GetObject(), aapcs));
        }

        LogInfo("ARMv5: registered calling conventions: aapcs, apcs, irq_handler, task_entry");
        return true;
    }
}
```

---

## 6. Notes / Embedded-specific considerations

### 6.1 `r9` as global pointer
Embedded toolchains often use `r9` for:
- static base
- TLS base
- per-task control block pointer

If this is true for your firmware, keeping `globalPointerReg = r9` improves analysis.

### 6.2 Stack alignment differences
- AAPCS: 8-byte aligned at public interfaces
- APCS: often 4-byte aligned

If the wrong stack alignment is chosen as default, you may see odd parameter/stack variable recovery.

### 6.3 IRQ CC is conservative
IRQ/exception entry/exit is not a normal function call. Modeling all regs as caller-saved is the safest default for analysis.

### 6.4 Task entry functions are typically `noreturn`
Binary Ninja's calling convention metadata does **not** mark `noreturn` by itself. Mark task entry functions as `noreturn` at the Function level if you auto-detect them.

---

## 7. Recommended defaults

- Default calling convention: **`armv5_aapcs`**
- Provide user override: allow switching to **`armv5_apcs`**
- Apply **`armv5_irq_handler`** for vector/IRQ functions
- Apply **`armv5_task_entry`** for RTOS task entrypoints

---

### End of document
