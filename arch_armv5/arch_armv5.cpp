/*
 * ARMv5 Architecture Plugin Registration
 *
 * ============================================================================
 * PLUGIN OVERVIEW
 * ============================================================================
 *
 * This file is the entry point for the ARMv5 Binary Ninja architecture plugin.
 * It registers all plugin components when Binary Ninja loads the plugin.
 *
 * WHAT THIS PLUGIN PROVIDES:
 * --------------------------
 * 1. Architecture: "armv5" (32-bit ARM mode) and "armv5t" (16-bit Thumb mode)
 * 2. BinaryViewType: "ARMv5 Firmware" for bare-metal ARM firmware analysis
 * 3. Calling Conventions: AAPCS, APCS, IRQ handler, task entry, Linux syscall
 * 4. ELF Relocations: R_ARM_* relocation handling
 * 5. Function Recognizers: ARM/Thumb thunk detection
 * 6. Platform Recognizers: ELF and raw binary platform detection
 * 7. Firmware Workflow: Custom analysis workflow for firmware discovery
 *
 * ARCHITECTURE RELATIONSHIP:
 * --------------------------
 * ARM processors can switch between ARM mode (32-bit instructions) and
 * Thumb mode (16-bit instructions). This requires two architectures that
 * reference each other for interworking:
 *
 *   armv5 (ARM mode) <---> armv5t (Thumb mode)
 *          ^                      ^
 *          |                      |
 *          +-- m_thumbArch -------+
 *          +-- m_armArch ---------+
 *
 * When code executes BX/BLX with bit 0 set, it switches to Thumb mode.
 * GetAssociatedArchitectureByAddress() handles this automatically.
 *
 * ============================================================================
 * INITIALIZATION ORDER
 * ============================================================================
 *
 * Plugin initialization follows a specific order:
 *
 * 1. InitPluginSettings() - Register plugin settings with Binary Ninja
 * 2. RegisterArmv5Architecture() - Register ARM and Thumb architectures
 *    a. Create architecture objects
 *    b. Link ARM <-> Thumb for interworking
 *    c. Register with Binary Ninja
 *    d. Register calling conventions
 *    e. Register function/platform recognizers
 *    f. Register ELF relocation handlers
 *    g. Set up platform interworking
 * 3. InitArmv5FirmwareViewType() - Register custom firmware BinaryViewType
 * 4. RegisterArmv5FirmwareWorkflow() - Register custom analysis workflow
 *
 * ============================================================================
 * REFERENCE: binaryninja-api/arch/armv7/arch_armv7.cpp
 * ============================================================================
 */

#include "binaryninjaapi.h"
#include "arch_armv5.h"
#include "arch/armv5_architecture.h"
#include "commands/scan_commands.h"
#include "conventions/calling_conventions.h"
#include "recognizers/function_recognizers.h"
#include "platforms/platform_recognizers.h"
#include "relocations/relocations.h"
#include "firmware/firmware_view.h"
#include "workflow/firmware_workflow.h"
#include "settings/plugin_settings.h"

using namespace BinaryNinja;

/**
 * Register ARM and Thumb architectures for a given endianness.
 *
 * This function creates both architecture objects, links them for
 * interworking, and registers all associated components (calling
 * conventions, recognizers, relocations, etc.).
 *
 * @param armName    Name for the ARM architecture (e.g., "armv5")
 * @param thumbName  Name for the Thumb architecture (e.g., "armv5t")
 * @param endian     Endianness (LittleEndian or BigEndian)
 */
static void RegisterArmv5Architecture(const char* armName, const char* thumbName, BNEndianness endian)
{
  /*
   * Create architecture objects.
   * These are separate classes that share a common base (ArmCommonArchitecture).
   */
  ArmCommonArchitecture* armv5 = InitArmv5Architecture(armName, endian);
  ArmCommonArchitecture* thumb = InitThumbArchitecture(thumbName, endian);

  /*
   * Link architectures for interworking.
   * This enables GetAssociatedArchitectureByAddress() to switch modes
   * based on bit 0 of the target address.
   */
  armv5->SetArmAndThumbArchitectures(armv5, thumb);
  thumb->SetArmAndThumbArchitectures(armv5, thumb);

  /* Register architectures with Binary Ninja */
  Architecture::Register(armv5);
  Architecture::Register(thumb);

  /*
   * Register calling conventions for both architectures.
   * Most conventions are shared, but each architecture needs its own copies.
   */
  RegisterArmv5CallingConventions(armv5, thumb);

  /*
   * Register function recognizers (thunk detection, etc.)
   */
  RegisterArmv5FunctionRecognizers(armv5, thumb);

  /*
   * Register platform recognizers (ELF detection, raw binary handling)
   */
  RegisterArmv5PlatformRecognizers(endian);

  /*
   * Register ELF relocation handlers.
   * These handle R_ARM_* relocations during ELF loading.
   */
  RegisterArmv5ElfRelocationHandlers(armv5, thumb);

  /*
   * TODO: Add Mach-O, PE, and COFF relocation handlers.
   * The ARMv7 plugin has these, but they're not commonly used for ARMv5.
   *
   * armv5->RegisterRelocationHandler("Mach-O", new ArmMachORelocationHandler());
   * armv5->RegisterRelocationHandler("PE", new ArmPERelocationHandler());
   * armv5->RegisterRelocationHandler("COFF", new ArmCOFFRelocationHandler());
   * thumb->RegisterRelocationHandler("Mach-O", new ArmMachORelocationHandler());
   * thumb->RegisterRelocationHandler("COFF", new ArmCOFFRelocationHandler());
   */

  /*
   * Set up standalone platform interworking.
   *
   * CRITICAL: This enables ARM/Thumb switching for standalone platforms
   * (raw binaries without ELF/PE headers). Without this, BX/BLX to Thumb
   * addresses would fail to switch architectures properly.
   *
   * Related platforms must be registered bidirectionally - ARM knows about
   * Thumb, and Thumb knows about ARM.
   */
  armv5->GetStandalonePlatform()->AddRelatedPlatform(thumb, thumb->GetStandalonePlatform());
  thumb->GetStandalonePlatform()->AddRelatedPlatform(armv5, armv5->GetStandalonePlatform());
}

/*
 * ============================================================================
 * PLUGIN ENTRY POINTS
 * ============================================================================
 *
 * These extern "C" functions are called by Binary Ninja's plugin loader.
 * They must follow the exact signature specified by the plugin API.
 */

extern "C"
{
  /* Declare the Binary Ninja API version this plugin is built against */
  BN_DECLARE_CORE_ABI_VERSION

  /**
   * Declare plugin dependencies.
   *
   * Called before CorePluginInit() to allow Binary Ninja to load
   * dependencies first. We optionally depend on the ELF view plugin
   * so that our ELF relocation handlers work.
   */
  BINARYNINJAPLUGIN void CorePluginDependencies()
  {
    AddOptionalPluginDependency("view_elf");
  }

  /**
   * Initialize the plugin.
   *
   * Called once when Binary Ninja loads the plugin. Registers all
   * plugin components with Binary Ninja.
   *
   * @return true on success, false to unload the plugin.
   */
  BINARYNINJAPLUGIN bool CorePluginInit()
  {
    /* Step 1: Initialize plugin settings (before other registrations) */
    Armv5Settings::InitPluginSettings();

    /* Step 2: Register ARM and Thumb architectures (little-endian) */
    RegisterArmv5Architecture("armv5", "armv5t", LittleEndian);

    /* Step 3: Register custom BinaryViewType for firmware analysis */
    InitArmv5FirmwareViewType();

    /* Step 4: Register custom workflow for firmware discovery scans */
    RegisterArmv5FirmwareWorkflow();

    /* Step 5: Register plugin commands for on-demand scans */
    Armv5Commands::RegisterScanCommands();

    return true;
  }
}
