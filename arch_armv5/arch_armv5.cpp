/*
 * ARMv5 Architecture Plugin Registration
 */

#include "binaryninjaapi.h"
#include "arch_armv5.h"
#include "arch/armv5_architecture.h"
#include "conventions/calling_conventions.h"
#include "recognizers/function_recognizers.h"
#include "platforms/platform_recognizers.h"
#include "relocations/relocations.h"
#include "firmware/firmware_view.h"
#include "workflow/firmware_workflow.h"

using namespace BinaryNinja;

static void RegisterArmv5Architecture(const char* armName, const char* thumbName, BNEndianness endian)
{
  ArmCommonArchitecture* armv5 = InitArmv5Architecture(armName, endian);
  ArmCommonArchitecture* thumb = InitThumbArchitecture(thumbName, endian);
  armv5->SetArmAndThumbArchitectures(armv5, thumb);
  thumb->SetArmAndThumbArchitectures(armv5, thumb);

  Architecture::Register(armv5);
  Architecture::Register(thumb);

  RegisterArmv5CallingConventions(armv5, thumb);
  RegisterArmv5FunctionRecognizers(armv5, thumb);
  RegisterArmv5PlatformRecognizers(endian);

  RegisterArmv5ElfRelocationHandlers(armv5, thumb);
  /*
      Missing:
      armv5->RegisterRelocationHandler("Mach-O", new ArmMachORelocationHandler());
      armv5->RegisterRelocationHandler("PE", new ArmPERelocationHandler());
      armv5->RegisterRelocationHandler("COFF", new ArmCOFFRelocationHandler());

      thumb->RegisterRelocationHandler("Mach-O", new ArmMachORelocationHandler());
      thumb->RegisterRelocationHandler("COFF", new ArmCOFFRelocationHandler());
  */

  /* Set up standalone platform interworking - CRITICAL for proper ARM/Thumb switching */
  armv5->GetStandalonePlatform()->AddRelatedPlatform(thumb, thumb->GetStandalonePlatform());
  thumb->GetStandalonePlatform()->AddRelatedPlatform(armv5, armv5->GetStandalonePlatform());
}

extern "C"
{
  BN_DECLARE_CORE_ABI_VERSION

  BINARYNINJAPLUGIN void CorePluginDependencies()
  {
    AddOptionalPluginDependency("view_elf");
  }

  BINARYNINJAPLUGIN bool CorePluginInit()
  {
    RegisterArmv5Architecture("armv5", "armv5t", LittleEndian);
    InitArmv5FirmwareViewType();
    RegisterArmv5FirmwareWorkflow();
    return true;
  }
}
