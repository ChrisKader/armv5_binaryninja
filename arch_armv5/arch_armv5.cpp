/*
 * ARMv5 Architecture Plugin Registration
 */

#include <cctype>
#include <cstdlib>
#include <exception>
#include <string>

#include "binaryninjaapi.h"
#include "arch_armv5.h"
#include "arch/armv5_architecture.h"
#include "conventions/calling_conventions.h"
#include "recognizers/function_recognizers.h"
#include "platforms/platform_recognizers.h"
#include "relocations/relocations.h"
#include "firmware/firmware_view.h"

using namespace BinaryNinja;
using namespace std;

static bool FirmwareWorkflowDisabledByEnv()
{
  const char* disableScans = getenv("BN_ARMV5_FIRMWARE_DISABLE_SCANS");
  if (!disableScans || disableScans[0] == '\0')
    return false;
  string token;
  auto checkToken = [&](const string& raw) -> bool {
    if (raw.empty())
      return false;
    string normalized;
    normalized.reserve(raw.size());
    for (char ch : raw)
    {
      if (ch == '-')
        ch = '_';
      normalized.push_back(static_cast<char>(tolower(static_cast<unsigned char>(ch))));
    }
    return (normalized == "all" || normalized == "skip" || normalized == "skip_scans"
      || normalized == "skip_firmware_scans");
  };
  for (const char* p = disableScans; *p; ++p)
  {
    char c = *p;
    if (c == ',' || c == ';' || c == ' ' || c == '\t' || c == '\n' || c == '\r')
    {
      if (checkToken(token))
        return true;
      token.clear();
      continue;
    }
    token.push_back(c);
  }
  return checkToken(token);
}

static void RunArmv5FirmwareWorkflow(const Ref<AnalysisContext>& analysisContext)
{
  if (!analysisContext)
    return;
  auto view = analysisContext->GetBinaryView();
  if (!view)
    return;
  auto platform = view->GetDefaultPlatform();
  if (!platform)
    return;
  auto platformName = platform->GetName();
  if (platformName.find("armv5") != std::string::npos)
  {
    try
    {
      if (FirmwareWorkflowDisabledByEnv())
        return;
      RunArmv5FirmwareWorkflowScans(view);
    }
    catch (std::exception& e)
    {
      LogErrorForException(e, "Armv5 Firmware Workflow failed with uncaugt exception: %s", e.what());
    }
  }
}

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

    const char* disableWorkflow = getenv("BN_ARMV5_DISABLE_WORKFLOW");
    if (!disableWorkflow || disableWorkflow[0] == '\0')
    {
      // Register a module workflow activity that runs ARMv5 firmware scans alongside core analysis.
      Ref<Workflow> firmwareWorkflow = Workflow::Get("core.module.metaAnalysis")->Clone();
      firmwareWorkflow->RegisterActivity(R"~({
        "title": "ARMv5 Firmware Scan",
        "name": "analysis.armv5.firmwareScan",
        "role": "action",
        "description": "Run ARMv5 firmware discovery passes (prologue/call/pointer/orphan scans and cleanup).",
        "eligibility": {
          "runOnce": true,
          "auto": { "default": true },
          "predicates": [
            {
              "type": "viewType",
              "operator": "in",
              "value": ["ARMv5 Firmware"]
            }
          ]
        },
        "dependencies": {
          "downstream": ["core.module.update"]
        }
      })~", &RunArmv5FirmwareWorkflow);
      firmwareWorkflow->InsertAfter("core.module.extendedAnalysis", "analysis.armv5.firmwareScan");
      Workflow::RegisterWorkflow(firmwareWorkflow);
    }
    else
    {
      LogInfo("ARMv5 firmware workflow disabled via BN_ARMV5_DISABLE_WORKFLOW");
    }
    return true;
  }
}
