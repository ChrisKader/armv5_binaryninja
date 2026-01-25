/*
 * ARMv5 Function Recognizer Service - Implementation
 */

#include "function_recognizer.h"
#include "common/armv5_utils.h"
#include "firmware/firmware_settings.h"

#include <chrono>
#include <unordered_map>

using namespace BinaryNinja;

namespace Armv5Analysis
{

// ============================================================================
// Settings Serialization Helpers
// ============================================================================

static const std::string kSettingsMetadataKey = "armv5.functionRecognizer.settings";
static const std::string kFeedbackMetadataKey = "armv5.functionRecognizer.feedback";

static Ref<Metadata> DetectorConfigToMetadata(const DetectorConfig& dc)
{
	std::map<std::string, Ref<Metadata>> m;
	m["enabled"] = new Metadata(dc.enabled);
	m["weight"] = new Metadata(dc.weight);
	m["threshold"] = new Metadata(dc.threshold);
	return new Metadata(m);
}

static DetectorConfig MetadataToDetectorConfig(Ref<Metadata> md, const DetectorConfig& fallback)
{
	if (!md)
		return fallback;
	auto m = md->GetKeyValueStore();
	DetectorConfig dc = fallback;
	if (m.count("enabled"))
		dc.enabled = m["enabled"]->GetBoolean();
	if (m.count("weight"))
		dc.weight = m["weight"]->GetDouble();
	if (m.count("threshold"))
		dc.threshold = m["threshold"]->GetDouble();
	return dc;
}

static Ref<Metadata> SettingsToMetadata(const FunctionDetectionSettings& s)
{
	std::map<std::string, Ref<Metadata>> m;

	// Global settings
	m["minimumScore"] = new Metadata(s.minimumScore);
	m["highConfidenceScore"] = new Metadata(s.highConfidenceScore);
	m["scanExecutableOnly"] = new Metadata(s.scanExecutableOnly);
	m["respectExistingFunctions"] = new Metadata(s.respectExistingFunctions);
	m["alignmentPreference"] = new Metadata((uint64_t)s.alignmentPreference);

	// ARM/Thumb
	m["detectArmFunctions"] = new Metadata(s.detectArmFunctions);
	m["detectThumbFunctions"] = new Metadata(s.detectThumbFunctions);
	m["useEntryPointHint"] = new Metadata(s.useEntryPointHint);

	// DetectorConfigs (prologue)
	m["prologuePush"] = DetectorConfigToMetadata(s.prologuePush);
	m["prologueSubSp"] = DetectorConfigToMetadata(s.prologueSubSp);
	m["prologueMovFp"] = DetectorConfigToMetadata(s.prologueMovFp);
	m["prologueStmfd"] = DetectorConfigToMetadata(s.prologueStmfd);

	// Call targets
	m["blTarget"] = DetectorConfigToMetadata(s.blTarget);
	m["blxTarget"] = DetectorConfigToMetadata(s.blxTarget);
	m["indirectCallTarget"] = DetectorConfigToMetadata(s.indirectCallTarget);

	// Cross-reference
	m["highXrefDensity"] = DetectorConfigToMetadata(s.highXrefDensity);
	m["pointerTableEntry"] = DetectorConfigToMetadata(s.pointerTableEntry);

	// Structural
	m["afterUnconditionalRet"] = DetectorConfigToMetadata(s.afterUnconditionalRet);
	m["afterTailCall"] = DetectorConfigToMetadata(s.afterTailCall);
	m["alignmentBoundary"] = DetectorConfigToMetadata(s.alignmentBoundary);
	m["afterLiteralPool"] = DetectorConfigToMetadata(s.afterLiteralPool);
	m["afterPadding"] = DetectorConfigToMetadata(s.afterPadding);

	// Exception/interrupt
	m["vectorTableTarget"] = DetectorConfigToMetadata(s.vectorTableTarget);
	m["interruptPrologue"] = DetectorConfigToMetadata(s.interruptPrologue);

	// Advanced patterns
	m["thunkPattern"] = DetectorConfigToMetadata(s.thunkPattern);
	m["trampolinePattern"] = DetectorConfigToMetadata(s.trampolinePattern);
	m["switchCaseHandler"] = DetectorConfigToMetadata(s.switchCaseHandler);

	// Compiler-specific
	m["gccPrologue"] = DetectorConfigToMetadata(s.gccPrologue);
	m["armccPrologue"] = DetectorConfigToMetadata(s.armccPrologue);
	m["iarPrologue"] = DetectorConfigToMetadata(s.iarPrologue);

	// RTOS
	m["taskEntryPattern"] = DetectorConfigToMetadata(s.taskEntryPattern);
	m["callbackPattern"] = DetectorConfigToMetadata(s.callbackPattern);

	// Statistical
	m["instructionSequence"] = DetectorConfigToMetadata(s.instructionSequence);
	m["entropyTransition"] = DetectorConfigToMetadata(s.entropyTransition);

	// CFG
	m["cfgValidation"] = DetectorConfigToMetadata(s.cfgValidation);
	m["useCfgValidation"] = new Metadata(s.useCfgValidation);
	m["cfgMaxBlocks"] = new Metadata((uint64_t)s.cfgMaxBlocks);
	m["cfgMaxInstructions"] = new Metadata((uint64_t)s.cfgMaxInstructions);

	// Linear sweep
	m["useLinearSweep"] = new Metadata(s.useLinearSweep);
	m["linearSweepWeight"] = new Metadata(s.linearSweepWeight);
	m["linearSweepMaxBlocks"] = new Metadata((uint64_t)s.linearSweepMaxBlocks);

	// Switch resolution
	m["useSwitchResolution"] = new Metadata(s.useSwitchResolution);
	m["switchTargetWeight"] = new Metadata(s.switchTargetWeight);
	m["switchMaxTables"] = new Metadata((uint64_t)s.switchMaxTables);

	// Tail call
	m["useTailCallAnalysis"] = new Metadata(s.useTailCallAnalysis);
	m["tailCallTargetWeight"] = new Metadata(s.tailCallTargetWeight);
	m["tailCallMaxDepth"] = new Metadata((uint64_t)s.tailCallMaxDepth);

	// Penalties
	m["midInstructionPenalty"] = new Metadata(s.midInstructionPenalty);
	m["insideFunctionPenalty"] = new Metadata(s.insideFunctionPenalty);
	m["dataRegionPenalty"] = new Metadata(s.dataRegionPenalty);
	m["invalidInstructionPenalty"] = new Metadata(s.invalidInstructionPenalty);
	m["unlikelyPatternPenalty"] = new Metadata(s.unlikelyPatternPenalty);
	m["epiloguePenalty"] = new Metadata(s.epiloguePenalty);

	// Scanning
	m["maxCandidates"] = new Metadata((uint64_t)s.maxCandidates);
	m["scanInChunks"] = new Metadata(s.scanInChunks);
	m["chunkSize"] = new Metadata((uint64_t)s.chunkSize);

	// Advanced
	m["useRecursiveDiscovery"] = new Metadata(s.useRecursiveDiscovery);
	m["detectCompilerStyle"] = new Metadata(s.detectCompilerStyle);
	m["useMachineLearningRules"] = new Metadata(s.useMachineLearningRules);

	// Unified config
	m["unifiedMode"] = new Metadata((uint64_t)s.unifiedConfig.mode);
	m["unifiedMinimumScore"] = new Metadata(s.unifiedConfig.minimumScore);
	m["unifiedHighConfidenceScore"] = new Metadata(s.unifiedConfig.highConfidenceScore);

	return new Metadata(m);
}

static FunctionDetectionSettings MetadataToSettings(Ref<Metadata> md)
{
	FunctionDetectionSettings s;
	if (!md)
		return s;

	auto m = md->GetKeyValueStore();

	// Helper lambdas for safe extraction with fallback
	auto getDouble = [&](const std::string& key, double& out) {
		if (m.count(key)) out = m[key]->GetDouble();
	};
	auto getBool = [&](const std::string& key, bool& out) {
		if (m.count(key)) out = m[key]->GetBoolean();
	};
	auto getUint32 = [&](const std::string& key, uint32_t& out) {
		if (m.count(key)) out = static_cast<uint32_t>(m[key]->GetUnsignedInteger());
	};
	auto getSizeT = [&](const std::string& key, size_t& out) {
		if (m.count(key)) out = static_cast<size_t>(m[key]->GetUnsignedInteger());
	};
	auto getDC = [&](const std::string& key, DetectorConfig& out) {
		if (m.count(key)) out = MetadataToDetectorConfig(m[key], out);
	};

	// Global
	getDouble("minimumScore", s.minimumScore);
	getDouble("highConfidenceScore", s.highConfidenceScore);
	getBool("scanExecutableOnly", s.scanExecutableOnly);
	getBool("respectExistingFunctions", s.respectExistingFunctions);
	getUint32("alignmentPreference", s.alignmentPreference);

	// ARM/Thumb
	getBool("detectArmFunctions", s.detectArmFunctions);
	getBool("detectThumbFunctions", s.detectThumbFunctions);
	getBool("useEntryPointHint", s.useEntryPointHint);

	// DetectorConfigs
	getDC("prologuePush", s.prologuePush);
	getDC("prologueSubSp", s.prologueSubSp);
	getDC("prologueMovFp", s.prologueMovFp);
	getDC("prologueStmfd", s.prologueStmfd);
	getDC("blTarget", s.blTarget);
	getDC("blxTarget", s.blxTarget);
	getDC("indirectCallTarget", s.indirectCallTarget);
	getDC("highXrefDensity", s.highXrefDensity);
	getDC("pointerTableEntry", s.pointerTableEntry);
	getDC("afterUnconditionalRet", s.afterUnconditionalRet);
	getDC("afterTailCall", s.afterTailCall);
	getDC("alignmentBoundary", s.alignmentBoundary);
	getDC("afterLiteralPool", s.afterLiteralPool);
	getDC("afterPadding", s.afterPadding);
	getDC("vectorTableTarget", s.vectorTableTarget);
	getDC("interruptPrologue", s.interruptPrologue);
	getDC("thunkPattern", s.thunkPattern);
	getDC("trampolinePattern", s.trampolinePattern);
	getDC("switchCaseHandler", s.switchCaseHandler);
	getDC("gccPrologue", s.gccPrologue);
	getDC("armccPrologue", s.armccPrologue);
	getDC("iarPrologue", s.iarPrologue);
	getDC("taskEntryPattern", s.taskEntryPattern);
	getDC("callbackPattern", s.callbackPattern);
	getDC("instructionSequence", s.instructionSequence);
	getDC("entropyTransition", s.entropyTransition);
	getDC("cfgValidation", s.cfgValidation);

	// CFG
	getBool("useCfgValidation", s.useCfgValidation);
	getSizeT("cfgMaxBlocks", s.cfgMaxBlocks);
	getSizeT("cfgMaxInstructions", s.cfgMaxInstructions);

	// Linear sweep
	getBool("useLinearSweep", s.useLinearSweep);
	getDouble("linearSweepWeight", s.linearSweepWeight);
	getSizeT("linearSweepMaxBlocks", s.linearSweepMaxBlocks);

	// Switch resolution
	getBool("useSwitchResolution", s.useSwitchResolution);
	getDouble("switchTargetWeight", s.switchTargetWeight);
	getSizeT("switchMaxTables", s.switchMaxTables);

	// Tail call
	getBool("useTailCallAnalysis", s.useTailCallAnalysis);
	getDouble("tailCallTargetWeight", s.tailCallTargetWeight);
	getSizeT("tailCallMaxDepth", s.tailCallMaxDepth);

	// Penalties
	getDouble("midInstructionPenalty", s.midInstructionPenalty);
	getDouble("insideFunctionPenalty", s.insideFunctionPenalty);
	getDouble("dataRegionPenalty", s.dataRegionPenalty);
	getDouble("invalidInstructionPenalty", s.invalidInstructionPenalty);
	getDouble("unlikelyPatternPenalty", s.unlikelyPatternPenalty);
	getDouble("epiloguePenalty", s.epiloguePenalty);

	// Scanning
	getUint32("maxCandidates", s.maxCandidates);
	getBool("scanInChunks", s.scanInChunks);
	getUint32("chunkSize", s.chunkSize);

	// Advanced
	getBool("useRecursiveDiscovery", s.useRecursiveDiscovery);
	getBool("detectCompilerStyle", s.detectCompilerStyle);
	getBool("useMachineLearningRules", s.useMachineLearningRules);

	// Unified config
	if (m.count("unifiedMode"))
	{
		uint64_t modeVal = m["unifiedMode"]->GetUnsignedInteger();
		if (modeVal <= static_cast<uint64_t>(DetectionMode::Conservative))
			s.unifiedConfig.mode = static_cast<DetectionMode>(modeVal);
	}
	getDouble("unifiedMinimumScore", s.unifiedConfig.minimumScore);
	getDouble("unifiedHighConfidenceScore", s.unifiedConfig.highConfidenceScore);

	return s;
}

// Global map of session ID -> recognizer
// Uses session ID instead of raw pointer to prevent ABA problem
// (where a freed view's address is reused by a new allocation)
static std::mutex g_recognizerMapMutex;
static std::unordered_map<size_t, std::unique_ptr<FunctionRecognizer>>* g_recognizerMap = nullptr;

static std::unordered_map<size_t, std::unique_ptr<FunctionRecognizer>>& GetRecognizerMap()
{
	if (!g_recognizerMap)
		g_recognizerMap = new std::unordered_map<size_t, std::unique_ptr<FunctionRecognizer>>();
	return *g_recognizerMap;
}

static size_t GetViewSessionKey(BinaryView* view)
{
	auto file = view->GetFile();
	return file ? file->GetSessionId() : 0;
}

FunctionRecognizer* GetRecognizerForView(BinaryView* view)
{
	if (!view)
		return nullptr;

	size_t key = GetViewSessionKey(view);
	if (key == 0)
		return nullptr;

	std::lock_guard<std::mutex> lock(g_recognizerMapMutex);
	auto& map = GetRecognizerMap();

	auto it = map.find(key);
	if (it != map.end())
		return it->second.get();

	// Create new recognizer
	auto recognizer = std::make_unique<FunctionRecognizer>(view);
	FunctionRecognizer* ptr = recognizer.get();
	map[key] = std::move(recognizer);
	return ptr;
}

void ReleaseRecognizerForView(BinaryView* view)
{
	if (!view)
		return;

	size_t key = GetViewSessionKey(view);
	if (key == 0)
		return;

	std::lock_guard<std::mutex> lock(g_recognizerMapMutex);
	auto& map = GetRecognizerMap();
	map.erase(key);
}

FunctionRecognizer::FunctionRecognizer(Ref<BinaryView> view)
	: m_view(view)
	, m_settings(FunctionDetector::DefaultSettings())
{
	m_logger = LogRegistry::CreateLogger("ARMv5.FunctionRecognizer");
	m_detector = std::make_unique<FunctionDetector>(view);

	// Try to load saved settings and feedback from view metadata
	LoadSettingsFromView();
	LoadFeedbackFromView();
}

FunctionRecognizer::~FunctionRecognizer()
{
	// Save settings and feedback before destruction
	SaveSettingsToView();
	SaveFeedbackToView();
}

bool FunctionRecognizer::ShouldCancel() const
{
	if (m_cancellationRequested)
		return true;
	if (BNIsShutdownRequested())
		return true;
	if (!m_view || !m_view->GetObject())
		return true;
	return false;
}

void FunctionRecognizer::UpdateProgress(size_t current, size_t total, const std::string& status)
{
	if (m_progressCallback)
	{
		if (!m_progressCallback(current, total, status))
			m_cancellationRequested = true;
	}
}

RecognitionResult FunctionRecognizer::RunRecognition()
{
	return RunRecognition(m_settings);
}

RecognitionResult FunctionRecognizer::RunRecognition(const FunctionDetectionSettings& settings)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	RecognitionResult result;
	m_isRunning = true;
	m_cancellationRequested = false;

	auto startTime = std::chrono::steady_clock::now();

	try
	{
		if (ShouldCancel())
		{
			result.cancelled = true;
			result.errorMessage = "Cancelled before starting";
			m_isRunning = false;
			return result;
		}

		m_logger->LogInfo("FunctionRecognizer: Starting detection...");
		UpdateProgress(0, 100, "Starting function recognition...");

		// Auto-apply feedback-adjusted settings if feedback exists
		FunctionDetectionSettings effectiveSettings = settings;
		if (m_feedback.HasFeedback())
		{
			effectiveSettings = m_feedback.ComputeAdjustedSettings(settings);
			m_logger->LogInfo("FunctionRecognizer: Applied feedback adjustments (%zu entries)",
				m_feedback.GetFeedback().size());
		}

		// Run the detector with progress forwarding
		m_detector->SetSettings(effectiveSettings);
		m_detector->SetProgressCallback([this](size_t phase, size_t total, const std::string& phaseName) {
			// Map detector phases (1-14) to progress percentage (0-90%)
			// Reserve last 10% for post-processing
			size_t progress = (phase * 90) / total;
			UpdateProgress(progress, 100, phaseName);
			return !ShouldCancel();
		});
		result.candidates = m_detector->Detect();
		result.stats = m_detector->GetStats();

		if (ShouldCancel())
		{
			result.cancelled = true;
			result.errorMessage = "Cancelled during detection";
			m_isRunning = false;
			return result;
		}

		// Categorize by confidence using the effective (feedback-adjusted) thresholds
		for (const auto& candidate : result.candidates)
		{
			if (candidate.score >= effectiveSettings.highConfidenceScore)
				result.highConfidenceCount++;
			else if (candidate.score >= effectiveSettings.minimumScore)
				result.mediumConfidenceCount++;
			else
				result.lowConfidenceCount++;
		}

		result.completed = true;

		auto endTime = std::chrono::steady_clock::now();
		result.durationSeconds = std::chrono::duration<double>(endTime - startTime).count();

		m_logger->LogInfo("FunctionRecognizer: Found %zu candidates (%zu high, %zu med, %zu low) in %.2fs",
			result.candidates.size(),
			result.highConfidenceCount,
			result.mediumConfidenceCount,
			result.lowConfidenceCount,
			result.durationSeconds);

		UpdateProgress(100, 100, "Recognition complete");
	}
	catch (const std::exception& e)
	{
		result.errorMessage = std::string("Exception: ") + e.what();
		m_logger->LogError("FunctionRecognizer: %s", result.errorMessage.c_str());
	}

	m_lastResult = result;
	m_isRunning = false;
	return result;
}

size_t FunctionRecognizer::ApplyResults(const RecognitionResult& results, double minScore)
{
	if (!m_view || !m_view->GetObject())
		return 0;

	size_t created = 0;
	Ref<Platform> platform = m_view->GetDefaultPlatform();
	if (!platform)
	{
		m_logger->LogError("FunctionRecognizer: No default platform");
		return 0;
	}

	Ref<Architecture> baseArch = m_view->GetDefaultArchitecture();

	// Get effective code-data boundary using centralized logic
	FirmwareSettings fwSettings = DefaultFirmwareSettings(FirmwareSettingsMode::Workflow);
	Ref<Settings> viewSettings = m_view->GetLoadSettings(m_view->GetTypeName());
	if (viewSettings)
		fwSettings = LoadFirmwareSettings(viewSettings, m_view.GetPtr(), FirmwareSettingsMode::Workflow);
	uint64_t codeDataBoundary = GetEffectiveCodeDataBoundary(m_view, fwSettings);

	for (const auto& candidate : results.candidates)
	{
		if (candidate.score < minScore)
			continue;

		// Validate alignment: ARM requires 4-byte, Thumb requires 2-byte
		uint64_t funcAddr = candidate.address & ~1ULL;  // Clear potential Thumb bit
		if (!candidate.isThumb && (funcAddr & 3))
			continue;  // ARM function at non-4-byte-aligned address - skip
		if (candidate.isThumb && (funcAddr & 1))
			continue;  // Thumb function at odd address - skip

		// Skip if function already exists
		if (m_view->GetAnalysisFunction(platform, funcAddr))
			continue;

		// Check code-data boundary using centralized logic
		if (codeDataBoundary != 0 && funcAddr >= codeDataBoundary)
		{
			m_logger->LogDebug("FunctionRecognizer: Skipping function at 0x%llx - in data region (>= 0x%llx)",
				(unsigned long long)funcAddr, (unsigned long long)codeDataBoundary);
			continue;
		}

		// Skip if address is inside a detected string
		BNStringReference strRef;
		if (m_view->GetStringAtAddress(funcAddr, strRef) && strRef.length > 0)
		{
			m_logger->LogDebug("FunctionRecognizer: Skipping function at 0x%llx - inside string at 0x%llx (len=%zu)",
				(unsigned long long)funcAddr, (unsigned long long)strRef.start, strRef.length);
			continue;
		}

		// Resolve platform for Thumb mode
		Ref<Platform> targetPlat = platform;
		if (baseArch && candidate.isThumb)
		{
			// Set bit 0 so GetAssociatedArchitectureByAddress returns Thumb arch
			uint64_t thumbAddr = candidate.address | 1;
			Ref<Architecture> thumbArch = baseArch->GetAssociatedArchitectureByAddress(thumbAddr);
			if (thumbArch && thumbArch != baseArch)
			{
				Ref<Platform> thumbPlat = platform->GetRelatedPlatform(thumbArch);
				if (thumbPlat)
					targetPlat = thumbPlat;
			}
		}

		// Validate before creating function (check for strings, padding, etc.)
		if (!armv5::IsValidFunctionStart(m_view, targetPlat, funcAddr, m_logger.GetPtr(), "FunctionRecognizer"))
		{
			m_logger->LogDebug("FunctionRecognizer: Rejected 0x%llx - failed validation",
				(unsigned long long)funcAddr);
			continue;
		}

		// Create the function
		Ref<Function> func = m_view->CreateUserFunction(targetPlat, funcAddr);
		if (func)
			created++;
	}

	m_logger->LogInfo("FunctionRecognizer: Created %zu functions", created);
	return created;
}

size_t FunctionRecognizer::RecognizeAndApply(double minScore)
{
	auto results = RunRecognition();
	if (!results.completed)
		return 0;
	return ApplyResults(results, minScore);
}

std::vector<std::pair<uint64_t, bool>> FunctionRecognizer::GetCandidateAddresses(
	const RecognitionResult& results, double minScore) const
{
	std::vector<std::pair<uint64_t, bool>> addresses;
	addresses.reserve(results.candidates.size());

	for (const auto& candidate : results.candidates)
	{
		if (candidate.score >= minScore)
			addresses.emplace_back(candidate.address, candidate.isThumb);
	}

	return addresses;
}

void FunctionRecognizer::SetSettings(const FunctionDetectionSettings& settings)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_settings = settings;
	if (m_detector)
		m_detector->SetSettings(settings);
}

void FunctionRecognizer::LoadSettingsFromView()
{
	if (!m_view)
		return;

	auto metadata = m_view->QueryMetadata(kSettingsMetadataKey);
	if (!metadata)
		return;

	m_settings = MetadataToSettings(metadata);
	if (m_detector)
		m_detector->SetSettings(m_settings);

	m_logger->LogDebug("FunctionRecognizer: Loaded settings from view metadata");
}

void FunctionRecognizer::SaveSettingsToView()
{
	if (!m_view || !m_view->GetObject())
		return;

	m_view->StoreMetadata(kSettingsMetadataKey, SettingsToMetadata(m_settings));

	m_logger->LogDebug("FunctionRecognizer: Saved settings to view metadata");
}

void FunctionRecognizer::UseDefaultSettings()
{
	SetSettings(FunctionDetector::DefaultSettings());
}

void FunctionRecognizer::UseAggressiveSettings()
{
	SetSettings(FunctionDetector::AggressiveSettings());
}

void FunctionRecognizer::UseConservativeSettings()
{
	SetSettings(FunctionDetector::ConservativeSettings());
}

void FunctionRecognizer::UsePrologueOnlySettings()
{
	SetSettings(FunctionDetector::PrologueOnlySettings());
}

void FunctionRecognizer::UseCallTargetOnlySettings()
{
	SetSettings(FunctionDetector::CallTargetOnlySettings());
}

std::vector<FunctionRecognizer::TunableParameter> FunctionRecognizer::GetTunableParameters()
{
	std::vector<TunableParameter> params;

	// Global settings
	params.push_back({"minimumScore", "Minimum score to report a candidate", "Global", TunableParameter::Double, 0.0, 1.0, 0.4});
	params.push_back({"highConfidenceScore", "Score threshold for high confidence", "Global", TunableParameter::Double, 0.0, 1.0, 0.8});
	params.push_back({"alignmentPreference", "Preferred byte alignment", "Global", TunableParameter::Int, 1, 16, 4});

	// Mode detection
	params.push_back({"detectArmFunctions", "Detect ARM mode functions", "Mode", TunableParameter::Bool, 0, 1, 1});
	params.push_back({"detectThumbFunctions", "Detect Thumb mode functions", "Mode", TunableParameter::Bool, 0, 1, 1});

	// Prologue detectors
	params.push_back({"prologuePush.enabled", "Enable PUSH prologue detection", "Prologue", TunableParameter::Bool, 0, 1, 1});
	params.push_back({"prologuePush.weight", "Weight for PUSH prologue", "Prologue", TunableParameter::Double, 0.0, 5.0, 1.5});
	params.push_back({"prologueSubSp.enabled", "Enable SUB SP prologue detection", "Prologue", TunableParameter::Bool, 0, 1, 1});
	params.push_back({"prologueSubSp.weight", "Weight for SUB SP prologue", "Prologue", TunableParameter::Double, 0.0, 5.0, 0.8});

	// Call targets
	params.push_back({"blTarget.enabled", "Enable BL target detection", "Call Targets", TunableParameter::Bool, 0, 1, 1});
	params.push_back({"blTarget.weight", "Weight for BL targets", "Call Targets", TunableParameter::Double, 0.0, 5.0, 2.0});
	params.push_back({"blxTarget.enabled", "Enable BLX target detection", "Call Targets", TunableParameter::Bool, 0, 1, 1});
	params.push_back({"blxTarget.weight", "Weight for BLX targets", "Call Targets", TunableParameter::Double, 0.0, 5.0, 2.0});

	// Structural
	params.push_back({"afterUnconditionalRet.enabled", "Detect after return patterns", "Structural", TunableParameter::Bool, 0, 1, 1});
	params.push_back({"afterUnconditionalRet.weight", "Weight for after-return", "Structural", TunableParameter::Double, 0.0, 5.0, 1.3});

	// CFG validation
	params.push_back({"useCfgValidation", "Enable CFG validation", "CFG", TunableParameter::Bool, 0, 1, 1});
	params.push_back({"cfgValidation.weight", "Weight for CFG validation", "CFG", TunableParameter::Double, 0.0, 5.0, 2.0});

	// Penalties
	params.push_back({"midInstructionPenalty", "Penalty for mid-instruction", "Penalties", TunableParameter::Double, 0.0, 3.0, 1.0});
	params.push_back({"insideFunctionPenalty", "Penalty for inside function", "Penalties", TunableParameter::Double, 0.0, 3.0, 0.8});
	params.push_back({"dataRegionPenalty", "Penalty for data region", "Penalties", TunableParameter::Double, 0.0, 3.0, 0.9});

	return params;
}

DetectionFeedback FunctionRecognizer::GetFeedback() const
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_feedback;
}

void FunctionRecognizer::RecordFeedback(uint64_t addr, FeedbackType type, uint32_t sources, double score)
{
	{
		std::lock_guard<std::mutex> lock(m_mutex);

		switch (type)
		{
		case FeedbackType::Correct:
			m_feedback.RecordCorrectDetection(addr, sources, score);
			break;
		case FeedbackType::FalsePositive:
			m_feedback.RecordFalsePositive(addr, sources, score);
			break;
		case FeedbackType::Missed:
			m_feedback.RecordMissedFunction(addr);
			break;
		}
	}

	// Persist outside the lock to avoid deadlock if StoreMetadata
	// triggers callbacks that re-enter FunctionRecognizer
	SaveFeedbackToView();

	m_logger->LogDebug("FunctionRecognizer: Recorded %s feedback at 0x%llx",
		type == FeedbackType::Correct ? "correct" :
		type == FeedbackType::FalsePositive ? "false-positive" : "missed",
		(unsigned long long)addr);
}

void FunctionRecognizer::ClearFeedback()
{
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_feedback.Clear();
	}

	// Persist outside the lock — removes stale metadata
	SaveFeedbackToView();
}

void FunctionRecognizer::LoadFeedbackFromView()
{
	if (!m_view)
		return;

	auto metadata = m_view->QueryMetadata(kFeedbackMetadataKey);
	if (!metadata)
		return;

	m_feedback = DetectionFeedback::FromMetadata(metadata);

	m_logger->LogDebug("FunctionRecognizer: Loaded %zu feedback entries from view metadata",
		m_feedback.GetFeedback().size());
}

void FunctionRecognizer::SaveFeedbackToView()
{
	if (!m_view || !m_view->GetObject())
		return;

	if (m_feedback.HasFeedback())
		m_view->StoreMetadata(kFeedbackMetadataKey, m_feedback.ToMetadata());
	else
		m_view->RemoveMetadata(kFeedbackMetadataKey);

	m_logger->LogDebug("FunctionRecognizer: Saved %zu feedback entries to view metadata",
		m_feedback.GetFeedback().size());
}

}  // namespace Armv5Analysis
