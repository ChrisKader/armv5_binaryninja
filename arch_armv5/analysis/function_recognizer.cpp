/*
 * ARMv5 Function Recognizer Service - Implementation
 */

#include "function_recognizer.h"

#include <chrono>
#include <unordered_map>

using namespace BinaryNinja;

namespace Armv5Analysis
{

// Global map of view -> recognizer
static std::mutex g_recognizerMapMutex;
static std::unordered_map<uintptr_t, std::unique_ptr<FunctionRecognizer>>* g_recognizerMap = nullptr;

static std::unordered_map<uintptr_t, std::unique_ptr<FunctionRecognizer>>& GetRecognizerMap()
{
	if (!g_recognizerMap)
		g_recognizerMap = new std::unordered_map<uintptr_t, std::unique_ptr<FunctionRecognizer>>();
	return *g_recognizerMap;
}

FunctionRecognizer* GetRecognizerForView(BinaryView* view)
{
	if (!view)
		return nullptr;

	std::lock_guard<std::mutex> lock(g_recognizerMapMutex);
	auto& map = GetRecognizerMap();

	uintptr_t key = reinterpret_cast<uintptr_t>(view);
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

	std::lock_guard<std::mutex> lock(g_recognizerMapMutex);
	auto& map = GetRecognizerMap();

	uintptr_t key = reinterpret_cast<uintptr_t>(view);
	map.erase(key);
}

FunctionRecognizer::FunctionRecognizer(Ref<BinaryView> view)
	: m_view(view)
	, m_settings(FunctionDetector::DefaultSettings())
{
	m_logger = LogRegistry::CreateLogger("FunctionRecognizer");
	m_detector = std::make_unique<FunctionDetector>(view);

	// Try to load saved settings from view metadata
	LoadSettingsFromView();
}

FunctionRecognizer::~FunctionRecognizer()
{
	// Save settings before destruction
	SaveSettingsToView();
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

		// Run the detector
		m_detector->SetSettings(settings);
		result.candidates = m_detector->Detect();
		result.stats = m_detector->GetStats();

		if (ShouldCancel())
		{
			result.cancelled = true;
			result.errorMessage = "Cancelled during detection";
			m_isRunning = false;
			return result;
		}

		// Categorize by confidence
		for (const auto& candidate : result.candidates)
		{
			if (candidate.score >= settings.highConfidenceScore)
				result.highConfidenceCount++;
			else if (candidate.score >= settings.minimumScore)
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

		// HARD BOUNDARY: Don't create functions in known data regions
		const uint64_t DATA_REGION_START = 0x1127e638;
		if (funcAddr >= DATA_REGION_START)
		{
			m_logger->LogDebug("FunctionRecognizer: Skipping function at 0x%llx - in data region (>= 0x%llx)",
				(unsigned long long)funcAddr, (unsigned long long)DATA_REGION_START);
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

	// Load from view metadata
	// Format: JSON stored in "armv5.functionRecognizer.settings"
	std::string key = "armv5.functionRecognizer.settings";

	auto metadata = m_view->QueryMetadata(key);
	if (!metadata)
		return;

	// TODO: Parse JSON metadata into settings
	// For now, just use defaults
	m_logger->LogDebug("FunctionRecognizer: Would load settings from view metadata");
}

void FunctionRecognizer::SaveSettingsToView()
{
	if (!m_view || !m_view->GetObject())
		return;

	// Save to view metadata
	std::string key = "armv5.functionRecognizer.settings";

	// TODO: Serialize settings to JSON
	// For now, skip saving
	m_logger->LogDebug("FunctionRecognizer: Would save settings to view metadata");
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

}  // namespace Armv5Analysis
