/*
 * ARMv5 Function Recognizer Service
 *
 * Unified interface for function detection that can be used by both:
 * - The workflow (automatic scanning during analysis)
 * - The UI (interactive tuning without reloading)
 *
 * This service wraps the FunctionDetector class and provides:
 * - Settings persistence via BinaryView metadata
 * - Progress reporting and cancellation
 * - Integration with FirmwareScanPlan for atomic changes
 *
 * NOTE: Named "FunctionRecognizer" rather than "FirmwareFunctionDetector"
 * because this can be used for any ARMv5 binary, not just firmware.
 */

#pragma once

#include "binaryninjaapi.h"
#include "function_detector.h"

#include <functional>
#include <memory>
#include <mutex>
#include <atomic>

namespace Armv5Analysis
{

/**
 * Progress callback for recognition operations
 * Returns false to request cancellation
 */
using RecognitionProgressCallback = std::function<bool(size_t current, size_t total, const std::string& status)>;

/**
 * Result from a recognition run
 */
struct RecognitionResult
{
	std::vector<FunctionCandidate> candidates;
	FunctionDetector::DetectionStats stats;
	bool completed = false;
	bool cancelled = false;
	std::string errorMessage;

	// Breakdown by confidence
	size_t highConfidenceCount = 0;
	size_t mediumConfidenceCount = 0;
	size_t lowConfidenceCount = 0;

	// Time taken
	double durationSeconds = 0.0;
};

/**
 * Unified function recognition service for ARMv5 analysis
 */
class FunctionRecognizer
{
public:
	explicit FunctionRecognizer(BinaryNinja::Ref<BinaryNinja::BinaryView> view);
	~FunctionRecognizer();

	/**
	 * Run recognition with current settings
	 * Does NOT apply results - call ApplyResults() separately
	 */
	RecognitionResult RunRecognition();

	/**
	 * Run recognition with custom settings (does not persist settings)
	 */
	RecognitionResult RunRecognition(const FunctionDetectionSettings& settings);

	/**
	 * Apply recognition results to the BinaryView
	 * @param results The recognition results to apply
	 * @param minScore Minimum score threshold for applying candidates
	 * @return Number of functions created
	 */
	size_t ApplyResults(const RecognitionResult& results, double minScore = 0.5);

	/**
	 * Run recognition and apply results in one call
	 * This is what the workflow uses
	 * @param minScore Minimum score threshold
	 * @return Number of functions created
	 */
	size_t RecognizeAndApply(double minScore = 0.5);

	/**
	 * Get candidates as addresses for FirmwareScanPlan integration
	 * @param results The recognition results
	 * @param minScore Minimum score threshold
	 * @return Vector of (address, isThumb) pairs
	 */
	std::vector<std::pair<uint64_t, bool>> GetCandidateAddresses(
		const RecognitionResult& results, double minScore = 0.5) const;

	/**
	 * Get/set the current recognition settings
	 */
	const FunctionDetectionSettings& GetSettings() const { return m_settings; }
	void SetSettings(const FunctionDetectionSettings& settings);

	/**
	 * Load settings from view metadata
	 */
	void LoadSettingsFromView();

	/**
	 * Save settings to view metadata
	 */
	void SaveSettingsToView();

	/**
	 * Preset configurations
	 */
	void UseDefaultSettings();
	void UseAggressiveSettings();
	void UseConservativeSettings();
	void UsePrologueOnlySettings();
	void UseCallTargetOnlySettings();

	/**
	 * Progress and cancellation
	 */
	void SetProgressCallback(RecognitionProgressCallback callback) { m_progressCallback = callback; }
	void RequestCancellation() { m_cancellationRequested = true; }
	bool IsCancellationRequested() const { return m_cancellationRequested; }
	void ClearCancellation() { m_cancellationRequested = false; }

	/**
	 * Get the last recognition result (for UI inspection)
	 */
	const RecognitionResult& GetLastResult() const { return m_lastResult; }

	/**
	 * Check if a recognition is currently running
	 */
	bool IsRunning() const { return m_isRunning; }

	/**
	 * Get the underlying detector (for advanced use)
	 */
	FunctionDetector* GetDetector() { return m_detector.get(); }

	/**
	 * Static helper: Get list of settings that can be tuned
	 */
	struct TunableParameter
	{
		std::string name;
		std::string description;
		std::string category;
		enum { Bool, Double, Int } type;
		double minValue;
		double maxValue;
		double defaultValue;
	};
	static std::vector<TunableParameter> GetTunableParameters();

private:
	bool ShouldCancel() const;
	void UpdateProgress(size_t current, size_t total, const std::string& status);

	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	std::unique_ptr<FunctionDetector> m_detector;
	FunctionDetectionSettings m_settings;
	RecognitionResult m_lastResult;

	RecognitionProgressCallback m_progressCallback;
	std::atomic<bool> m_cancellationRequested{false};
	std::atomic<bool> m_isRunning{false};
	mutable std::mutex m_mutex;

	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;
};

/**
 * Get or create the recognizer for a view
 * Recognizers are cached per-view
 */
FunctionRecognizer* GetRecognizerForView(BinaryNinja::BinaryView* view);

/**
 * Release the recognizer for a view (called during view cleanup)
 */
void ReleaseRecognizerForView(BinaryNinja::BinaryView* view);

}  // namespace Armv5Analysis
