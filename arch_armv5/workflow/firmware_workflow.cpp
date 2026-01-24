/*
 * ARMv5 Firmware Workflow Registration
 *
 * ============================================================================
 * WHY USE A WORKFLOW?
 * ============================================================================
 *
 * Binary Ninja workflows provide a structured way to run analysis passes.
 * For firmware analysis, we need to run our custom scans (prologue detection,
 * call target discovery, etc.) at the right point in the analysis pipeline.
 *
 * ALTERNATIVES CONSIDERED:
 * ------------------------
 * 1. BinaryViewType callbacks (Init/PerformLoad):
 *    - Runs too early, before initial analysis completes
 *    - Can't leverage existing function discovery
 *
 * 2. Notification callbacks (OnAnalysisComplete):
 *    - Runs after ALL analysis, may be too late
 *    - No control over ordering with other passes
 *
 * 3. Workflow activities (CHOSEN):
 *    - Runs at a specific point in the pipeline
 *    - Can depend on and trigger other activities
 *    - Proper integration with Binary Ninja's analysis system
 *
 * ============================================================================
 * WORKFLOW STRUCTURE
 * ============================================================================
 *
 * We clone the "core.module.metaAnalysis" workflow and add our activity:
 *
 *   core.module.extendedAnalysis   (built-in)
 *           |
 *           v
 *   analysis.armv5.firmwareScan    <-- OUR ACTIVITY
 *           |
 *           v
 *   core.module.update             (built-in, our downstream dependency)
 *
 * This ensures our scans run after extended analysis (which may have found
 * some functions) but before the final update pass (which finalizes state).
 *
 * ============================================================================
 * LIFETIME SAFETY - CRITICAL
 * ============================================================================
 *
 * Workflow callbacks receive an AnalysisContext. We MUST follow these rules:
 *
 * 1. NEVER store Ref<BinaryView> across callback invocations
 *    - The callback may be invoked multiple times
 *    - Storing extends the view's lifetime beyond user expectations
 *
 * 2. ALWAYS re-acquire the view from AnalysisContext each time
 *    - auto view = analysisContext->GetBinaryView();
 *    - This gets the current, valid reference
 *
 * 3. CHECK for closing before doing work
 *    - IsFirmwareViewClosing(view.GetPtr()) checks if user closed the view
 *    - Without this check, we might operate on a dying view
 *
 * 4. HANDLE exceptions gracefully
 *    - Uncaught exceptions in workflow callbacks can crash Binary Ninja
 *    - Wrap activity code in try/catch
 *
 * REFERENCE: binaryninja-api/workflow.cpp, arch/armv7/arch_armv7.cpp
 */

#include "firmware_workflow.h"
#include "firmware/firmware_view.h"
#include <algorithm>
#include <exception>

using namespace BinaryNinja;

/**
 * Early workflow activity to type BN-detected strings BEFORE function discovery.
 *
 * This runs after initial analysis (when strings are found) but before
 * extendedAnalysis (when functions are discovered). By typing strings early,
 * we prevent false function detection at string addresses.
 *
 * @param analysisContext The analysis context from Binary Ninja.
 */
static void RunArmv5StringTypingWorkflow(const Ref<AnalysisContext>& analysisContext)
{
	if (!analysisContext)
		return;

	auto view = analysisContext->GetBinaryView();
	if (!view || !view->GetObject())
		return;

	if (IsFirmwareViewClosing(view.GetPtr()))
		return;

	auto logger = LogRegistry::CreateLogger("BinaryView.ARMv5FirmwareView");

	try
	{
		auto bnStrings = view->GetStrings();

		// Sort strings by address - BN doesn't guarantee order
		std::sort(bnStrings.begin(), bnStrings.end(),
			[](const BNStringReference& a, const BNStringReference& b) {
				return a.start < b.start;
			});

		size_t typed = 0;
		size_t skippedShort = 0;
		size_t skippedAlreadyTyped = 0;
		size_t skippedNoString = 0;
		size_t skippedInsidePrevious = 0;
		size_t skippedGarbage = 0;

		// Track end of last typed string to skip BN's "split" strings
		uint64_t lastTypedEnd = 0;

		for (const auto& str : bnStrings)
		{
			// Debug: log strings near the problematic address for diagnosis
			const bool debugThis = (str.start >= 0x10b46c00 && str.start <= 0x10b47000);
			if (debugThis && logger)
				logger->LogDebug("StringTyping: BN detected string at 0x%llx len=%zu type=%d, lastTypedEnd=0x%llx",
					(unsigned long long)str.start, str.length, (int)str.type, (unsigned long long)lastTypedEnd);

			// Skip if this string starts inside a previously typed string
			// (BN may report multiple "strings" that are actually one contiguous string)
			if (str.start < lastTypedEnd)
			{
				if (debugThis && logger)
					logger->LogDebug("StringTyping: Skipping 0x%llx - inside previous (ends at 0x%llx)",
						(unsigned long long)str.start, (unsigned long long)lastTypedEnd);
				skippedInsidePrevious++;
				continue;
			}

			// Skip very short strings
			if (str.length < 4)
			{
				skippedShort++;
				continue;
			}

			// Skip if already has a proper string type defined
			DataVariable existingVar;
			if (view->GetDataVariableAtAddress(str.start, existingVar) && existingVar.type.GetValue())
			{
				auto existingType = existingVar.type.GetValue();
				if (existingType->IsArray())
				{
					auto elemType = existingType->GetChildType().GetValue();
					if (elemType && (elemType->IsInteger() || elemType->IsWideChar()))
					{
						skippedAlreadyTyped++;
						continue;
					}
				}
			}

			// Determine element size based on string type
			// For firmware, skip UTF-16/32 strings - they're almost never legitimate
			// and BN often misdetects binary data as wide strings
			if (str.type == Utf16String || str.type == Utf32String)
			{
				skippedNoString++;
				continue;
			}
			size_t elementSize = 1;  // Only process ASCII/UTF-8

			// Scan for actual null terminator ourselves
			// Use 4KB buffer - much faster than 64KB and covers almost all strings
			// Very long strings (>4KB) are rare in firmware and can be truncated
			const size_t maxScanBytes = 4096;

			DataBuffer buffer = view->ReadBuffer(str.start, maxScanBytes);
			if (buffer.GetLength() < elementSize)
			{
				skippedNoString++;
				continue;
			}

			const uint8_t* data = static_cast<const uint8_t*>(buffer.GetData());
			size_t bufLen = buffer.GetLength();
			size_t nullPos = 0;
			bool foundNull = false;
			bool hitInvalidChar = false;

			// Helper to check if a byte is a valid string character
			// Printable ASCII (0x20-0x7E) plus common control chars (tab, newline, carriage return)
			auto isValidStringByte = [](uint8_t b) -> bool {
				if (b >= 0x20 && b <= 0x7E)
					return true;  // Printable ASCII
				if (b == '\t' || b == '\n' || b == '\r')
					return true;  // Common whitespace
				return false;
			};

			// Helper to check if a string looks like real text vs random ASCII garbage
			// Returns true if the string appears to be meaningful
			auto isLikelyRealString = [](const uint8_t* data, size_t len) -> bool {
				if (len < 4)
					return false;

				// Count vowels, consonants, digits, punctuation, spaces
				size_t vowels = 0;
				size_t consonants = 0;
				size_t digits = 0;
				size_t spaces = 0;
				size_t punctuation = 0;
				size_t consecutiveConsonants = 0;
				size_t maxConsecutiveConsonants = 0;
				size_t uppercase = 0;
				size_t lowercase = 0;

				auto isVowel = [](uint8_t c) -> bool {
					c = (c >= 'A' && c <= 'Z') ? (c + 32) : c;  // tolower
					return c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u';
				};

				auto isConsonant = [](uint8_t c) -> bool {
					if (c >= 'A' && c <= 'Z') c += 32;
					if (c < 'a' || c > 'z') return false;
					return !(c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u');
				};

				for (size_t i = 0; i < len; i++)
				{
					uint8_t c = data[i];
					if (c == 0) break;

					if (isVowel(c))
					{
						vowels++;
						consecutiveConsonants = 0;
						if (c >= 'A' && c <= 'Z') uppercase++;
						else if (c >= 'a' && c <= 'z') lowercase++;
					}
					else if (isConsonant(c))
					{
						consonants++;
						consecutiveConsonants++;
						if (consecutiveConsonants > maxConsecutiveConsonants)
							maxConsecutiveConsonants = consecutiveConsonants;
						if (c >= 'A' && c <= 'Z') uppercase++;
						else if (c >= 'a' && c <= 'z') lowercase++;
					}
					else if (c >= '0' && c <= '9')
					{
						digits++;
						consecutiveConsonants = 0;
					}
					else if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
					{
						spaces++;
						consecutiveConsonants = 0;
					}
					else
					{
						punctuation++;
						consecutiveConsonants = 0;
					}
				}

				size_t letters = vowels + consonants;

				// Heuristic 1: If it has spaces, it's more likely real text
				// (multi-word strings are usually meaningful)
				if (spaces > 0 && letters > 4)
					return true;

				// Heuristic 2: Strings with digits mixed with letters are often meaningful
				// (version strings, error codes, addresses)
				if (digits > 0 && letters > 2)
					return true;

				// Heuristic 3: Strings with punctuation like '.' '/' '_' ':' are often paths/identifiers
				if (punctuation > 0 && letters > 2)
					return true;

				// Heuristic 4: Check vowel ratio for letter-only strings
				// Real English text has ~38% vowels, allow 15-60% range
				if (letters >= 4)
				{
					double vowelRatio = (double)vowels / letters;
					if (vowelRatio < 0.10 || vowelRatio > 0.70)
						return false;  // Too few or too many vowels

					// Heuristic 5: Max consecutive consonants
					// English rarely exceeds 4 (e.g., "strengths" has 3)
					// Be lenient for short strings, stricter for long ones
					size_t maxAllowed = (len < 8) ? 5 : 4;
					if (maxConsecutiveConsonants > maxAllowed)
						return false;
				}

				// Heuristic 6: Very long all-lowercase with no spaces is suspicious
				// unless it has camelCase or numbers
				if (len > 20 && spaces == 0 && digits == 0 && punctuation == 0)
				{
					// Check for camelCase (mix of upper and lower)
					if (uppercase == 0 || lowercase == 0)
						return false;  // All one case, no spaces, very long = suspicious
				}

				return true;
			};

			// Search for null terminator, validating characters along the way
			for (size_t pos = 0; pos + elementSize <= bufLen; pos += elementSize)
			{
				// Check for null terminator
				bool isNull = true;
				for (size_t i = 0; i < elementSize; i++)
				{
					if (data[pos + i] != 0)
					{
						isNull = false;
						break;
					}
				}
				if (isNull)
				{
					nullPos = pos;
					foundNull = true;
					break;
				}

				// For ASCII strings, validate that character is printable
				// For UTF-16/32, we're more lenient (just check for null)
				if (elementSize == 1)
				{
					if (!isValidStringByte(data[pos]))
					{
						// Hit a non-printable byte - this is where the string really ends
						// or it's not a valid string at all
						hitInvalidChar = true;
						if (debugThis && logger)
							logger->LogDebug("StringTyping: Hit invalid byte 0x%02x at offset %zu for 0x%llx",
								data[pos], pos, (unsigned long long)str.start);
						break;
					}
				}
			}

			// If we hit an invalid character before finding null, skip this string
			if (hitInvalidChar)
			{
				if (debugThis && logger)
					logger->LogDebug("StringTyping: Skipping 0x%llx - contains non-printable characters",
						(unsigned long long)str.start);
				skippedNoString++;
				continue;
			}

			if (!foundNull)
			{
				if (debugThis && logger)
					logger->LogDebug("StringTyping: No null terminator found within %zu bytes for 0x%llx",
						maxScanBytes, (unsigned long long)str.start);
				skippedNoString++;
				continue;
			}

			if (debugThis && logger)
				logger->LogDebug("StringTyping: Found null at offset %zu for 0x%llx",
					nullPos, (unsigned long long)str.start);

			// Check if the string looks like real text vs random ASCII garbage
			// Only apply this check for ASCII strings (not UTF-16/32)
			if (elementSize == 1 && !isLikelyRealString(data, nullPos))
			{
				if (debugThis && logger)
					logger->LogDebug("StringTyping: Skipping 0x%llx - looks like random ASCII garbage",
						(unsigned long long)str.start);
				skippedGarbage++;
				continue;
			}

			// Create appropriate type based on encoding
			Ref<Type> elementType;
			switch (str.type)
			{
			case Utf16String:
				elementType = Type::WideCharType(2);
				break;
			case Utf32String:
				elementType = Type::WideCharType(4);
				break;
			default:  // ASCII, UTF-8
				elementType = Type::IntegerType(1, true);  // char
				break;
			}

			// nullPos is the offset of the null terminator
			size_t stringBytes = nullPos;  // Bytes before null
			size_t arrayLength = (stringBytes / elementSize) + 1;  // +1 for null terminator
			Ref<Type> stringType = Type::ArrayType(elementType, arrayLength);

			view->DefineUserDataVariable(str.start, stringType);
			typed++;

			// Track the end of this string so we skip BN's "split" strings
			lastTypedEnd = str.start + stringBytes + elementSize;  // Include null terminator

			if (debugThis && logger)
				logger->LogDebug("StringTyping: Typed 0x%llx as char[%zu], new lastTypedEnd=0x%llx",
					(unsigned long long)str.start, arrayLength, (unsigned long long)lastTypedEnd);
		}

		if (logger)
		{
			logger->LogInfo("Early string typing: %zu typed, %zu short, %zu already typed, %zu no string (invalid chars), %zu garbage, %zu inside previous",
				typed, skippedShort, skippedAlreadyTyped, skippedNoString, skippedGarbage, skippedInsidePrevious);
			// Log validation stats to confirm validation is active
			logger->LogInfo("String typing validation: skippedNoString includes strings with non-printable bytes, skippedGarbage includes nonsense patterns");
		}
	}
	catch (std::exception& e)
	{
		if (logger)
			logger->LogError("Early string typing failed: %s", e.what());
	}
}

/**
 * Workflow activity callback for ARMv5 firmware analysis.
 *
 * This function is called by Binary Ninja's workflow system when our
 * activity is eligible to run. It performs the firmware scan passes.
 *
 * SAFETY NOTES:
 * - Re-acquires view from context (never cached)
 * - Checks for view closing before work
 * - Catches exceptions to prevent crashes
 *
 * @param analysisContext The analysis context from Binary Ninja.
 */
static void RunArmv5FirmwareWorkflow(const Ref<AnalysisContext>& analysisContext)
{
	/*
	 * Guard 1: Validate analysis context
	 * This should never be null, but defensive programming is good.
	 */
	if (!analysisContext)
		return;

	/*
	 * Guard 2: Re-acquire the BinaryView from context
	 *
	 * IMPORTANT: We get a fresh Ref<BinaryView> each callback invocation.
	 * This is the correct pattern - never store the view across callbacks.
	 */
	auto view = analysisContext->GetBinaryView();
	if (!view)
		return;
	if (!view->GetObject())
		return;

	/*
	 * Guard 3: Check if the view is closing
	 *
	 * The user may have closed the view while waiting for this activity.
	 * IsFirmwareViewClosing() checks our instance tracking system.
	 */
	if (IsFirmwareViewClosing(view.GetPtr()))
		return;

	/*
	 * Run the firmware scans with exception handling.
	 *
	 * Uncaught exceptions in workflow callbacks can crash Binary Ninja.
	 * We catch and log them to prevent data loss.
	 */
	try
	{
		RunArmv5FirmwareWorkflowScans(view);
	}
	catch (std::exception& e)
	{
		LogErrorForException(e, "Armv5 Firmware Workflow failed with uncaught exception: %s", e.what());
	}
}

/**
 * Register the ARMv5 firmware workflow.
 *
 * Called once at plugin initialization. Creates and registers our
 * custom workflow by cloning and extending the metaAnalysis workflow.
 *
 * WORKFLOW REGISTRATION PROCESS:
 * 1. Get the base metaAnalysis workflow
 * 2. Clone it (so we don't modify the original)
 * 3. Register our activity with eligibility predicates
 * 4. Insert our activity at the right point in the pipeline
 * 5. Register the modified workflow
 */
void BinaryNinja::RegisterArmv5FirmwareWorkflow()
{
	// Guard against double registration
	static bool s_registered = false;
	if (s_registered)
		return;
	s_registered = true;

	/*
	 * Get the base workflow to extend.
	 * "core.module.metaAnalysis" is the standard module analysis workflow.
	 */
	Ref<Workflow> metaWorkflow = Workflow::Get("core.module.metaAnalysis");
	if (!metaWorkflow)
		return;

	/*
	 * Clone the workflow so we don't modify the shared original.
	 * Our clone will have our activity added.
	 */
	Ref<Workflow> firmwareWorkflow = metaWorkflow->Clone();
	if (!firmwareWorkflow)
		return;

	/*
	 * Register our activity with JSON configuration.
	 *
	 * CONFIGURATION FIELDS:
	 * - title: Human-readable name shown in UI
	 * - name: Unique identifier for the activity
	 * - role: "action" means it performs analysis work
	 * - description: Tooltip/documentation text
	 * - eligibility:
	 *   - runOnce: Only run once per analysis (not on incremental updates)
	 *   - predicates: Conditions for running (only on ARMv5 Firmware views)
	 * - dependencies:
	 *   - downstream: Activities that should run after us
	 */
	Ref<Activity> activity = firmwareWorkflow->RegisterActivity(R"~({
		"title": "ARMv5 Firmware Scan",
		"name": "analysis.armv5.firmwareScan",
		"role": "action",
		"description": "Run ARMv5 firmware discovery passes (prologue/call/pointer/orphan scans and cleanup).",
		"eligibility": {
			"runOnce": false,
			"auto": {},
			"predicates": [
				{
					"type": "viewType",
					"value": ["ARMv5 Firmware"],
					"operator": "in"
				}
			]
		},
		"dependencies": {
			"downstream": ["core.module.loadDebugInfo"]
		}
	})~", &RunArmv5FirmwareWorkflow);
	if (!activity)
		return;

	/*
	 * Register early string typing activity.
	 *
	 * This activity runs BEFORE extendedAnalysis to type BN-detected strings
	 * as proper char[]/wchar[] arrays. This prevents function detection from
	 * creating false functions at string addresses.
	 */
	Ref<Activity> stringTypingActivity = firmwareWorkflow->RegisterActivity(R"~({
		"title": "ARMv5 String Typing",
		"name": "analysis.armv5.typeStrings",
		"role": "action",
		"description": "Type BN-detected strings before function discovery to prevent false positives.",
		"eligibility": {
			"runOnce": true,
			"auto": {},
			"predicates": [
				{
					"type": "viewType",
					"value": ["ARMv5 Firmware"],
					"operator": "in"
				}
			]
		}
	})~", &RunArmv5StringTypingWorkflow);
	if (!stringTypingActivity)
		return;

	/*
	 * WORKFLOW ORDER for ARMv5 Firmware:
	 *
	 * 1. core.module.stringsAnalysis     (BN finds strings)
	 * 2. analysis.armv5.typeStrings      (We type strings as char[])
	 * 3. ... BN's analysis activities ...
	 * 4. analysis.armv5.firmwareScan     (Our scans run AFTER BN settles)
	 * 5. core.module.loadDebugInfo       (BN loads debug info)
	 *
	 * Running our scans LATE avoids cascading function creation where:
	 * we add function → BN finds call targets → BN adds more → repeat
	 */

	// Insert string typing AFTER stringsAnalysis (early - blocks bad functions)
	std::vector<std::string> stringTypingInsert = { "analysis.armv5.typeStrings" };
	firmwareWorkflow->InsertAfter("core.module.stringsAnalysis", stringTypingInsert);

	// Insert firmware scans LATE - before loadDebugInfo but after most BN analysis
	std::vector<std::string> firmwareScanInsert = { "analysis.armv5.firmwareScan" };
	firmwareWorkflow->Insert("core.module.loadDebugInfo", firmwareScanInsert);

	/*
	 * Register the workflow.
	 *
	 * Binary Ninja will use this workflow for views that match our
	 * eligibility predicates (ARMv5 Firmware type).
	 */
	Workflow::RegisterWorkflow(firmwareWorkflow);
}
