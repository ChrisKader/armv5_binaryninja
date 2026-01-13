/*
 * ARMv5 Firmware BinaryViewType
 *
 * Custom BinaryViewType for bare metal ARM firmware detection.
 * Detects ARM binaries by looking for vector table patterns at offset 0.
 */

#pragma once

#include "binaryninjaapi.h"
#include "firmware_scan_types.h"
#include <set>

namespace BinaryNinja
{
	class Armv5FirmwareView: public BinaryView
	{
		bool m_parseOnly;
		uint64_t m_entryPoint;
		BNEndianness m_endian;
		size_t m_addressSize;
	Ref<Architecture> m_arch;
	Ref<Platform> m_plat;
	Ref<Logger> m_logger;
	bool m_postAnalysisScansDone;
	std::set<uint64_t> m_seededFunctions;
	std::set<uint64_t> m_seededUserFunctions;
	std::vector<FirmwareScanDataDefine> m_seededDataDefines;
	std::vector<BinaryNinja::Ref<BinaryNinja::Symbol>> m_seededSymbols;
	uint64_t m_viewId;

		virtual uint64_t PerformGetEntryPoint() const override;
		virtual bool PerformIsExecutable() const override { return true; }
		virtual BNEndianness PerformGetDefaultEndianness() const override;
		virtual bool PerformIsRelocatable() const override { return false; }
		virtual size_t PerformGetAddressSize() const override;

	public:
		Armv5FirmwareView(BinaryView* data, bool parseOnly = false);
		virtual ~Armv5FirmwareView();
		virtual bool Init() override;
		void RunFirmwareWorkflowScans();
	bool TryBeginWorkflowScans();
	const std::set<uint64_t>& GetSeededFunctions() const;
	const std::set<uint64_t>& GetSeededUserFunctions() const;
	const std::vector<FirmwareScanDataDefine>& GetSeededDataDefines() const;
	const std::vector<BinaryNinja::Ref<BinaryNinja::Symbol>>& GetSeededSymbols() const;
	};

	class Armv5FirmwareViewType: public BinaryViewType
	{
		Ref<Logger> m_logger;
	public:
		Armv5FirmwareViewType();
		virtual Ref<BinaryView> Create(BinaryView* data) override;
		virtual Ref<BinaryView> Parse(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual bool IsForceLoadable() override;
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
	};

	void InitArmv5FirmwareViewType();
	void RunArmv5FirmwareWorkflowScans(const Ref<BinaryView>& view);
	bool IsFirmwareViewClosing(const BinaryView* view);
	bool IsFirmwareViewClosingById(uint64_t viewId);
	bool IsFirmwareViewScanCancelled(const BinaryView* view);
	bool IsFirmwareViewScanCancelledById(uint64_t viewId);
	void SetFirmwareViewScanCancelled(uint64_t viewId, bool cancelled);
	Armv5FirmwareView* GetFirmwareViewForSessionId(uint64_t viewId);
}
