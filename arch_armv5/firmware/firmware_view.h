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
#include <unordered_set>

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
		uint64_t m_instanceId;
		uint64_t m_fileSessionId;
		uintptr_t m_viewPtr;

		virtual uint64_t PerformGetEntryPoint() const override;
		virtual bool PerformIsExecutable() const override { return true; }
		virtual BNEndianness PerformGetDefaultEndianness() const override;
		virtual bool PerformIsRelocatable() const override { return false; }
		virtual size_t PerformGetAddressSize() const override;

	public:
		Armv5FirmwareView(BinaryView* data, bool parseOnly = false);
		virtual ~Armv5FirmwareView();
		virtual bool Init() override;
		// Takes Ref<> passed through from workflow callback - do NOT create new Ref<> from this
		void RunFirmwareWorkflowScans(Ref<BinaryView> viewRef);
	bool TryBeginWorkflowScans();
	const std::set<uint64_t>& GetSeededFunctions() const;
	const std::set<uint64_t>& GetSeededUserFunctions() const;
	const std::vector<FirmwareScanDataDefine>& GetSeededDataDefines() const;
	const std::vector<BinaryNinja::Ref<BinaryNinja::Symbol>>& GetSeededSymbols() const;
	uint64_t GetInstanceId() const { return m_instanceId; }
	uint64_t GetFileSessionId() const { return m_fileSessionId; }
	bool IsParseOnly() const { return m_parseOnly; }
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
	uint64_t GetInstanceIdFromView(const BinaryView* view);
	bool IsFirmwareViewClosing(const BinaryView* view);
	bool IsFirmwareViewClosingById(uint64_t instanceId);
	bool IsFirmwareViewScanCancelled(const BinaryView* view);
	bool IsFirmwareViewScanCancelledById(uint64_t instanceId);
	void SetFirmwareViewScanCancelled(uint64_t instanceId, bool cancelled);
	Armv5FirmwareView* GetFirmwareViewForInstanceId(uint64_t instanceId);
	Armv5FirmwareView* GetFirmwareViewForFileSessionId(uint64_t fileSessionId);

	// Lifecycle helpers
	bool IsFirmwareViewAliveById(uint64_t instanceId);

	// Snapshot helpers for tracking post-scan function changes
	void StoreFirmwareFunctionSnapshot(uint64_t instanceId, const std::unordered_set<uint64_t>& snapshot);
	std::unordered_set<uint64_t> LoadFirmwareFunctionSnapshot(uint64_t instanceId);
	void ClearFirmwareFunctionSnapshot(uint64_t instanceId);

	// Removed-functions blacklist: prevents BN's call-following from re-creating
	// functions that cleanup already removed. Scoped per firmware view instance.
	void AddRemovedFunctionAddress(uint64_t instanceId, uint64_t addr);
	bool IsRemovedFunctionAddress(uint64_t instanceId, uint64_t addr);
	void ClearRemovedFunctions(uint64_t instanceId);
}
