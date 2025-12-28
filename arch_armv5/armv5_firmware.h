/*
 * ARMv5 Firmware BinaryViewType
 *
 * Custom BinaryViewType for bare metal ARM firmware detection.
 * Detects ARM binaries by looking for vector table patterns at offset 0.
 */

#pragma once

#include "binaryninjaapi.h"
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

		virtual uint64_t PerformGetEntryPoint() const override;
		virtual bool PerformIsExecutable() const override { return true; }
		virtual BNEndianness PerformGetDefaultEndianness() const override;
		virtual bool PerformIsRelocatable() const override { return false; }
		virtual size_t PerformGetAddressSize() const override;

	public:
		Armv5FirmwareView(BinaryView* data, bool parseOnly = false);
		virtual ~Armv5FirmwareView();
		virtual bool Init() override;
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
}
