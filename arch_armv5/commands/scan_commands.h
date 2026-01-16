/*
 * ARMv5 Scan Commands
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * This file declares plugin commands for running firmware analysis scans.
 * Commands are accessible via:
 *   - Command Palette (Ctrl/Cmd + P)
 *   - Right-click menu (Plugins > ARMv5 > ...)
 *   - Scripting API
 *
 * Each command can run individual scans or all scans together. This allows
 * users to re-run analysis after modifying settings or to run specific
 * passes on demand.
 *
 * ============================================================================
 * USAGE
 * ============================================================================
 *
 * 1. Open a binary with ARMv5 architecture
 * 2. Use Command Palette (Ctrl+P) and type "ARMv5"
 * 3. Select the desired scan command
 *
 * Or via right-click menu:
 *   Right-click > Plugins > ARMv5 > Run All Firmware Scans
 *
 * ============================================================================
 */

#pragma once

namespace Armv5Commands
{

/**
 * Register all ARMv5 plugin commands with Binary Ninja.
 *
 * Called during plugin initialization. Registers commands for:
 *   - Run All Firmware Scans
 *   - Run Prologue Scan
 *   - Run Call Target Scan
 *   - Run Pointer Target Scan
 *   - Run Orphan Code Scan
 *   - Run Cleanup Pass
 *   - Detect RTOS
 */
void RegisterScanCommands();

}
