/*
 * ARMv5 Platform Recognizers
 */

#include <cstring>
#include <inttypes.h>

#include "binaryninjaapi.h"
#include "platforms/platform_recognizers.h"

using namespace BinaryNinja;

static Ref<Logger> GetPlatformLogger()
{
  static Ref<Logger> logger = LogRegistry::CreateLogger("ARMv5.Platform");
  return logger;
}

/*
 * Parse ARM .ARM.attributes to get Tag_CPU_arch for an ELF binary.
 *
 * Returns -1 if not found or on parse error, otherwise Tag_CPU_arch value.
 */
static int ParseArmAttributesCpuArch(BinaryView* view)
{
  if (!view)
    return -1;

  /* Get the parent (raw) view to access non-loaded sections */
  Ref<BinaryView> parent = view->GetParentView();
  if (!parent)
  {
    /* Try to get raw view through the file object */
    Ref<FileMetadata> file = view->GetFile();
    if (file)
      parent = file->GetViewOfType("Raw");
  }

  if (!parent)
    return -1;

  /* Read ELF header from raw view */
  uint8_t ehdr[52];  /* 32-bit ELF header size */
  if (parent->Read(ehdr, 0, 52) != 52)
    return -1;

  /* Verify ELF magic and 32-bit */
  if (ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F')
    return -1;
  if (ehdr[4] != 1)  /* EI_CLASS: must be 32-bit */
    return -1;

  bool littleEndian = (ehdr[5] == 1);  /* EI_DATA */

  /* Parse section header table info from ELF header */
  auto readU16 = [littleEndian](const uint8_t* p) -> uint16_t {
    return littleEndian ? (p[0] | (p[1] << 8)) : ((p[0] << 8) | p[1]);
  };
  auto readU32 = [littleEndian](const uint8_t* p) -> uint32_t {
    return littleEndian ?
      (p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24)) :
      ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
  };

  uint32_t e_shoff = readU32(&ehdr[0x20]);      /* Section header table offset */
  uint16_t e_shentsize = readU16(&ehdr[0x2e]);  /* Section header entry size */
  uint16_t e_shnum = readU16(&ehdr[0x30]);      /* Number of section headers */
  uint16_t e_shstrndx = readU16(&ehdr[0x32]);   /* Section name string table index */

  if (e_shoff == 0 || e_shnum == 0 || e_shstrndx >= e_shnum)
    return -1;
  if (e_shentsize < 40)  /* Minimum section header size */
    return -1;

  /* Read section name string table header */
  uint8_t strtab_shdr[40];
  if (parent->Read(strtab_shdr, e_shoff + e_shstrndx * e_shentsize, 40) != 40)
    return -1;

  uint32_t strtab_offset = readU32(&strtab_shdr[0x10]);
  uint32_t strtab_size = readU32(&strtab_shdr[0x14]);

  if (strtab_size > 0x10000)  /* Sanity check */
    strtab_size = 0x10000;

  /* Read string table */
  DataBuffer strtab = parent->ReadBuffer(strtab_offset, strtab_size);
  if (strtab.GetLength() < strtab_size)
    return -1;

  /* Scan section headers for .ARM.attributes */
  for (uint16_t i = 0; i < e_shnum; i++)
  {
    uint8_t shdr[40];
    if (parent->Read(shdr, e_shoff + i * e_shentsize, 40) != 40)
      continue;

    uint32_t sh_name = readU32(&shdr[0x00]);
    uint32_t sh_offset = readU32(&shdr[0x10]);
    uint32_t sh_size = readU32(&shdr[0x14]);

    if (sh_name >= strtab.GetLength())
      continue;

    /* Get section name from string table */
    const char* name = (const char*)strtab.GetData() + sh_name;
    if (strcmp(name, ".ARM.attributes") != 0)
      continue;

    /* Found .ARM.attributes section - read and parse it */
    if (sh_size < 5 || sh_size > 4096)
      return -1;

    DataBuffer attrBuf = parent->ReadBuffer(sh_offset, sh_size);
    if (attrBuf.GetLength() < sh_size)
      return -1;

    const uint8_t* data = (const uint8_t*)attrBuf.GetData();
    size_t len = attrBuf.GetLength();
    size_t pos = 0;

    /* Check format version */
    if (data[pos++] != 'A')
      return -1;

    /* Parse subsections */
    while (pos + 4 <= len)  /* Need 4 bytes for length field */
    {
      /* Subsection length (always little-endian in attributes) */
      uint32_t subLen = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
      pos += 4;

      if (subLen < 5 || pos + subLen - 4 > len)
        break;

      size_t subEnd = pos + subLen - 4;

      /* Vendor name (null-terminated string) */
      size_t vendorStart = pos;
      while (pos < subEnd && data[pos] != 0)
        pos++;
      if (pos >= subEnd)
        break;
      pos++;  /* Skip null terminator */

      /* Check if this is the "aeabi" vendor (standard ARM attributes) */
      bool isAeabi = (strcmp((const char*)&data[vendorStart], "aeabi") == 0);

      if (!isAeabi)
      {
        pos = subEnd;
        continue;
      }

      /* Parse sub-subsections within aeabi */
      while (pos + 5 <= subEnd)  /* Need at least 1 byte tag + 4 bytes size */
      {
        uint8_t tag = data[pos++];

        /* Sub-subsection size (little-endian) */
        if (pos + 4 > subEnd)
          break;
        uint32_t ssSize = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
        pos += 4;

        if (ssSize < 5 || pos + ssSize - 5 > subEnd)
          break;

        size_t ssEnd = pos + ssSize - 5;

        /* Only process Tag_File (1) - file-scope attributes */
        if (tag != 1)
        {
          pos = ssEnd;
          continue;
        }

        /* Parse attribute tag-value pairs */
        while (pos < ssEnd)
        {
          /* Read ULEB128 tag */
          uint32_t attrTag = 0;
          uint32_t shift = 0;
          while (pos < ssEnd)
          {
            uint8_t b = data[pos++];
            attrTag |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0)
              break;
            shift += 7;
          }

          if (pos >= ssEnd)
            break;

          /* Determine if value is ULEB128 or NTBS based on tag */
          /* Tags 4, 5, 32, 65, 67 are strings; most others are ULEB128 */
          bool isString = (attrTag == 4 || attrTag == 5 || attrTag == 32 ||
                           attrTag == 65 || attrTag == 67);

          if (isString)
          {
            /* Skip null-terminated string */
            while (pos < ssEnd && data[pos] != 0)
              pos++;
            if (pos < ssEnd)
              pos++;  /* Skip null */
          }
          else
          {
            /* Read ULEB128 value */
            uint32_t attrVal = 0;
            shift = 0;
            while (pos < ssEnd)
            {
              uint8_t b = data[pos++];
              attrVal |= (b & 0x7F) << shift;
              if ((b & 0x80) == 0)
                break;
              shift += 7;
            }

            /* Tag 6 is Tag_CPU_arch */
            if (attrTag == 6)
              return (int)attrVal;
          }
        }

        pos = ssEnd;
      }

      pos = subEnd;
    }

    /* Found section but couldn't parse Tag_CPU_arch */
    return -1;
  }

  return -1;
}

/*
 * ELF ARM Platform Recognizer for ARMv5
 *
 * This callback is invoked by the ELF loader to determine which platform/architecture
 * to use for ARM binaries (EM_ARM = 0x28). It parses .ARM.attributes to detect ARMv5.
 *
 * Detection strategy:
 * 1. Parse .ARM.attributes section for Tag_CPU_arch (authoritative)
 * 2. Fall back to e_flags EABI version heuristics for older binaries
 *
 * Returns: ARMv5 platform if detected, nullptr to fall through to ARMv7
 */
/*
 * ELF ARM Platform Recognizer for ARMv5.
 *
 * Detection strategy:
 * 1) Parse .ARM.attributes Tag_CPU_arch (authoritative when present).
 * 2) Fall back to e_flags EABI heuristics for older binaries.
 */
static Ref<Platform> ElfArmv5PlatformRecognize(BinaryView* view, Metadata* metadata)
{
  if (!view)
    return nullptr;

  /* First, try to parse .ARM.attributes for authoritative CPU arch */
  int cpuArch = ParseArmAttributesCpuArch(view);
  if (cpuArch >= 0)
  {
    /*
     * Tag_CPU_arch values for ARMv5 family:
     *   3 = ARMv5T
     *   4 = ARMv5TE
     *   5 = ARMv5TEJ
     *
     * Also claim older architectures (pre-v4, v4, v4T) since ARMv5 is a superset.
     * ARMv6+ (values 6-14) should fall through to ARMv7.
     */
    if (cpuArch >= 0 && cpuArch <= 5)
    {
      const char* archNames[] = {"Pre-v4", "ARMv4", "ARMv4T", "ARMv5T", "ARMv5TE", "ARMv5TEJ"};
      if (auto pLog = GetPlatformLogger())
        pLog->LogInfo("ELF .ARM.attributes Tag_CPU_arch=%d (%s): using armv5 architecture",
                      cpuArch, archNames[cpuArch]);
      return Platform::GetByName("arm");
    }

    /* ARMv6+ detected, let ARMv7 handle it */
    return nullptr;
  }

  /* Fall back to e_flags heuristics for binaries without .ARM.attributes */
  if (!metadata)
    return nullptr;

  /* Check ELF OS/ABI - we only handle Linux/SYSV (0) and GNU (3) */
  Ref<Metadata> abiMetadata = metadata->Get("EI_OSABI");
  if (abiMetadata && abiMetadata->IsUnsignedInteger())
  {
    uint64_t abi = abiMetadata->GetUnsignedInteger();
    if (abi != 0 && abi != 3)
      return nullptr;
  }

  /* Check e_flags for ARM EABI version hints */
  Ref<Metadata> flagsMetadata = metadata->Get("e_flags");
  if (!flagsMetadata || !flagsMetadata->IsUnsignedInteger())
    return nullptr;

  uint64_t flags = flagsMetadata->GetUnsignedInteger();

  /*
   * ARM EABI e_flags:
   * - EF_ARM_EABIMASK (0xFF000000): EABI version
   * - EF_ARM_EABI_VER1 (0x01000000): EABI v1 - typically ARMv4T/ARMv5
   * - EF_ARM_EABI_VER2 (0x02000000): EABI v2 - typically ARMv5
   *
   * Note: EABI version alone doesn't indicate CPU arch; modern toolchains
   * use EABI v5 for all ARM variants. The .ARM.attributes section is
   * authoritative, but older binaries may not have it.
   */
  #define EF_ARM_EABIMASK 0xFF000000
  #define EF_ARM_EABI_VER1 0x01000000
  #define EF_ARM_EABI_VER2 0x02000000

  uint64_t eabiVersion = flags & EF_ARM_EABIMASK;

  /* Claim binaries with older EABI versions as ARMv5 */
  if (eabiVersion == EF_ARM_EABI_VER1 || eabiVersion == EF_ARM_EABI_VER2)
  {
    if (auto pLog = GetPlatformLogger())
      pLog->LogInfo("ELF e_flags 0x%08" PRIx64 " indicates early ARM EABI: using armv5 architecture", flags);
    return Platform::GetByName("arm");
  }

  return nullptr;
}

/*
 * Raw Binary Platform Recognizer for ARMv5
 *
 * This callback is invoked by the Mapped view type for raw binaries to determine
 * which platform/architecture to use. It inspects the raw bytes to detect ARM patterns.
 *
 * Detection strategy:
 * 1. Check for ARM vector table pattern at offset 0 (reset vector typically LDR PC or B instruction)
 * 2. Look for common ARM instruction patterns
 * 3. Use heuristics based on instruction density
 *
 * The BinaryView passed is the Raw view, allowing us to read bytes directly.
 *
 * Returns: ARMv5 platform if detected, nullptr to fall through to other architectures
 */
/*
 * Raw Binary Platform Recognizer for ARMv5.
 *
 * Detects ARM vector table patterns in the first 32 bytes.
 */
static Ref<Platform> RawArmv5PlatformRecognize(BinaryView* view, Metadata* metadata)
{
  if (!view)
    return nullptr;

  /* Read first 32 bytes to check for ARM vector table patterns */
  uint8_t buffer[32];
  size_t bytesRead = view->Read(buffer, 0, sizeof(buffer));
  if (bytesRead < 32)
    return nullptr;

  /*
   * Check for ARM vector table pattern (little-endian):
   * ARM processors typically start with a vector table at address 0 containing
   * LDR PC, [PC, #offset] (0xE59FF0xx) or B instructions (0xEAxxxxxx).
   */
  int armPatternCount = 0;

  for (int i = 0; i < 8; i++)
  {
    uint32_t word = buffer[i*4] | (buffer[i*4+1] << 8) | (buffer[i*4+2] << 16) | (buffer[i*4+3] << 24);

    /* Check for LDR PC, [PC, #imm] or branch instructions */
    if ((word & 0xFFFFF000) == 0xE59FF000 || /* LDR PC, [PC, #imm] */
        (word & 0xFF000000) == 0xEA000000 || /* B <offset> */
        (word & 0x0F000000) == 0x0A000000)   /* Bcc <offset> */
    {
      armPatternCount++;
    }
  }

  /* If we see at least 4 vector table entries that look like ARM code, claim it */
  if (armPatternCount >= 4)
  {
    if (auto pLog = GetPlatformLogger())
      pLog->LogInfo("Raw binary detected as ARM: vector table pattern found (%d/8 entries), claiming as armv5", armPatternCount);
    return Platform::GetByName("arm");
  }

  return nullptr;
}

void RegisterArmv5PlatformRecognizers(BNEndianness endian)
{
  // Guard against double registration
  static bool s_leRegistered = false;
  static bool s_beRegistered = false;

  bool& registered = (endian == LittleEndian) ? s_leRegistered : s_beRegistered;
  if (registered)
    return;
  registered = true;

  Ref<BinaryViewType> elf = BinaryViewType::GetByName("ELF");
  if (elf)
    elf->RegisterPlatformRecognizer(0x28, endian, ElfArmv5PlatformRecognize);

  Ref<BinaryViewType> raw = BinaryViewType::GetByName("Raw");
  if (raw)
    raw->RegisterPlatformRecognizer(0, endian, RawArmv5PlatformRecognize);

  Ref<BinaryViewType> mapped = BinaryViewType::GetByName("Mapped");
  if (mapped)
    mapped->RegisterPlatformRecognizer(0, endian, RawArmv5PlatformRecognize);
}
