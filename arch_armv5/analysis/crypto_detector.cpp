/*
 * Crypto Constant Detector Implementation
 */

#include "crypto_detector.h"

using namespace BinaryNinja;

namespace Armv5Analysis
{

// ============================================================================
// Known Crypto Constants
// ============================================================================

// AES S-box (256 bytes)
static const uint8_t AES_SBOX[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// AES Inverse S-box (256 bytes)
static const uint8_t AES_INV_SBOX[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// AES round constants (Rcon) - first 10 values used in AES-128
static const uint8_t AES_RCON[10] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// DES initial permutation table (first 32 bytes)
static const uint8_t DES_IP[32] = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8
};

// DES S-box 1 (64 bytes)
static const uint8_t DES_SBOX1[64] = {
	14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
	0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
	4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
	15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
};

// SHA-1 initial hash values (20 bytes)
static const uint8_t SHA1_H0[20] = {
	0x67, 0x45, 0x23, 0x01,  // H0
	0xef, 0xcd, 0xab, 0x89,  // H1
	0x98, 0xba, 0xdc, 0xfe,  // H2
	0x10, 0x32, 0x54, 0x76,  // H3
	0xc3, 0xd2, 0xe1, 0xf0   // H4
};

// SHA-1 K constants (80 32-bit values, first 20 bytes shown)
static const uint8_t SHA1_K[20] = {
	0x5a, 0x82, 0x79, 0x99,  // K0-19
	0x6e, 0xd9, 0xeb, 0xa1,  // K20-39
	0x8f, 0x1b, 0xbc, 0xdc,  // K40-59
	0xca, 0x62, 0xc1, 0xd6,  // K60-79
	0x5a, 0x82, 0x79, 0x99   // (repeated pattern check)
};

// SHA-256 initial hash values (32 bytes)
static const uint8_t SHA256_H0[32] = {
	0x6a, 0x09, 0xe6, 0x67,
	0xbb, 0x67, 0xae, 0x85,
	0x3c, 0x6e, 0xf3, 0x72,
	0xa5, 0x4f, 0xf5, 0x3a,
	0x51, 0x0e, 0x52, 0x7f,
	0x9b, 0x05, 0x68, 0x8c,
	0x1f, 0x83, 0xd9, 0xab,
	0x5b, 0xe0, 0xcd, 0x19
};

// SHA-256 K constants (first 64 bytes of 256)
static const uint8_t SHA256_K[64] = {
	0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
	0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5, 0xdb, 0xa5,
	0x39, 0x56, 0xc2, 0x5b, 0x59, 0xf1, 0x11, 0xf1,
	0x92, 0x3f, 0x82, 0xa4, 0xab, 0x1c, 0x5e, 0xd5,
	0xd8, 0x07, 0xaa, 0x98, 0x12, 0x83, 0x5b, 0x01,
	0x24, 0x31, 0x85, 0xbe, 0x55, 0x0c, 0x7d, 0xc3,
	0x72, 0xbe, 0x5d, 0x74, 0x80, 0xde, 0xb1, 0xfe,
	0x9b, 0xdc, 0x06, 0xa7, 0xc1, 0x9b, 0xf1, 0x74
};

// MD5 sine-derived constants T (first 64 bytes)
static const uint8_t MD5_T[64] = {
	0xd7, 0x6a, 0xa4, 0x78, 0xe8, 0xc7, 0xb7, 0x56,
	0x24, 0x20, 0x70, 0xdb, 0xc1, 0xbd, 0xce, 0xee,
	0xf5, 0x7c, 0x0f, 0xaf, 0x4d, 0x87, 0x98, 0x29,
	0x69, 0x89, 0x80, 0xe3, 0xfd, 0x46, 0x95, 0xd9,
	0xa4, 0xbe, 0xea, 0x0d, 0x4b, 0xde, 0xcf, 0xa9,
	0xf7, 0x53, 0x7e, 0xc4, 0xc7, 0xe3, 0x5f, 0x45,
	0xe2, 0x21, 0xe1, 0xbd, 0xc6, 0xeb, 0xee, 0xae,
	0xd6, 0x29, 0x04, 0x84, 0x00, 0x00, 0x00, 0x00
};

// MD5 initial values
static const uint8_t MD5_INIT[16] = {
	0x01, 0x23, 0x45, 0x67,  // A
	0x89, 0xab, 0xcd, 0xef,  // B
	0xfe, 0xdc, 0xba, 0x98,  // C
	0x76, 0x54, 0x32, 0x10   // D
};

// CRC32 polynomial table (first 32 bytes, IEEE polynomial)
static const uint8_t CRC32_TABLE[32] = {
	0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77,
	0x2c, 0x61, 0x0e, 0xee, 0xba, 0x51, 0x09, 0x99,
	0x19, 0xc4, 0x6d, 0x07, 0x8f, 0xf4, 0x6a, 0x70,
	0x35, 0xa5, 0x63, 0xe9, 0xa3, 0x95, 0x64, 0x9e
};

// XTEA delta constant
static const uint8_t XTEA_DELTA[4] = { 0x9e, 0x37, 0x79, 0xb9 };

// TEA delta constant (same value, different name)
static const uint8_t TEA_DELTA[4] = { 0x9e, 0x37, 0x79, 0xb9 };

// Blowfish P-array initial values (first 32 bytes)
static const uint8_t BLOWFISH_P[32] = {
	0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
	0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,
	0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0,
	0x08, 0x2e, 0xfa, 0x98, 0xec, 0x4e, 0x6c, 0x89
};

// Base64 alphabet
static const uint8_t BASE64_ALPHA[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

// ChaCha20/Salsa20 constant "expand 32-byte k"
static const uint8_t CHACHA_CONST[16] = {
	'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
	'2', '-', 'b', 'y', 't', 'e', ' ', 'k'
};

// RSA common public exponent
static const uint8_t RSA_E[4] = { 0x00, 0x01, 0x00, 0x01 };  // 65537

// ============================================================================
// Implementation
// ============================================================================

CryptoDetector::CryptoDetector(BinaryView* view) : m_view(view) {}

const char* CryptoDetector::AlgorithmToString(CryptoAlgorithm algo)
{
	switch (algo)
	{
	case CryptoAlgorithm::AES: return "AES";
	case CryptoAlgorithm::DES: return "DES";
	case CryptoAlgorithm::TripleDES: return "3DES";
	case CryptoAlgorithm::SHA1: return "SHA-1";
	case CryptoAlgorithm::SHA256: return "SHA-256";
	case CryptoAlgorithm::SHA512: return "SHA-512";
	case CryptoAlgorithm::MD5: return "MD5";
	case CryptoAlgorithm::MD4: return "MD4";
	case CryptoAlgorithm::CRC32: return "CRC32";
	case CryptoAlgorithm::CRC16: return "CRC16";
	case CryptoAlgorithm::XTEA: return "XTEA";
	case CryptoAlgorithm::TEA: return "TEA";
	case CryptoAlgorithm::Blowfish: return "Blowfish";
	case CryptoAlgorithm::RC4: return "RC4";
	case CryptoAlgorithm::RC5: return "RC5";
	case CryptoAlgorithm::RC6: return "RC6";
	case CryptoAlgorithm::ChaCha20: return "ChaCha20";
	case CryptoAlgorithm::Salsa20: return "Salsa20";
	case CryptoAlgorithm::Twofish: return "Twofish";
	case CryptoAlgorithm::Serpent: return "Serpent";
	case CryptoAlgorithm::Camellia: return "Camellia";
	case CryptoAlgorithm::GOST: return "GOST";
	case CryptoAlgorithm::IDEA: return "IDEA";
	case CryptoAlgorithm::SEED: return "SEED";
	case CryptoAlgorithm::ARIA: return "ARIA";
	case CryptoAlgorithm::SM4: return "SM4";
	case CryptoAlgorithm::Base64: return "Base64";
	case CryptoAlgorithm::HMAC: return "HMAC";
	case CryptoAlgorithm::PBKDF2: return "PBKDF2";
	case CryptoAlgorithm::RSA: return "RSA";
	case CryptoAlgorithm::DSA: return "DSA";
	case CryptoAlgorithm::ECC: return "ECC";
	default: return "Unknown";
	}
}

const char* CryptoDetector::ConstTypeToString(CryptoConstantType type)
{
	switch (type)
	{
	case CryptoConstantType::SBox: return "S-Box";
	case CryptoConstantType::InverseSBox: return "Inverse S-Box";
	case CryptoConstantType::RoundConstant: return "Round Constant";
	case CryptoConstantType::InitialValue: return "Initial Value";
	case CryptoConstantType::PermutationTable: return "Permutation Table";
	case CryptoConstantType::ExpansionTable: return "Expansion Table";
	case CryptoConstantType::CompressionTable: return "Compression Table";
	case CryptoConstantType::PolynomialTable: return "Polynomial Table";
	case CryptoConstantType::DeltaConstant: return "Delta Constant";
	case CryptoConstantType::MixColumnMatrix: return "MixColumn Matrix";
	case CryptoConstantType::PBox: return "P-Box";
	case CryptoConstantType::KeySchedule: return "Key Schedule";
	case CryptoConstantType::SineTable: return "Sine Table";
	case CryptoConstantType::MagicNumber: return "Magic Number";
	case CryptoConstantType::Prime: return "Prime";
	case CryptoConstantType::Generator: return "Generator";
	case CryptoConstantType::Curve: return "Elliptic Curve";
	case CryptoConstantType::Alphabet: return "Alphabet";
	default: return "Unknown";
	}
}

bool CryptoDetector::matchBytes(uint64_t addr, const uint8_t* pattern, size_t len, double& confidence)
{
	DataBuffer buf = m_view->ReadBuffer(addr, len);
	if (buf.GetLength() < len) return false;
	
	const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
	size_t matches = 0;
	for (size_t i = 0; i < len; i++)
	{
		if (data[i] == pattern[i]) matches++;
	}
	
	confidence = static_cast<double>(matches) / len;
	return matches >= m_settings.minMatchBytes && confidence >= m_settings.minConfidence;
}

bool CryptoDetector::matchBytesReversed(uint64_t addr, const uint8_t* pattern, size_t len, double& confidence)
{
	// Try matching with endian-swapped 32-bit words
	DataBuffer buf = m_view->ReadBuffer(addr, len);
	if (buf.GetLength() < len) return false;
	
	const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
	size_t matches = 0;
	
	// Try byte-reversed match (for little-endian storage of big-endian constants)
	for (size_t i = 0; i < len; i += 4)
	{
		if (i + 4 <= len)
		{
			// Compare reversed word
			if (data[i] == pattern[i+3] && data[i+1] == pattern[i+2] &&
				data[i+2] == pattern[i+1] && data[i+3] == pattern[i])
				matches += 4;
		}
	}
	
	confidence = static_cast<double>(matches) / len;
	return matches >= m_settings.minMatchBytes && confidence >= m_settings.minConfidence;
}

void CryptoDetector::addResult(uint64_t addr, CryptoAlgorithm algo, CryptoConstantType type,
	size_t size, double conf, const std::string& desc, bool partial)
{
	if (m_foundAddresses.find(addr) != m_foundAddresses.end()) return;
	m_foundAddresses.insert(addr);
	
	CryptoConstant c;
	c.address = addr;
	c.algorithm = algo;
	c.constType = type;
	c.size = size;
	c.confidence = conf;
	c.description = desc;
	c.isPartialMatch = partial;
	
	// Get xrefs
	for (const auto& ref : m_view->GetDataReferences(addr))
		c.xrefAddresses.push_back(ref);
	for (const auto& ref : m_view->GetCodeReferences(addr))
		c.xrefAddresses.push_back(ref.addr);
	
	m_results.push_back(c);
	m_stats.totalFound++;
	
	switch (algo)
	{
	case CryptoAlgorithm::AES: m_stats.aesFound++; break;
	case CryptoAlgorithm::DES: case CryptoAlgorithm::TripleDES: m_stats.desFound++; break;
	case CryptoAlgorithm::SHA1: case CryptoAlgorithm::SHA256: case CryptoAlgorithm::SHA512: m_stats.shaFound++; break;
	case CryptoAlgorithm::MD5: case CryptoAlgorithm::MD4: m_stats.md5Found++; break;
	case CryptoAlgorithm::CRC32: case CryptoAlgorithm::CRC16: m_stats.crcFound++; break;
	default: m_stats.otherFound++; break;
	}
}

void CryptoDetector::scanForAES()
{
	for (const auto& seg : m_view->GetSegments())
	{
		uint64_t start = seg->GetStart();
		uint64_t end = seg->GetEnd();
		
		for (uint64_t addr = start; addr + 256 <= end; addr += 4)
		{
			double conf;
			
			// Check for AES S-box (256 bytes)
			if (matchBytes(addr, AES_SBOX, 256, conf))
			{
				addResult(addr, CryptoAlgorithm::AES, CryptoConstantType::SBox,
					256, conf, "AES S-box (SubBytes lookup table)");
				addr += 256;
				continue;
			}
			
			// Check for AES Inverse S-box
			if (matchBytes(addr, AES_INV_SBOX, 256, conf))
			{
				addResult(addr, CryptoAlgorithm::AES, CryptoConstantType::InverseSBox,
					256, conf, "AES Inverse S-box (InvSubBytes)");
				addr += 256;
				continue;
			}
			
			// Check for partial matches (common in optimized implementations)
			if (m_settings.allowPartialMatches)
			{
				if (matchBytes(addr, AES_SBOX, 64, conf) && conf >= 0.9)
				{
					addResult(addr, CryptoAlgorithm::AES, CryptoConstantType::SBox,
						64, conf, "AES S-box (partial, first 64 bytes)", true);
				}
			}
		}
		
		// Check for Rcon
		for (uint64_t addr = start; addr + 10 <= end; addr += 1)
		{
			double conf;
			if (matchBytes(addr, AES_RCON, 10, conf))
			{
				addResult(addr, CryptoAlgorithm::AES, CryptoConstantType::RoundConstant,
					10, conf, "AES round constants (Rcon)");
			}
		}
	}
}

void CryptoDetector::scanForDES()
{
	for (const auto& seg : m_view->GetSegments())
	{
		uint64_t start = seg->GetStart();
		uint64_t end = seg->GetEnd();
		
		for (uint64_t addr = start; addr + 64 <= end; addr += 4)
		{
			double conf;
			
			// Check for DES S-box 1
			if (matchBytes(addr, DES_SBOX1, 64, conf))
			{
				addResult(addr, CryptoAlgorithm::DES, CryptoConstantType::SBox,
					64, conf, "DES S-box 1");
				continue;
			}
			
			// Check for DES initial permutation
			if (matchBytes(addr, DES_IP, 32, conf))
			{
				addResult(addr, CryptoAlgorithm::DES, CryptoConstantType::PermutationTable,
					32, conf, "DES initial permutation table (IP)");
			}
		}
	}
}

void CryptoDetector::scanForSHA()
{
	for (const auto& seg : m_view->GetSegments())
	{
		uint64_t start = seg->GetStart();
		uint64_t end = seg->GetEnd();
		
		for (uint64_t addr = start; addr + 32 <= end; addr += 4)
		{
			double conf;
			
			// SHA-1 initial values
			if (matchBytes(addr, SHA1_H0, 20, conf) || matchBytesReversed(addr, SHA1_H0, 20, conf))
			{
				addResult(addr, CryptoAlgorithm::SHA1, CryptoConstantType::InitialValue,
					20, conf, "SHA-1 initial hash values (H0-H4)");
			}
			
			// SHA-256 initial values
			if (matchBytes(addr, SHA256_H0, 32, conf) || matchBytesReversed(addr, SHA256_H0, 32, conf))
			{
				addResult(addr, CryptoAlgorithm::SHA256, CryptoConstantType::InitialValue,
					32, conf, "SHA-256 initial hash values (H0-H7)");
			}
			
			// SHA-256 K constants
			if (matchBytes(addr, SHA256_K, 64, conf) || matchBytesReversed(addr, SHA256_K, 64, conf))
			{
				addResult(addr, CryptoAlgorithm::SHA256, CryptoConstantType::RoundConstant,
					64, conf, "SHA-256 K constants (first 16 of 64)");
			}
		}
	}
}

void CryptoDetector::scanForMD5()
{
	for (const auto& seg : m_view->GetSegments())
	{
		uint64_t start = seg->GetStart();
		uint64_t end = seg->GetEnd();
		
		for (uint64_t addr = start; addr + 64 <= end; addr += 4)
		{
			double conf;
			
			// MD5 T constants (sine-derived)
			if (matchBytes(addr, MD5_T, 64, conf) || matchBytesReversed(addr, MD5_T, 64, conf))
			{
				addResult(addr, CryptoAlgorithm::MD5, CryptoConstantType::SineTable,
					64, conf, "MD5 T constants (sine-derived, first 16)");
			}
			
			// MD5 initial values
			if (matchBytes(addr, MD5_INIT, 16, conf) || matchBytesReversed(addr, MD5_INIT, 16, conf))
			{
				addResult(addr, CryptoAlgorithm::MD5, CryptoConstantType::InitialValue,
					16, conf, "MD5 initial values (A, B, C, D)");
			}
		}
	}
}

void CryptoDetector::scanForCRC()
{
	for (const auto& seg : m_view->GetSegments())
	{
		uint64_t start = seg->GetStart();
		uint64_t end = seg->GetEnd();
		
		for (uint64_t addr = start; addr + 32 <= end; addr += 4)
		{
			double conf;
			
			// CRC32 polynomial table
			if (matchBytes(addr, CRC32_TABLE, 32, conf) || matchBytesReversed(addr, CRC32_TABLE, 32, conf))
			{
				addResult(addr, CryptoAlgorithm::CRC32, CryptoConstantType::PolynomialTable,
					32, conf, "CRC32 lookup table (IEEE polynomial, first 8 entries)");
			}
		}
	}
}

void CryptoDetector::scanForTEA()
{
	for (const auto& seg : m_view->GetSegments())
	{
		uint64_t start = seg->GetStart();
		uint64_t end = seg->GetEnd();
		
		for (uint64_t addr = start; addr + 4 <= end; addr += 1)
		{
			double conf;
			
			// TEA/XTEA delta constant (0x9E3779B9)
			if (matchBytes(addr, TEA_DELTA, 4, conf) || matchBytesReversed(addr, TEA_DELTA, 4, conf))
			{
				addResult(addr, CryptoAlgorithm::XTEA, CryptoConstantType::DeltaConstant,
					4, conf, "TEA/XTEA delta constant (golden ratio derived)");
			}
		}
	}
}

void CryptoDetector::scanForBlowfish()
{
	for (const auto& seg : m_view->GetSegments())
	{
		uint64_t start = seg->GetStart();
		uint64_t end = seg->GetEnd();
		
		for (uint64_t addr = start; addr + 32 <= end; addr += 4)
		{
			double conf;
			
			// Blowfish P-array
			if (matchBytes(addr, BLOWFISH_P, 32, conf) || matchBytesReversed(addr, BLOWFISH_P, 32, conf))
			{
				addResult(addr, CryptoAlgorithm::Blowfish, CryptoConstantType::PBox,
					32, conf, "Blowfish P-array initial values (first 8)");
			}
		}
	}
}

void CryptoDetector::scanForRC4()
{
	// RC4 is stateful, not much to detect except the 256-byte state initialization
	// Look for sequential 0-255 byte sequences
	for (const auto& seg : m_view->GetSegments())
	{
		uint64_t start = seg->GetStart();
		uint64_t end = seg->GetEnd();
		
		for (uint64_t addr = start; addr + 256 <= end; addr += 4)
		{
			DataBuffer buf = m_view->ReadBuffer(addr, 256);
			if (buf.GetLength() < 256) continue;
			
			const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
			
			// Check if it's a sequential 0-255 table (identity permutation)
			bool isIdentity = true;
			for (int i = 0; i < 256 && isIdentity; i++)
			{
				if (data[i] != i) isIdentity = false;
			}
			
			if (isIdentity)
			{
				addResult(addr, CryptoAlgorithm::RC4, CryptoConstantType::KeySchedule,
					256, 1.0, "RC4 identity permutation (S-box before KSA)");
				addr += 256;
			}
		}
	}
}

void CryptoDetector::scanForChaCha()
{
	for (const auto& seg : m_view->GetSegments())
	{
		uint64_t start = seg->GetStart();
		uint64_t end = seg->GetEnd();
		
		for (uint64_t addr = start; addr + 16 <= end; addr += 1)
		{
			double conf;
			
			// ChaCha20/Salsa20 "expand 32-byte k" constant
			if (matchBytes(addr, CHACHA_CONST, 16, conf))
			{
				addResult(addr, CryptoAlgorithm::ChaCha20, CryptoConstantType::MagicNumber,
					16, conf, "ChaCha20/Salsa20 sigma constant");
			}
		}
	}
}

void CryptoDetector::scanForBase64()
{
	for (const auto& seg : m_view->GetSegments())
	{
		uint64_t start = seg->GetStart();
		uint64_t end = seg->GetEnd();
		
		for (uint64_t addr = start; addr + 64 <= end; addr += 1)
		{
			double conf;
			
			// Base64 alphabet
			if (matchBytes(addr, BASE64_ALPHA, 64, conf))
			{
				addResult(addr, CryptoAlgorithm::Base64, CryptoConstantType::Alphabet,
					64, conf, "Base64 encoding alphabet");
			}
		}
	}
}

void CryptoDetector::scanForRSA()
{
	for (const auto& seg : m_view->GetSegments())
	{
		uint64_t start = seg->GetStart();
		uint64_t end = seg->GetEnd();
		
		for (uint64_t addr = start; addr + 4 <= end; addr += 1)
		{
			double conf;
			
			// Common RSA public exponent 65537
			if (matchBytes(addr, RSA_E, 4, conf) || matchBytesReversed(addr, RSA_E, 4, conf))
			{
				// Only report if it looks like it's in a key structure
				// (has refs or is followed by a large value)
				auto refs = m_view->GetCodeReferences(addr);
				if (!refs.empty())
				{
					addResult(addr, CryptoAlgorithm::RSA, CryptoConstantType::Prime,
						4, conf, "RSA public exponent (65537)");
				}
			}
		}
	}
}

std::vector<CryptoConstant> CryptoDetector::Detect(const CryptoDetectionSettings& settings)
{
	m_settings = settings;
	m_results.clear();
	m_foundAddresses.clear();
	m_stats = CryptoDetectionStats();
	
	if (settings.detectAES) scanForAES();
	if (settings.detectDES) scanForDES();
	if (settings.detectSHA) scanForSHA();
	if (settings.detectMD5) scanForMD5();
	if (settings.detectCRC) scanForCRC();
	if (settings.detectTEA) scanForTEA();
	if (settings.detectBlowfish) scanForBlowfish();
	if (settings.detectRC) scanForRC4();
	if (settings.detectChaCha) scanForChaCha();
	if (settings.detectBase64) scanForBase64();
	if (settings.detectRSA) scanForRSA();
	
	// Sort by address
	std::sort(m_results.begin(), m_results.end(),
		[](const CryptoConstant& a, const CryptoConstant& b) { return a.address < b.address; });
	
	return m_results;
}

}
