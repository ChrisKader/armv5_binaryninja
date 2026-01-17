/*
 * Crypto Constant Detector
 *
 * Detects cryptographic constants in firmware binaries:
 * - AES S-boxes and round constants
 * - DES S-boxes and permutation tables
 * - SHA-1/256/512 initial values and K constants
 * - MD5 sine table and initial values
 * - CRC32 polynomial tables
 * - XTEA/TEA delta constants
 * - RSA/DSA primes (common moduli)
 * - RC4 state initialization patterns
 * - ChaCha/Salsa quarter-round patterns
 */

#pragma once

#include "binaryninjaapi.h"
#include <cstdint>
#include <string>
#include <vector>
#include <set>

namespace Armv5Analysis
{

enum class CryptoAlgorithm
{
	Unknown,
	AES,
	DES,
	TripleDES,
	SHA1,
	SHA256,
	SHA512,
	MD5,
	MD4,
	CRC32,
	CRC16,
	XTEA,
	TEA,
	Blowfish,
	RC4,
	RC5,
	RC6,
	ChaCha20,
	Salsa20,
	Twofish,
	Serpent,
	Camellia,
	GOST,
	IDEA,
	SEED,
	ARIA,
	SM4,
	Base64,
	HMAC,
	PBKDF2,
	RSA,
	DSA,
	ECC
};

enum class CryptoConstantType
{
	SBox,
	InverseSBox,
	RoundConstant,
	InitialValue,
	PermutationTable,
	ExpansionTable,
	CompressionTable,
	PolynomialTable,
	DeltaConstant,
	MixColumnMatrix,
	PBox,
	KeySchedule,
	SineTable,
	MagicNumber,
	Prime,
	Generator,
	Curve,
	Alphabet,
	Unknown
};

struct CryptoConstant
{
	uint64_t address;
	CryptoAlgorithm algorithm;
	CryptoConstantType constType;
	size_t size;
	double confidence;
	std::string description;
	std::vector<uint64_t> xrefAddresses;
	bool isPartialMatch;
};

struct CryptoDetectionSettings
{
	bool detectAES = true;
	bool detectDES = true;
	bool detectSHA = true;
	bool detectMD5 = true;
	bool detectCRC = true;
	bool detectTEA = true;
	bool detectBlowfish = true;
	bool detectRC = true;
	bool detectChaCha = true;
	bool detectBase64 = true;
	bool detectRSA = true;
	double minConfidence = 0.7;
	size_t minMatchBytes = 32;
	bool allowPartialMatches = true;
};

struct CryptoDetectionStats
{
	size_t totalFound = 0;
	size_t aesFound = 0;
	size_t desFound = 0;
	size_t shaFound = 0;
	size_t md5Found = 0;
	size_t crcFound = 0;
	size_t otherFound = 0;
};

class CryptoDetector
{
public:
	explicit CryptoDetector(BinaryNinja::BinaryView* view);
	
	std::vector<CryptoConstant> Detect(const CryptoDetectionSettings& settings = CryptoDetectionSettings());
	const CryptoDetectionStats& GetStats() const { return m_stats; }
	
	static const char* AlgorithmToString(CryptoAlgorithm algo);
	static const char* ConstTypeToString(CryptoConstantType type);

private:
	void scanForAES();
	void scanForDES();
	void scanForSHA();
	void scanForMD5();
	void scanForCRC();
	void scanForTEA();
	void scanForBlowfish();
	void scanForRC4();
	void scanForChaCha();
	void scanForBase64();
	void scanForRSA();
	
	bool matchBytes(uint64_t addr, const uint8_t* pattern, size_t len, double& confidence);
	bool matchBytesReversed(uint64_t addr, const uint8_t* pattern, size_t len, double& confidence);
	void addResult(uint64_t addr, CryptoAlgorithm algo, CryptoConstantType type, 
		size_t size, double conf, const std::string& desc, bool partial = false);
	
	BinaryNinja::BinaryView* m_view;
	CryptoDetectionSettings m_settings;
	CryptoDetectionStats m_stats;
	std::vector<CryptoConstant> m_results;
	std::set<uint64_t> m_foundAddresses;
};

}
