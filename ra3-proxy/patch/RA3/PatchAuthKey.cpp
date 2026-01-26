// PatchAuthKey.cpp : Defines the PatchAuthKey class, which handles the patching of auth certificate check.
#include "../../Framework.h"
#include "../../util.h"
#include "PatchAuthKey.hpp"
#include "PatchSSL.hpp"  // For PatternByte

// Forward declarations from PatchSSL.cpp
extern std::vector<PatternByte> ParsePattern(const std::string& pattern_str);
extern std::vector<std::byte*> FindAllPatterns(std::byte* start_address, size_t search_length, const std::vector<PatternByte>& pattern);

PatchAuthKey::PatchAuthKey()
{
	// Get the handle of the current module
	HANDLE hModule = GetModuleHandle(nullptr);
	baseAddress_ = reinterpret_cast<DWORD>(hModule);

	// Get the size and entry point offset of the module
	size_ = GetModuleSize(hModule);
	offset_ = GetEntryPointOffset(hModule);
	entryPoint_ = baseAddress_ + offset_;
}

BOOL PatchAuthKey::Patch() const
{
	BOOST_LOG_NAMED_SCOPE("AuthKeyPatch")

	// Pattern for already patched executable:
	// F7 D8 B8 01 00 00 00 5E 81 C4 ?? ?? 00 00 C3
	// (neg eax; mov eax, 1; pop esi; add esp, imm32; ret)
	std::string patched_pattern_string = "F7 D8 B8 01 00 00 00 5E 81 C4 ?? ?? 00 00 C3";

	BOOST_LOG_TRIVIAL(debug) << "Searching for pattern of already patched executable: \"" << patched_pattern_string << "\"";

	std::vector<PatternByte> parsed_pattern = ParsePattern(patched_pattern_string);
	if (parsed_pattern.empty()) {
		BOOST_LOG_TRIVIAL(error) << "Failed to parse patched pattern.";
		return FALSE;
	}

	std::byte* ptr = reinterpret_cast<std::byte*>(entryPoint_);

	std::vector<std::byte*> patched_addresses = FindAllPatterns(ptr, size_, parsed_pattern);
	if (!patched_addresses.empty()) {
		BOOST_LOG_TRIVIAL(info) << "Auth certificate check is already patched! Found " << patched_addresses.size() << " patched location(s).";
		for (const auto& addr : patched_addresses) {
			BOOST_LOG_TRIVIAL(debug) << "  - Patched at: 0x" << std::hex << reinterpret_cast<DWORD>(addr);
		}
		return TRUE;
	}

	// Pattern for unpatched executable:
	// F7 D8 1B C0 83 C0 01 5E 81 C4 ?? ?? 00 00 C3
	// (neg eax; sbb eax, eax; add eax, 1; pop esi; add esp, imm32; ret)
	// Patch point is at offset 2 (where "1B C0 83 C0 01" starts)
	std::string unpatched_pattern_string = "F7 D8 1B C0 83 C0 01 5E 81 C4 ?? ?? 00 00 C3";

	BOOST_LOG_TRIVIAL(info) << "Searching for auth certificate check pattern: \"" << unpatched_pattern_string << "\"";

	parsed_pattern = ParsePattern(unpatched_pattern_string);
	if (parsed_pattern.empty()) {
		BOOST_LOG_TRIVIAL(error) << "Failed to parse unpatched pattern.";
		return FALSE;
	}

	std::vector<std::byte*> found_addresses = FindAllPatterns(ptr, size_, parsed_pattern);
	if (found_addresses.empty()) {
		BOOST_LOG_TRIVIAL(error) << "Failed to find auth certificate check code. Pattern not found!";
		return FALSE;
	}

	BOOST_LOG_TRIVIAL(info) << "Found " << found_addresses.size() << " auth certificate check location(s) to patch.";

	// mov eax, 0x01 - makes the function return 1 (success)
	// We replace "1B C0 83 C0 01" (5 bytes) with "B8 01 00 00 00" (5 bytes)
	static constexpr BYTE new_auth_certificate_check_return_value[] = {
		0xB8, 0x01, 0x00, 0x00, 0x00  // mov eax, 0x01
	};

	int patchedCount = 0;
	for (std::byte* found_address : found_addresses) {
		// Patch point is at offset 2 from pattern start (after "F7 D8")
		BYTE* patchAddress = reinterpret_cast<BYTE*>(found_address + 2);

		DWORD oldProtect;
		if (!VirtualProtect(patchAddress, sizeof(new_auth_certificate_check_return_value), PAGE_EXECUTE_READWRITE, &oldProtect)) {
			BOOST_LOG_TRIVIAL(error) << "Failed to change memory protection at: 0x" << std::hex << reinterpret_cast<DWORD>(patchAddress);
			continue;
		}

		memcpy(patchAddress, new_auth_certificate_check_return_value, sizeof(new_auth_certificate_check_return_value));

		VirtualProtect(patchAddress, sizeof(new_auth_certificate_check_return_value), oldProtect, &oldProtect);

		BOOST_LOG_TRIVIAL(info) << "Patched auth certificate check at: 0x" << std::hex << reinterpret_cast<DWORD>(patchAddress);
		patchedCount++;
	}

	if (patchedCount > 0) {
		BOOST_LOG_TRIVIAL(info) << "Successfully patched " << std::dec << patchedCount << "/" << found_addresses.size() << " auth certificate check location(s)!";
		return TRUE;
	}
	else {
		BOOST_LOG_TRIVIAL(error) << "Failed to patch any auth certificate check locations.";
		return FALSE;
	}
}
