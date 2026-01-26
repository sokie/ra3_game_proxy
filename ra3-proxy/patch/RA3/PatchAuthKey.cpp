// PatchAuthKey.cpp : Defines the PatchAuthKey class, which handles the patching of auth certificate check.
#include "../../Framework.h"
#include "PatchAuthKey.hpp"

PatchAuthKey::PatchAuthKey()
{
	// Get the base address of the current module
	HANDLE hModule = GetModuleHandle(nullptr);
	baseAddress_ = reinterpret_cast<DWORD>(hModule);
}

BOOL PatchAuthKey::Patch() const
{
	BOOST_LOG_NAMED_SCOPE("AuthKeyPatch")

	BOOST_LOG_TRIVIAL(info) << "Patching auth certificate check...";

	// mov eax, 0x01 - makes the function return 1 (success)
	static constexpr BYTE new_auth_certificate_check_return_value[] = {
		0xB8, 0x01, 0x00, 0x00, 0x00  // mov eax, 0x01
	};

	// Addresses to patch (relative to module base would be offset, but these appear to be absolute)
	constexpr DWORD auth_check_addresses[] = {
		0xB36CBFu,
		0x9444BFu
	};

	int patchedCount = 0;

	for (DWORD address : auth_check_addresses)
	{
		BYTE* patchAddress = reinterpret_cast<BYTE*>(address);

		DWORD oldProtect;
		// Change page protection to allow writing
		if (!VirtualProtect(patchAddress, sizeof(new_auth_certificate_check_return_value), PAGE_EXECUTE_READWRITE, &oldProtect))
		{
			BOOST_LOG_TRIVIAL(error) << "Failed to change memory protection at address: 0x" << std::hex << address;
			continue;
		}

		// Write the patch bytes
		memcpy(patchAddress, new_auth_certificate_check_return_value, sizeof(new_auth_certificate_check_return_value));

		// Restore original protection
		VirtualProtect(patchAddress, sizeof(new_auth_certificate_check_return_value), oldProtect, &oldProtect);

		BOOST_LOG_TRIVIAL(info) << "Successfully patched auth certificate check at address: 0x" << std::hex << address;
		patchedCount++;
	}

	if (patchedCount == 2)
	{
		BOOST_LOG_TRIVIAL(info) << "Auth certificate check patching complete!";
		return TRUE;
	}
	else
	{
		BOOST_LOG_TRIVIAL(error) << "Failed to patch all auth certificate check addresses. Patched: " << patchedCount << "/2";
		return FALSE;
	}
}
