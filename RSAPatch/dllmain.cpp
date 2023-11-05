#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <fstream>
#include <filesystem>
#include <string>
#include "exports.h"
#include "Utils.h"

#pragma comment(lib, "ntdll.lib")

typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation
} SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;
EXTERN_C NTSTATUS __stdcall NtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS InformationClass, PVOID InformationBuffer, ULONG InformationBufferSize, PULONG ResultLength);
EXTERN_C NTSTATUS __stdcall NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG  NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
EXTERN_C NTSTATUS __stdcall NtPulseEvent(HANDLE EventHandle, PULONG PreviousState);

void DisableVMP()
{
	// restore hook at NtProtectVirtualMemory
	auto ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) return;

	bool linux = GetProcAddress(ntdll, "wine_get_version") != nullptr;
	void* routine = linux ? (void*)NtPulseEvent : (void*)NtQuerySection;
	DWORD old;
	VirtualProtect(NtProtectVirtualMemory, 1, PAGE_EXECUTE_READWRITE, &old);
	*(uintptr_t*)NtProtectVirtualMemory = *(uintptr_t*)routine & ~(0xFFui64 << 32) | (uintptr_t)(*(uint32_t*)((uintptr_t)routine + 4) - 1) << 32;
	VirtualProtect(NtProtectVirtualMemory, 1, old, &old);
}

void DisableLogReport()
{
	char szProcessPath[MAX_PATH]{};
	GetModuleFileNameA(nullptr, szProcessPath, MAX_PATH);

	auto path = std::filesystem::path(szProcessPath);
	auto ProcessName = path.filename().string();
	ProcessName = ProcessName.substr(0, ProcessName.find_last_of('.'));

	auto Astrolabe = path.parent_path() / (ProcessName + "_Data\\Plugins\\Astrolabe.dll");
	auto MiHoYoMTRSDK = path.parent_path() / (ProcessName + "_Data\\Plugins\\MiHoYoMTRSDK.dll");

	// open exclusive access to these two dlls
	// so they cannot be loaded
	HANDLE hFile = CreateFileA(Astrolabe.string().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	hFile = CreateFileA(MiHoYoMTRSDK.string().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

DWORD __stdcall Thread(LPVOID p)
{
	Utils::AttachConsole();

	Utils::ConsolePrint("anime encryption patcher by xeondev\n\n\n");
	Utils::ConsolePrint("waiting for anime software startup\n");

	auto pid = GetCurrentProcessId();
	while (true)
	{
		// use EnumWindows to pinpoint the target window
		// as there could be other window with the same class name
		EnumWindows([](HWND hwnd, LPARAM lParam)->BOOL __stdcall {

			DWORD wndpid = 0;
			GetWindowThreadProcessId(hwnd, &wndpid);

			char szWindowClass[256]{};
			GetClassNameA(hwnd, szWindowClass, 256);
			if (!strcmp(szWindowClass, "UnityWndClass") && wndpid == *(DWORD*)lParam)
			{
				*(DWORD*)lParam = 0;
				return FALSE;
			}

			return TRUE;

		}, (LPARAM)&pid);

		if (!pid)
			break;

		Sleep(2000);
	}

	DisableVMP();

	// RSA Signature verification always return 1
	uint8_t rsaVerifyReplacement[] = { 0xB0, 0x01, 0xC3 };
	uintptr_t RSASignVerification = Utils::PatternScan("UserAssembly.dll", "41 57 41 56 41 54 56 57 53 48 83 EC 28 4C 89 CB 4D 89 C4 48 89 D7 49 89 CE 80 3D 31 FF 40 F6 00 0F 84 49 01 00 00 48 85 FF 0F 84 5A 01 00 00 4D");
	Utils::WriteByteArray(RSASignVerification, rsaVerifyReplacement, 3);

	// mt19937 skip
	uint8_t jumpout[] = { 0xE9, 0xDC, 0x04, 0x00, 0x00 };
	uintptr_t mersenneTwisterLoop = Utils::PatternScan("UserAssembly.dll", "E8 DC 3E FF F4 48 89 C3 66 41 1B C9 66 81 D1 DD 57 66 0F A3 D9 48 8B 0D 05 BF D4 F3 F9 66 44 3B D3 83 B9 D8 00 00 00 00 0F 84 AF 02 00 00 48");
	Utils::WriteByteArray(mersenneTwisterLoop, jumpout, 5);

	// RSA public key construction for checking sign of server seed bytes
	uint8_t customPublicKeyBuilder[] = { 0x3C, 0x52, 0x53, 0x41, 0x4B, 0x65, 0x79, 0x56, 0x48, 0x89, 0x08, 0x48, 0xB9, 0x61, 0x6C, 0x75, 0x65, 0x3E, 0x3C, 0x4D, 0x6F, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x48, 0x08, 0x48, 0xB9, 0x64, 0x75, 0x6C, 0x75, 0x73, 0x3E, 0x78, 0x62, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x48, 0x10, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB9, 0x62, 0x78, 0x32, 0x6D, 0x31, 0x66, 0x65, 0x48, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x48, 0x18, 0x66, 0x0F, 0xBE, 0xCE, 0x66, 0x0F, 0xC9, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB9, 0x79, 0x72, 0x51, 0x37, 0x6A, 0x50, 0x2B, 0x38, 0x48, 0x89, 0x48, 0x20, 0x49, 0x8B, 0xCD, 0x48, 0xB9, 0x6D, 0x74, 0x44, 0x46, 0x2F, 0x70, 0x79, 0x59, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x48, 0x28, 0x48, 0x87, 0xC9, 0x0F, 0x90, 0xC5, 0x48, 0xB9, 0x4C, 0x72, 0x4A, 0x57, 0x4B, 0x57, 0x41, 0x64, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x48, 0x30, 0x48, 0x63, 0xCC, 0x48, 0xB9, 0x45, 0x76, 0x33, 0x77, 0x5A, 0x72, 0x4F, 0x74, 0x48, 0x89, 0x48, 0x38, 0x48, 0xB9, 0x6A, 0x4F, 0x5A, 0x7A, 0x65, 0x4C, 0x47, 0x50, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x48, 0x40, 0x41, 0x0F, 0xBF, 0xCB, 0x66, 0x41, 0x0F, 0x4E, 0xC9, 0x48, 0x0F, 0xC9, 0x48, 0xB9, 0x7A, 0x73, 0x6D, 0x6B, 0x63, 0x67, 0x6E, 0x63, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x48, 0x48, 0xC6, 0xC5, 0x03, 0x66, 0x41, 0x0F, 0xB6, 0xC8, 0x48, 0xB9, 0x67, 0x6F, 0x52, 0x68, 0x58, 0x34, 0x64, 0x54, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x48, 0x50, 0x48, 0xB9, 0x2B, 0x31, 0x69, 0x74, 0x53, 0x4D, 0x52, 0x39, 0x48, 0x89, 0x48, 0x58, 0x66, 0xF7, 0xD1, 0x66, 0x41, 0x0F, 0x4D, 0xCF, 0x41, 0x0F, 0xBF, 0xC9, 0x48, 0xB9, 0x6A, 0x39, 0x6D, 0x30, 0x2F, 0x4F, 0x77, 0x73, 0x48, 0x89, 0x48, 0x60, 0x0F, 0xB7, 0xCE, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB9, 0x48, 0x32, 0x55, 0x6F, 0x46, 0x36, 0x55, 0x33, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x48, 0x68, 0x48, 0xB9, 0x32, 0x4C, 0x78, 0x43, 0x4F, 0x51, 0x57, 0x51, 0x48, 0x89, 0x48, 0x70, 0x48, 0xB9, 0x44, 0x31, 0x41, 0x4D, 0x67, 0x49, 0x5A, 0x6A, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x48, 0x78, 0x48, 0xB9, 0x41, 0x6B, 0x4A, 0x65, 0x4A, 0x76, 0x46, 0x54, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x80, 0x00, 0x00, 0x00, 0x0F, 0x9F, 0xC5, 0x48, 0x0F, 0xBF, 0xCE, 0x0F, 0xBF, 0xC9, 0x48, 0xB9, 0x72, 0x74, 0x6E, 0x38, 0x66, 0x4D, 0x51, 0x31, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x88, 0x00, 0x00, 0x00, 0x49, 0x63, 0xCD, 0x8A, 0xEA, 0x0F, 0x98, 0xC1, 0x48, 0xB9, 0x37, 0x30, 0x31, 0x43, 0x6B, 0x62, 0x61, 0x4C, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x90, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB9, 0x54, 0x56, 0x49, 0x6A, 0x52, 0x4D, 0x6C, 0x54, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x98, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB9, 0x77, 0x38, 0x6B, 0x4E, 0x58, 0x76, 0x4E, 0x41, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x0F, 0xBF, 0xCF, 0x48, 0xB9, 0x2F, 0x41, 0x39, 0x55, 0x61, 0x74, 0x6F, 0x69, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0xA8, 0x00, 0x00, 0x00, 0x48, 0xB9, 0x44, 0x6D, 0x69, 0x34, 0x54, 0x46, 0x47, 0x36, 0x48, 0x89, 0x88, 0xB0, 0x00, 0x00, 0x00, 0x49, 0x0F, 0x41, 0xCA, 0x49, 0x0F, 0xB7, 0xCE, 0x48, 0xB9, 0x6D, 0x72, 0x78, 0x54, 0x4B, 0x5A, 0x70, 0x49, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0xB8, 0x00, 0x00, 0x00, 0xE9, 0x07, 0x00, 0x00, 0x00, 0xC6, 0xC5, 0x2D, 0x48, 0x0F, 0xB7, 0xCB, 0x48, 0xB9, 0x63, 0x54, 0x49, 0x6E, 0x76, 0x50, 0x45, 0x70, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0xC0, 0x00, 0x00, 0x00, 0x48, 0xB9, 0x6B, 0x4B, 0x32, 0x41, 0x37, 0x51, 0x73, 0x70, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0xC8, 0x00, 0x00, 0x00, 0x48, 0xF7, 0xD1, 0x66, 0x0F, 0x4C, 0xCE, 0x48, 0xB9, 0x31, 0x45, 0x34, 0x73, 0x6B, 0x46, 0x4B, 0x38, 0x48, 0x89, 0x88, 0xD0, 0x00, 0x00, 0x00, 0x66, 0x41, 0x0F, 0x4F, 0xCB, 0xE9, 0x02, 0x00, 0x00, 0x00, 0x0F, 0xC9, 0x48, 0xB9, 0x6A, 0x6D, 0x79, 0x73, 0x79, 0x37, 0x75, 0x52, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0xD8, 0x00, 0x00, 0x00, 0x66, 0x40, 0x0F, 0xBE, 0xCE, 0x48, 0xB9, 0x68, 0x4D, 0x61, 0x59, 0x48, 0x74, 0x50, 0x54, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0xE0, 0x00, 0x00, 0x00, 0x48, 0xB9, 0x73, 0x42, 0x76, 0x78, 0x50, 0x30, 0x7A, 0x6E, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0xE8, 0x00, 0x00, 0x00, 0x0F, 0x97, 0xC1, 0x66, 0x8B, 0xCC, 0x48, 0xB9, 0x33, 0x6C, 0x68, 0x4B, 0x42, 0x33, 0x57, 0x2B, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0xF0, 0x00, 0x00, 0x00, 0x41, 0x8A, 0xCC, 0x48, 0xB9, 0x48, 0x54, 0x71, 0x70, 0x6E, 0x65, 0x65, 0x77, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0xF8, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB9, 0x58, 0x57, 0x48, 0x6A, 0x43, 0x44, 0x66, 0x4C, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x00, 0x01, 0x00, 0x00, 0x41, 0x0F, 0xB7, 0xCD, 0x66, 0x41, 0x0F, 0xB6, 0xCE, 0x48, 0xB9, 0x37, 0x4E, 0x62, 0x62, 0x79, 0x39, 0x31, 0x6A, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x08, 0x01, 0x00, 0x00, 0xF7, 0xD1, 0x41, 0x0F, 0xB7, 0xCD, 0x48, 0xB9, 0x62, 0x7A, 0x35, 0x45, 0x4B, 0x50, 0x5A, 0x58, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x10, 0x01, 0x00, 0x00, 0x66, 0xF7, 0xD1, 0x0F, 0x9D, 0xC1, 0x48, 0xB9, 0x57, 0x4C, 0x75, 0x68, 0x58, 0x49, 0x76, 0x52, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x18, 0x01, 0x00, 0x00, 0x66, 0xB9, 0x5D, 0x5E, 0x48, 0xB9, 0x31, 0x43, 0x75, 0x34, 0x74, 0x69, 0x72, 0x75, 0x48, 0x89, 0x88, 0x20, 0x01, 0x00, 0x00, 0x48, 0x0F, 0xBF, 0xCE, 0x48, 0xB9, 0x6F, 0x72, 0x77, 0x58, 0x4A, 0x78, 0x6D, 0x58, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x28, 0x01, 0x00, 0x00, 0x48, 0xB9, 0x61, 0x50, 0x31, 0x48, 0x51, 0x5A, 0x6F, 0x6E, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x30, 0x01, 0x00, 0x00, 0x86, 0xED, 0x66, 0x0F, 0xB6, 0xCF, 0x48, 0x0F, 0xC9, 0x48, 0xB9, 0x79, 0x74, 0x45, 0x43, 0x4E, 0x55, 0x2F, 0x55, 0x48, 0x89, 0x88, 0x38, 0x01, 0x00, 0x00, 0x48, 0xB9, 0x4F, 0x7A, 0x50, 0x36, 0x47, 0x4E, 0x4C, 0x64, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x40, 0x01, 0x00, 0x00, 0x48, 0x63, 0xCF, 0x48, 0x0F, 0xC9, 0x48, 0x0F, 0xBF, 0xC8, 0x48, 0xB9, 0x71, 0x30, 0x65, 0x46, 0x44, 0x45, 0x34, 0x62, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x48, 0x01, 0x00, 0x00, 0x41, 0x0F, 0xBF, 0xC9, 0x48, 0x0F, 0x45, 0xC8, 0x48, 0xB9, 0x30, 0x34, 0x57, 0x6A, 0x70, 0x33, 0x39, 0x36, 0x48, 0x89, 0x88, 0x50, 0x01, 0x00, 0x00, 0x66, 0x41, 0x0F, 0xBE, 0xCD, 0x48, 0xB9, 0x35, 0x35, 0x31, 0x47, 0x39, 0x39, 0x59, 0x69, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x58, 0x01, 0x00, 0x00, 0x0F, 0x95, 0xC5, 0x66, 0x0F, 0x40, 0xCC, 0x66, 0x0F, 0xC9, 0x48, 0xB9, 0x46, 0x50, 0x32, 0x6E, 0x71, 0x48, 0x56, 0x4A, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x60, 0x01, 0x00, 0x00, 0x66, 0x40, 0x0F, 0xB6, 0xCE, 0x48, 0x0F, 0xC9, 0xF7, 0xD1, 0x48, 0xB9, 0x35, 0x4F, 0x4D, 0x51, 0x3D, 0x3D, 0x3C, 0x2F, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x68, 0x01, 0x00, 0x00, 0x66, 0x41, 0x0F, 0x4F, 0xCB, 0x48, 0x0F, 0xB7, 0xC8, 0x48, 0xB9, 0x4D, 0x6F, 0x64, 0x75, 0x6C, 0x75, 0x73, 0x3E, 0x48, 0x89, 0x88, 0x70, 0x01, 0x00, 0x00, 0x86, 0xED, 0x0F, 0xB7, 0xCF, 0x41, 0x0F, 0xBF, 0xCB, 0x48, 0xB9, 0x3C, 0x45, 0x78, 0x70, 0x6F, 0x6E, 0x65, 0x6E, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x78, 0x01, 0x00, 0x00, 0x48, 0xB9, 0x74, 0x3E, 0x41, 0x51, 0x41, 0x42, 0x3C, 0x2F, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x80, 0x01, 0x00, 0x00, 0x66, 0x0F, 0xC9, 0x66, 0x0F, 0xB6, 0xCE, 0x48, 0xB9, 0x45, 0x78, 0x70, 0x6F, 0x6E, 0x65, 0x6E, 0x74, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x88, 0x88, 0x01, 0x00, 0x00, 0x48, 0x0F, 0xB7, 0xCA, 0x66, 0x41, 0x0F, 0xB6, 0xCA, 0xB1, 0xC6, 0x48, 0xB9, 0x3E, 0x3C, 0x2F, 0x52, 0x53, 0x41, 0x4B, 0x65, 0x48, 0x89, 0x88, 0x90, 0x01, 0x00, 0x00, 0x48, 0xB9, 0x79, 0x56, 0x61, 0x6C, 0x75, 0x65, 0x3E };
	uintptr_t publicKeyBuildingPtr = Utils::PatternScan("UserAssembly.dll", "3C 52 53 41 4B 65 79 56 48 89 08 48 B9 61 6C 75 65 3E 3C 4D 6F E9 00 00 00 00 48 89 48 08 48 B9 64 75 6C 75 73 3E 31 35 E9 00 00 00 00 48 89 48 10 E9 00 00 00 00 48 B9 52 42 6D 2F 76 41 52 59 E9 00 00 00 00 48 89 48 18 66 0F BE CE 66 0F C9 E9 00 00 00 00 48 B9 30 61 78 59 6B 73 49 6D 48 89 48 20 49 8B CD 48 B9 68 73 54 69 63 70 76 30 E9 00 00 00 00 48 89 48 28 48 87 C9 0F 90 C5 48 B9 39 4F 59 66 53 34 2B 77 E9 00 00 00 00 48 89 48 30 48 63 CC 48 B9 43 76 6D 45 37 70 73 4F 48 89 48 38 48 B9 76 5A 68 57 32 55 52 5A E9 00 00 00 00 48 89 48 40 41 0F BF CB 66 41 0F 4E C9 48 0F C9 48 B9 32 52 6C 66 35 44 73 45 E9 00 00 00 00 48 89 48 48 C6 C5 03 66 41 0F B6 C8 48 B9 74 75 52 47 2F 37 76 35 E9 00 00 00 00 48 89 48 50 48 B9 57 2F 32 6F 62 71 71 56 48 89 48 58 66 F7 D1");
	Utils::WriteByteArray(publicKeyBuildingPtr, customPublicKeyBuilder, 1291);

	Utils::ConsolePrint("\n\nRules of nature\nAnd they run when the sun comes up\nWith their lives on the line\nFor all that I've\nGotta follow the laws of the wild\nWith their lives on the line\nOut here only the strong survive\n");

	return 0;
}

DWORD __stdcall DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpReserved)
{
	if (hInstance)
		DisableThreadLibraryCalls(hInstance);

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		if (HANDLE hThread = CreateThread(nullptr, 0, Thread, hInstance, 0, nullptr))
			CloseHandle(hThread);
	}

	return TRUE;
}

bool TlsOnce = false;
// this runs way before dllmain
void __stdcall TlsCallback(PVOID hModule, DWORD fdwReason, PVOID pContext)
{
	if (!TlsOnce)
	{
		DisableLogReport();
		// for version.dll proxy
		// load exports as early as possible
		// Utils::AttachConsole();
		Exports::Load();
		TlsOnce = true;
	}
}

#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#pragma const_seg(".CRT$XLF")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_func = TlsCallback;