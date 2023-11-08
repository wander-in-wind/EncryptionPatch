#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <fstream>
#include <filesystem>
#include <string>
#include "exports.h"
#include "Console.h"
#include "Memory.h"

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

DWORD __stdcall ThreadFunc(LPVOID p)
{
	Console::Attach();

	Console::Print("anime encryption patcher by xeondev\n\n\n");
	Console::Print("waiting for anime software startup..");

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

		Sleep(2000); // wait another 2 seconds and then re-check for window creation
		Console::Print(".");
	}
	Console::Print("OK\n");

	DisableVMP();

	// RSA Signature verification bypass (HTTP)
	uint8_t dontJmp[] = { 0x90, 0x90 };
	uintptr_t afterRSAVerify = Memory::Scan("UserAssembly.dll", "48 83 F8 01 75 08 49 8B C7 E9 E7 00 00 00 4C 8B 0D 9F E6 AB");
	Memory::WriteByteArray(afterRSAVerify + 4, dontJmp, 2);

	// RSA Signature verification bypass (Seed)
	uint8_t dontJmpInDecryptSeed[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
	uintptr_t afterRSAVerifyInDecryptSeed = Memory::Scan("UserAssembly.dll", "0F 85 EF 00 00 00 33 D2 49 8B CF E8 6B D2 6E 05 48 8B F8");
	Memory::WriteByteArray(afterRSAVerifyInDecryptSeed, dontJmpInDecryptSeed, 6);

	// hardcode SECOND mt19937 initialization seed to 1337
	uint8_t setSeed[] = { 0xC7, 0xC3, 0x39, 0x05, 0x00, 0x00, 0x90 };
	uintptr_t preMtInitCall = Memory::Scan("UserAssembly.dll", "8B D8 E9 00 00 00 00 E8 DC 4A B5 F2 48 8B C8 49");
	Memory::WriteByteArray(preMtInitCall, setSeed, 7);

	Console::Print("We're done here.\n");
	return 0;
}

DWORD __stdcall DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpReserved)
{
	if (hInstance)
		DisableThreadLibraryCalls(hInstance);

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		if (HANDLE hThread = CreateThread(nullptr, 0, ThreadFunc, hInstance, 0, nullptr))
			CloseHandle(hThread);
	}

	return TRUE;
}

bool EarlyInitDone = false;

// this runs way before dllmain
void __stdcall TlsCallback(PVOID hModule, DWORD fdwReason, PVOID pContext)
{
	if (!EarlyInitDone)
	{
		DisableLogReport();
		Exports::Load();
		EarlyInitDone = true;
	}
}

#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#pragma const_seg(".CRT$XLF")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_func = TlsCallback;
