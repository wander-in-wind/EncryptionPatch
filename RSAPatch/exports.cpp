#include "exports.h"
#include "Console.h"

FARPROC OriginalFuncs_version[17];

void Exports::Load()
{
	char szSystemDirectory[MAX_PATH]{};
	GetSystemDirectoryA(szSystemDirectory, MAX_PATH);

	std::string OriginalPath = szSystemDirectory;
	OriginalPath += "\\version.dll";

	HMODULE version = LoadLibraryA(OriginalPath.c_str());
	// load version.dll from system32
	if (!version)
	{
		Console::Print("Failed to load version.dll from system32\n");
		return;
	}

	// get addresses of original functions
	for (int i = 0; i < 17; i++)
	{
		OriginalFuncs_version[i] = GetProcAddress(version, ExportNames_version[i].c_str());
		if (!OriginalFuncs_version[i])
		{
			Console::Print("Failed to get address of %s\n", ExportNames_version[i].c_str());
			return;
		}
	}
}
