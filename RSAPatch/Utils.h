#ifndef UTILS_H
#define UTILS_H
#include <Windows.h>
#include <vector>

namespace Utils
{
	void WriteByteArray(uintptr_t address, uint8_t* value, size_t length);
	void AttachConsole();
	void DetachConsole();
	bool ConsolePrint(const char* fmt, ...);
	uintptr_t PatternScan(LPCSTR module, LPCSTR pattern);
}

#endif