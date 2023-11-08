#ifndef MEMORY_H
#define MEMORY_H

#include <Windows.h>
#include <vector>

namespace Memory
{
	void WriteByteArray(uintptr_t address, uint8_t* value, size_t length);
	uintptr_t Scan(LPCSTR module, LPCSTR pattern);
}

#endif