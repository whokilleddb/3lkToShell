#pragma once


#pragma managed(push, off)

#include <stdio.h>
#include <Windows.h>

#define EPRINT(x) printf("[-] %s() failed with error: 0x%lx\n", x, GetLastError())
#define NTEPRINT(x, e) printf("[-] %s() failed with error: 0x%lx\n", x, e)
#define MEPRINT printf("[-] malloc() failed at %s:%d\n", __FILE__, __LINE__)

BYTE* read_shellcode(const char* path, DWORD* outSize);

#pragma managed(pop)

using namespace System;
using namespace System::Reflection;
using namespace System::Reflection::Emit;
using namespace System::Runtime::InteropServices;
using namespace System::Runtime::CompilerServices;
using namespace System::Threading;

void Exec(BYTE* shellcode, DWORD shellcode_size);
