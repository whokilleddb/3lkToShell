#include "3lkToShell.hpp"

#pragma managed(push, off)

BYTE* read_shellcode(const char* path, DWORD* outSize) {
    HANDLE hFile = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        EPRINT("CreateFileA");
        return NULL;
    }

    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        EPRINT("GetFileSize");
        CloseHandle(hFile);
        return NULL;
    }

    BYTE* buf = (BYTE*)malloc(size);
    if (!buf) {
        MEPRINT;
        CloseHandle(hFile);
        return NULL;
    }


    DWORD read = 0;
    if (!ReadFile(hFile, buf, size, &read, NULL) || read != size) {
        EPRINT("ReadFile");
        free(buf);
        CloseHandle(hFile);
        return NULL;
    }
    CloseHandle(hFile);
    *outSize = size;
    return buf;
}

#pragma managed(pop)