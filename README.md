### Remote Process Injection Tool
This tool demonstrates a basic remote process injection technique using WinAPI functions in C. It allows injecting custom shellcode into a target process identified by its PID.

Note: This tool will likely be detected by Windows Defender and other antivirus software as malicious. I have not explored obfuscation or other evasion techniques in this project.

### Description
This program demonstrates the following:

Opening a handle to a process using OpenProcess.
Allocating memory within the target process using VirtualAllocEx.
Writing shellcode into the allocated memory using WriteProcessMemory.
Creating a remote thread within the target process to execute the injected shellcode using CreateRemoteThreadEx.

### Usage
```program.exe <PID>```.
In windows, you can locate the PID through this command:
```tasklist | findstr <program name>```.

### Learning Objectives
The basics of process manipulation and memory allocation in Windows.
Techniques used in malware development, such as process injection.
The practical application of WinAPI functions for system-level programming.
