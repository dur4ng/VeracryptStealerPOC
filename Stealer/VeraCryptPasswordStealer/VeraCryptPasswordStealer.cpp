#include <stdio.h>
#include <windows.h>
#include "detours.h"
#include <iostream> //include the header files like input-output streams
#include <fstream> //include the filestreamobject as the header files
using namespace std;
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "detours.lib")

int (WINAPI* pOrigWideCharToMultiByte)(UINT CodePage,
	DWORD dwFlags,
	_In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
	int cchWideChar,
	LPSTR lpMultiByteStr,
	int cbMultiByte,
	LPCCH lpDefaultChar,
	LPBOOL lpUsedDefaultChar) = WideCharToMultiByte;

BOOL Hookem(void);
BOOL UnHookem(void);

// Hooking function
int HookedWideCharToMultiByte(
	UINT CodePage,
	DWORD dwFlags,
	_In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
	int cchWideChar,
	LPSTR lpMultiByteStr,
	int cbMultiByte,
	LPCCH lpDefaultChar,
	LPBOOL lpUsedDefaultChar) {
	int result;
	char str[200];

	result = pOrigWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar); // using the trampolin

	ofstream o; //ofstream is the class for fstream package
	o.open("C:\\Windows\\Temp\\data.txt"); //open is the method of ofstream
	o << lpMultiByteStr; // << operator which is used to print the file informations in the screen
	o.close();
	sprintf_s(str, "CharToMultiByte() called!!! DATA = %s", lpMultiByteStr);
	OutputDebugStringA(str);

	return result;
}

// Set hooks on CharToMultiByte
BOOL Hookem(void) {

	LONG err;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread()); // specify the scope of the hook
	DetourAttach(&(PVOID&)pOrigWideCharToMultiByte, HookedWideCharToMultiByte); // specify the function to hook and the one that you want execute
	err = DetourTransactionCommit();

	OutputDebugStringA("CharToMultiByte() hooked!");

	return TRUE;
}

// Revert all changes to original code
BOOL UnHookem(void) {

	LONG err;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)pOrigWideCharToMultiByte, HookedWideCharToMultiByte);
	err = DetourTransactionCommit();

	OutputDebugStringA("Hook removed from CharToMultiByte()");

	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		Hookem();
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		UnHookem();
		break;
	}

	return TRUE;
}

