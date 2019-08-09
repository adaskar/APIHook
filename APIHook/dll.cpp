
#include <windows.h>
#include "include/detours.h"

#pragma comment(lib, "detours.lib")

#define KEYWORD L"APIHook"

/*
	MS_ ile baslayan fonksiyonlar, Microsoft'un kendi API cagrilarina gosterici
	MY_ ile baslayan fonksiyonlar, Microsoft'un yerine gececek olan, bizim cagrilarimiza gosterici

	Ozetle,			CreateFileW yerine MY_CreateFileW gececek, 
					MS_CreateFileW eski CreateFileW olacak.

	MS_CreateFileW	= CreateFileW
	CreateFileW		= MY_CreateFileW

	Eger CreateFileW cagrisina herhangi bir mudahalede bulunmayacaksak, degisimden sonra cagri sirasi su sekilde olacak,
	call CreateFileW (aslinda MY_CreateFileW)
		....
		log sth
		....
		call MS_CreateFileW (aslinda gercek CreateFileW)
			....
			sth
			....
			call NtCreateFile
*/

static
HANDLE
(WINAPI* MS_CreateFileW)(
	_In_ LPCWSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile) = CreateFileW;

static BOOL
(WINAPI* MS_DeleteFileW)(
	_In_ LPCWSTR lpFileName) = DeleteFileW;

static
BOOL
(WINAPI* MS_CreateProcessW)(
	_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation) = CreateProcessW;

static
HANDLE
WINAPI
MY_CreateFileW(
	_In_ LPCWSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
)
{
	if (wcsstr(lpFileName, KEYWORD)) {
		SetLastError(ERROR_ACCESS_DENIED);
		return NULL;
	}
	return MS_CreateFileW(lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);
}

static BOOL WINAPI MY_DeleteFileW(_In_ LPCWSTR lpFileName)
{
	if (wcsstr(lpFileName, KEYWORD)) {
		SetLastError(ERROR_ACCESS_DENIED);
		return FALSE;
	}

	return MS_DeleteFileW(lpFileName);
}

static
BOOL
WINAPI
MY_CreateProcessW(
	_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
)
{
	if (wcsstr(lpApplicationName, KEYWORD) ||
		wcsstr(lpCommandLine, KEYWORD)) {
		SetLastError(ERROR_ACCESS_DENIED);
		return FALSE;
	}

	return MS_CreateProcessW(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);
}


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	if (dwReason == DLL_PROCESS_ATTACH) {
		DetourRestoreAfterWith();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)MS_CreateFileW, MY_CreateFileW);
		DetourAttach(&(PVOID&)MS_DeleteFileW, MY_DeleteFileW);
		DetourAttach(&(PVOID&)MS_CreateProcessW, MY_CreateProcessW);
		DetourTransactionCommit();
	}
	else if (dwReason == DLL_PROCESS_DETACH) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)MS_CreateFileW, MY_CreateFileW);
		DetourDetach(&(PVOID&)MS_DeleteFileW, MY_DeleteFileW);
		DetourDetach(&(PVOID&)MS_CreateProcessW, MY_CreateProcessW);
		DetourTransactionCommit();
	}
	return TRUE;
}