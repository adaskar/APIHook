#include <Windows.h>
#include <Psapi.h>

HANDLE OpenProcessInject(const wchar_t *procname)
{
	DWORD need;
	DWORD pids[2048] = { 0 };

	if (!EnumProcesses(pids, sizeof(pids), &need))
		return NULL;

	for (DWORD i = 0; i < need / sizeof(DWORD); ++i) {
		DWORD dw;
		HMODULE mod;
		HANDLE proc;
		wchar_t pn[MAX_PATH] = { 0 };
		
		proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pids[i]);
		if (proc) {
			if (EnumProcessModules(proc, &mod, sizeof(mod), &dw)) {
				GetModuleBaseNameW(proc, mod, pn, sizeof(pn) / sizeof(char));
				if (_wcsicmp(pn, procname) == 0) {
					CloseHandle(proc);
					return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pids[i]);
				}
			}
			CloseHandle(proc);
		}
	}
	return NULL;
}

int main(int argc, char* argv[])
{
	HANDLE exphandle;
	PVOID buffer;
	wchar_t dllpath[MAX_PATH];
	PTHREAD_START_ROUTINE loadlibrary;

	// APIHook.dll, exe'nin yanindadir.
	GetCurrentDirectoryW(ARRAYSIZE(dllpath), dllpath);
	wcscat_s(dllpath, ARRAYSIZE(dllpath), L"\\APIHook.dll");

	// explorer.exe pid'i bulunup, PROCESS_ALL_ACCESS ile handle aciliyor.
	exphandle = OpenProcessInject(L"explorer.exe");

	// LoadLibraryW cagrisina parametre olarak APIHook.dll'nin tam yolunu veriyoruz (yaziyoruz)
	buffer = VirtualAllocEx(exphandle, NULL, sizeof dllpath, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(exphandle, buffer, (LPVOID)dllpath, sizeof dllpath, NULL);

	// baslangic noktasi LoadLibraryW olacak sekilde Thread baslatiyoruz(PTHREAD_START_ROUTINE loadlibrary), 
	// parametresi ise, az once yazdigimiz APIHook.dll'nin tam yolu(buffer).
	loadlibrary = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryW");
	CreateRemoteThread(exphandle, NULL, 0, loadlibrary, buffer, 0, NULL);
	CloseHandle(exphandle);

	return 0;
}